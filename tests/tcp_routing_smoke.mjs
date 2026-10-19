import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { homedir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';

const binary = path.resolve(process.argv[2] ?? 'target/release/tobaru');
const signal = AbortSignal.timeout(30_000);
const sockets = new Set();
const servers = [];
let child;
let childClosed;
let logs = '';
let root;

function track(socket) {
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
  socket.on('error', () => {});
  return socket;
}

async function listen(server) {
  servers.push(server);
  server.on('connection', track);
  server.listen(0, '0.0.0.0');
  await once(server, 'listening', { signal });
  return server.address().port;
}

async function freePort() {
  const server = net.createServer();
  server.listen(0, '0.0.0.0');
  await once(server, 'listening', { signal });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function response(socket) {
  const chunks = [];
  socket.on('data', chunk => chunks.push(chunk));
  await once(socket, 'end', { signal });
  socket.destroy();
  return Buffer.concat(chunks).toString();
}

function tlsResponse(port, servername, ALPNProtocols = []) {
  return response(track(tls.connect({ host: '127.0.0.1', port, servername, ALPNProtocols, rejectUnauthorized: false })));
}

try {
  const tmp = path.join(homedir(), 'tmp');
  await mkdir(tmp, { recursive: true });
  root = await mkdtemp(path.join(tmp, 'tobaru-tcp-routing-'));
  const certPath = path.join(root, 'cert.pem');
  const keyPath = path.join(root, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath,
    '-out', certPath, '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  const cert = await readFile(certPath);
  const key = await readFile(keyPath);
  let rawConnections = 0;
  const rawServer = tls.createServer({ cert, key }, socket => socket.end('raw'));
  rawServer.on('connection', () => rawConnections++);
  const rawPort = await listen(rawServer);
  const passPort = await listen(tls.createServer({ cert, key, ALPNProtocols: ['h2', 'http/1.1'] }, socket => socket.end('passthrough')));
  const plainPort = await listen(net.createServer(socket => socket.end('plain')));
  const fallbackFirstBytes = [];
  const fallbackPort = await listen(net.createServer(socket => socket.once('data', bytes => {
    fallbackFirstBytes.push(bytes[0]);
    socket.end(bytes);
  })));
  const configs = [];
  async function listener(targets) {
    const port = await freePort();
    configs.push({ address: `0.0.0.0:${port}`, transport: 'tcp', iptables: false, targets });
    return port;
  }
  const raw = (port = rawPort, allowlist = '127.0.0.0/8') => ({ allowlist, location: `127.0.0.1:${port}` });
  const pass = (name, protocols, allowlist = '127.0.0.1/32') => ({
    ...raw(passPort, allowlist),
    server_tls: { mode: 'passthrough', sni_hostnames: name, alpn_protocols: protocols },
  });
  const terminate = (name, extra = {}) => ({
    ...raw(plainPort, '127.0.0.1/32'),
    server_tls: { cert: certPath, key: keyPath, sni_hostnames: name, ...extra },
  });
  const http = {
    allowlist: '127.0.0.1/32',
    default_http_action: { type: 'serve-message', status_code: 200, content: 'http-shadow' },
  };

  const mainPort = await listener([
    raw(), pass('specific.example', ['h2']), terminate('secure.example'),
  ]);
  const catchAllPort = await listener([
    raw(), terminate(['any', 'none']), pass('specific.example', ['h2']),
  ]);
  const ancestorsPort = await listener([
    raw(), pass('any', ['h2']), pass('.example.com', ['http/1.1']),
    pass('api.example.com', undefined, '192.0.2.1/32'), pass('api.example.com', ['private']),
  ]);
  const rawOverridePort = await listener([
    pass(['any', 'none'], undefined, '127.0.0.0/8'), raw(plainPort, '127.0.0.1/32'),
  ]);
  const httpShadowPort = await listener([http, raw()]);
  const authPort = await listener([
    raw(), terminate('secure.example', { client_fingerprints: ['00'.repeat(32)] }),
  ]);
  const modeTiePort = await listener([terminate('secure.example'), pass('secure.example')]);
  const rawTiePort = await listener([raw(plainPort, '127.0.0.1/32'), raw(rawPort, '127.0.0.1/32')]);
  const malformedPort = await listener([raw(fallbackPort), pass('specific.example')]);
  const optionalPort = await listener([{
    ...terminate('secure.example', { optional: true }), location: `127.0.0.1:${fallbackPort}`,
  }]);
  const mixedFamilyPorts = [];
  const mixedFamilyTiePorts = [];
  mixedFamilyTiePorts.push(await listener([raw(plainPort, 'all'), raw(rawPort, '::ffff:0:0/80')]));
  for (const broad of ['all', '::/0']) {
    for (const [rawMask, tlsMask] of [['0.0.0.0/0', broad], [broad, '0.0.0.0/0']]) {
      mixedFamilyPorts.push(await listener([
        raw(rawPort, rawMask), pass('specific.example', undefined, tlsMask),
      ]));
      mixedFamilyPorts.push(await listener([
        { ...pass('any', undefined, rawMask), location: `127.0.0.1:${rawPort}` },
        pass('specific.example', undefined, tlsMask),
      ]));
      mixedFamilyTiePorts.push(await listener([raw(plainPort, rawMask), raw(rawPort, tlsMask)]));
    }
  }
  const configPath = path.join(root, 'routes.json');
  await writeFile(configPath, JSON.stringify(configs));
  child = spawn(binary, ['-t', '1', configPath]);
  childClosed = new Promise(resolve => child.once('close', resolve));
  child.on('error', error => { throw error; });
  const capture = bytes => { logs = (logs + bytes).slice(-65536); };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);
  while ((logs.match(/Listening \(TCP\)/g) ?? []).length < configs.length) {
    assert.equal(child.exitCode, null, logs);
    await delay(20, undefined, { signal });
  }

  assert.equal(await tlsResponse(mainPort, 'qa.snailcdn.com', ['http/1.1']), 'raw');
  assert.equal(await tlsResponse(mainPort, 'specific.example', ['h2']), 'passthrough');
  assert.equal(await tlsResponse(mainPort, 'specific.example', ['http/1.1']), 'raw');
  assert.equal(await tlsResponse(mainPort, 'secure.example'), 'plain');
  assert.equal(await tlsResponse(mainPort, undefined), 'raw');
  assert.equal(await tlsResponse(catchAllPort, 'other.example'), 'plain');
  assert.equal(await tlsResponse(catchAllPort, undefined), 'plain');
  assert.equal(await tlsResponse(catchAllPort, 'specific.example', ['h2']), 'passthrough');
  assert.equal(await tlsResponse(ancestorsPort, 'api.example.com', ['h2']), 'passthrough');
  assert.equal(await tlsResponse(ancestorsPort, 'api.example.com', ['http/1.1']), 'passthrough');
  assert.equal(await tlsResponse(ancestorsPort, 'example.com', ['http/1.1']), 'passthrough');
  assert.equal(await tlsResponse(ancestorsPort, 'api.example.com'), 'raw');
  assert.equal(await tlsResponse(httpShadowPort, 'qa.snailcdn.com'), 'raw');
  assert.equal(await tlsResponse(modeTiePort, 'secure.example'), 'plain');
  for (const port of mixedFamilyPorts) {
    assert.equal(await tlsResponse(port, 'specific.example'), 'passthrough');
  }

  // A narrower raw route must not wait for ClientHello, even with a TLS catch-all.
  for (const port of [rawOverridePort, rawTiePort, ...mixedFamilyTiePorts]) {
    const socket = track(net.connect(port, '127.0.0.1'));
    socket.setTimeout(1000, () => socket.destroy(new Error('raw route waited for ClientHello')));
    assert.equal(await response(socket), 'plain');
  }
  const httpSocket = track(net.connect(httpShadowPort, '127.0.0.1'));
  httpSocket.write('GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  assert.match(await response(httpSocket), /http-shadow/);
  const malformed = Buffer.from([0x17, 3, 3, 0, 1, 0, 65, 66, 67]);
  for (const port of [malformedPort, optionalPort]) {
    const socket = track(net.connect(port, '127.0.0.1'));
    socket.write(malformed);
    assert.equal(await response(socket), malformed.toString());
  }
  const beforeOptional = fallbackFirstBytes.length;
  await assert.rejects(tlsResponse(optionalPort, 'other.example'));
  assert.equal(fallbackFirstBytes.length, beforeOptional + 1);
  assert.equal(fallbackFirstBytes.at(-1), 0x16, 'optional raw target did not receive the unmatched ClientHello');
  const before = rawConnections;
  await assert.rejects(tlsResponse(authPort, 'secure.example'));
  await delay(50, undefined, { signal });
  assert.equal(rawConnections, before, 'failed client authentication reached raw fallback');

  console.log('TCP routing smoke passed: raw TLS fallback, specific routes, competing catch-alls, IP/SNI/ALPN precedence, mixed-family catch-alls, absent SNI/ALPN, wildcard fallback, HTTP isolation, server-first raw overrides, optional TLS migration, byte replay, and terminal authentication failure.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  if (child && child.exitCode === null) child.kill('SIGTERM');
  if (childClosed) await childClosed;
  for (const socket of sockets) socket.destroy();
  await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
  if (root) await rm(root, { recursive: true, force: true });
}
