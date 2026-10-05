import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import http2 from 'node:http2';
import net from 'node:net';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const binary = resolve(process.argv[2] ?? join(root, 'target/release/tobaru'));
mkdirSync(join(homedir(), 'tmp'), { recursive: true });
const directory = mkdtempSync(join(homedir(), 'tmp/tobaru-h2-smoke-'));
const signal = AbortSignal.timeout(30_000);
const sockets = new Set();
const sessions = new Set();
const servers = [];
let child;
let childClosed;
let logs = '';
let backendConnections = 0;
let uploads = 0;
let pushDisabled = false;
let peerFailure;
function guard(callback) {
  return (...args) => {
    try { callback(...args); }
    catch (error) {
      peerFailure ??= error;
      for (const session of sessions) session.destroy(error);
    }
  };
}
signal.addEventListener('abort', () => {
  for (const session of sessions) session.destroy(new Error('Smoke test deadline'));
}, { once: true });

async function listen(server, path) {
  servers.push(server);
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  if (path) server.listen(path);
  else server.listen(0, '0.0.0.0');
  await once(server, 'listening', { signal });
  return server.address().port;
}

async function port() {
  const server = net.createServer();
  const value = await listen(server);
  await new Promise(resolve => server.close(resolve));
  return value;
}

function track(session) {
  sessions.add(session);
  session.on('error', () => {});
  session.on('close', () => sessions.delete(session));
  return session;
}

function get(session, path = '/', method = 'GET') {
  return new Promise((resolve, reject) => {
    const request = session.request({ ':path': path, ':method': method });
    let headers;
    let trailers;
    const chunks = [];
    request.on('response', value => { headers = value; });
    request.on('trailers', value => { trailers = value; });
    request.on('data', value => chunks.push(value));
    request.on('error', reject);
    request.on('close', () => { if (!request.readableEnded) reject(new Error('Stream closed before response end')); });
    request.on('end', () => {
      if (!headers) reject(new Error('Stream ended without response headers'));
      else resolve({ headers, trailers, body: Buffer.concat(chunks).toString() });
    });
    request.end();
  });
}

function h1Get(port, options = {}) {
  return new Promise((resolve, reject) => {
    const request = https.get({
      hostname: '127.0.0.1', port, path: '/', servername: 'localhost',
      ALPNProtocols: ['http/1.1'], rejectUnauthorized: false, agent: false, signal, ...options,
    }, response => {
      const chunks = [];
      const alpn = response.socket.alpnProtocol;
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ response, alpn, body: Buffer.concat(chunks).toString() }));
      response.on('error', reject);
    });
    request.on('error', reject);
  });
}

function h1ToH2Upload(port, payload, chunked) {
  return new Promise((resolve, reject) => {
    const information = [];
    const request = https.request({
      hostname: '127.0.0.1', port, path: '/ingress-upload', method: 'POST',
      servername: 'localhost', ALPNProtocols: ['http/1.1'], rejectUnauthorized: false,
      agent: false, signal,
      headers: {
        expect: '100-continue', connection: 'close, x-private', 'x-private': 'hidden',
        ...(chunked ? { 'transfer-encoding': 'chunked', trailer: 'x-upload' } : { 'content-length': payload.length }),
      },
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('error', reject);
      response.on('end', () => {
        try {
          assert.equal(response.statusCode, 200);
          assert.deepEqual(information, [100, 103]);
          assert.deepEqual(Buffer.concat(chunks), payload);
          assert.equal(response.trailers['x-finished'], 'yes');
          resolve();
        } catch (error) { reject(error); }
      });
    });
    request.on('error', reject);
    request.on('information', response => information.push(response.statusCode));
    request.on('continue', () => {
      request.write(payload);
      if (chunked) request.addTrailers({ 'x-upload': 'complete' });
      request.end();
    });
    request.flushHeaders();
  });
}

function clearH1Get(port, method = 'GET') {
  return new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port, method, path: '/', agent: false, signal }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks).toString()));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end();
  });
}

async function duplex(session) {
  const request = session.request({ ':method': 'POST', ':path': '/duplex', expect: '100-continue' }, { waitForTrailers: true });
  const information = [];
  const chunks = [];
  let started = false;
  let ended = false;
  request.on('headers', headers => {
    information.push(headers[':status']);
    if (headers[':status'] === 100) { started = true; request.write('first'); }
  });
  request.on('data', guard(chunk => {
    chunks.push(chunk);
    if (!ended) {
      assert.equal(started, true);
      ended = true;
      request.end('last');
    }
  }));
  request.on('wantTrailers', () => request.sendTrailers({ 'x-upload': 'complete' }));
  let trailers;
  request.on('trailers', value => { trailers = value; });
  await once(request, 'end', { signal });
  assert.deepEqual(information, [100, 103]);
  assert.equal(Buffer.concat(chunks).toString(), 'firstlast');
  assert.equal(trailers['x-finished'], 'yes');
  assert.equal(uploads, 1);
}

async function h1Upload(session, payload) {
  const request = session.request({
    ':method': 'POST', ':path': '/h1/upload', 'content-length': String(payload.length),
    te: 'trailers', cookie: ['a=1', 'b=2'],
  }, { waitForTrailers: true });
  let status;
  request.on('response', headers => { status = headers[':status']; });
  request.on('wantTrailers', () => request.sendTrailers({ 'x-upload': 'complete' }));
  request.resume();
  request.end(payload);
  await once(request, 'end', { signal });
  assert.equal(status, 200);
}

try {
  const keyPath = join(directory, 'key.pem');
  const certPath = join(directory, 'cert.pem');
  const generated = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost'], { encoding: 'utf8' });
  assert.equal(generated.status, 0, generated.stderr);
  const cert = readFileSync(certPath);
  const key = readFileSync(keyPath);
  const fingerprint = new X509Certificate(cert).fingerprint256.replaceAll(':', '');
  const backend = http2.createSecureServer({ key, cert, ca: cert, requestCert: true, rejectUnauthorized: true });
  backend.on('session', session => {
    backendConnections++;
    track(session);
    session.on('remoteSettings', settings => { pushDisabled = settings.enablePush === false; });
  });
  backend.on('stream', guard((stream, headers) => {
    stream.on('error', () => {});
    assert.equal(stream.session.socket.authorized, true);
    assert.equal(stream.session.socket.servername, 'localhost');
    if (headers[':path'] === '/ingress-upload') {
      assert.equal(headers.connection, undefined);
      assert.equal(headers['x-private'], undefined);
      assert.equal(headers['transfer-encoding'], undefined);
      stream.additionalHeaders({ ':status': 100 });
      stream.additionalHeaders({ ':status': 103, link: '</asset>' });
      const chunks = [];
      let trailers;
      stream.on('data', data => chunks.push(data));
      stream.on('trailers', fields => { trailers = fields; });
      stream.on('end', guard(() => {
        if (headers['content-length'] === undefined) assert.equal(trailers['x-upload'], 'complete');
        else assert.equal(Buffer.concat(chunks).length, Number(headers['content-length']));
        stream.respond({ ':status': 200 }, { waitForTrailers: true });
        stream.end(Buffer.concat(chunks));
      }));
      stream.on('wantTrailers', () => stream.sendTrailers({ 'x-finished': 'yes' }));
    } else if (headers[':path'] === '/duplex') {
      stream.additionalHeaders({ ':status': 100 });
      stream.additionalHeaders({ ':status': 103, link: '</asset>' });
      stream.respond({ ':status': 200 }, { waitForTrailers: true });
      stream.on('data', data => stream.write(data));
      stream.on('trailers', guard(trailers => { assert.equal(trailers['x-upload'], 'complete'); uploads++; }));
      stream.on('end', () => stream.end());
      stream.on('wantTrailers', () => stream.sendTrailers({ 'x-finished': 'yes' }));
    } else {
      stream.respond({ ':status': 200, 'set-cookie': ['a=1', 'b=2'] });
      stream.end('h2 backend');
    }
  }));
  const backendPort = await listen(backend);
  const parsedH1 = [];
  const h1Backend = http.createServer(guard((request, response) => {
    const entry = { path: request.url, socket: request.socket };
    parsedH1.push(entry);
    if (request.url === '/h1/upload') {
      assert.equal(request.headers['content-length'], undefined);
      assert.equal(request.headers.te, undefined);
      assert.equal(request.headers['transfer-encoding'], 'chunked');
      assert.equal(request.headers.connection, 'close');
      assert.equal(request.headers.cookie, 'a=1; b=2');
      const names = request.rawHeaders.filter((_, index) => index % 2 === 0).map(name => name.toLowerCase());
      assert.equal(names.filter(name => name === 'host').length, 1);
      assert.equal(names.filter(name => name === 'transfer-encoding').length, 1);
      const data = [];
      request.on('data', bytes => data.push(bytes));
      request.on('end', guard(() => {
        assert.equal(request.complete, true);
        assert.equal(request.trailers['x-upload'], 'complete');
        entry.body = Buffer.concat(data);
        response.end('accepted');
      }));
      return;
    }
    response.writeEarlyHints({ link: '</asset>' });
    response.writeHead(200, { 'Set-Cookie': ['one=1', 'two=2'], Trailer: 'x-finished' });
    response.write('h1 backend');
    response.addTrailers({ 'x-finished': 'yes' });
    response.end();
  }));
  const h1Port = await listen(h1Backend);
  const wrongAlpn = https.createServer({ key, cert, ALPNProtocols: ['http/1.1'] });
  let wrongAlpnBytes = 0;
  wrongAlpn.on('secureConnection', socket => socket.on('data', data => { wrongAlpnBytes += data.length; }));
  const wrongPort = await listen(wrongAlpn);
  const unixPath = join(directory, 'backend.sock');
  const unixBackend = http2.createServer();
  unixBackend.on('session', track);
  unixBackend.on('stream', stream => { stream.respond({ ':status': 200 }); stream.end('unix h2'); });
  await listen(unixBackend, unixPath);
  const tlsPort = await port();
  const clearPort = await port();
  const authPort = await port();
  const autoPort = await port();
  const h1OnlyPort = await port();
  const h2OnlyPort = await port();
  const selectionPort = await port();
  const publicRoot = join(directory, 'public');
  mkdirSync(join(publicRoot, 'escape'), { recursive: true });
  writeFileSync(join(publicRoot, 'index.html'), 'public');
  writeFileSync(join(directory, 'private.txt'), 'private');
  symlinkSync(join(directory, 'private.txt'), join(publicRoot, 'escape/index.html'));
  const tls = { verify: false, sni_hostname: 'localhost', server_fingerprint: fingerprint, cert: certPath, key: keyPath };
  const forward = { type: 'forward', upstream_protocol: 'http2', location: { address: `127.0.0.1:${backendPort}`, client_tls: tls } };
  const configPath = join(directory, 'config.json');
  writeFileSync(configPath, JSON.stringify([
    { address: `0.0.0.0:${tlsPort}`, transport: 'tcp', target: {
      allowlist: '127.0.0.1/32',
      server_tls: { cert: certPath, key: keyPath, alpn_protocols: ['h2', 'http/1.1', 'legacy-http', 'none'] },
      default_http_action: forward,
      http_paths: {
        '/static/': { http_action: { type: 'serve-directory', path: publicRoot } },
        '/h1/': { http_action: { type: 'forward', location: `127.0.0.1:${h1Port}` } },
        '/unix/': { http_action: { type: 'forward', upstream_protocol: 'http2', location: unixPath } },
        '/bad-pin/': { http_action: { ...forward, location: { address: `127.0.0.1:${backendPort}`, client_tls: { ...tls, server_fingerprint: '00'.repeat(32) } } } },
        '/untrusted/': { http_action: { ...forward, location: { address: `127.0.0.1:${backendPort}`, client_tls: { ...tls, verify: true } } } },
        '/bad-alpn/': { http_action: { ...forward, location: { address: `127.0.0.1:${wrongPort}`, client_tls: { ...tls } } } },
      },
    } },
    { address: `0.0.0.0:${clearPort}`, transport: 'tcp', target: {
      allowlist: '127.0.0.1/32',
      default_http_action: { type: 'serve-message', status_code: 200, content: 'clear h2' },
    } },
    { address: `0.0.0.0:${authPort}`, transport: 'tcp', target: {
      allowlist: '127.0.0.1/32',
      server_tls: { cert: certPath, key: keyPath, alpn_protocols: ['h2'], client_fingerprints: [fingerprint] },
      default_http_action: { type: 'serve-message', status_code: 200, content: 'authenticated' },
    } },
    ...[
      [autoPort, undefined, 'automatic'],
      [h1OnlyPort, ['http1'], 'h1 only'],
      [h2OnlyPort, ['http2'], 'h2 only'],
    ].map(([port, protocols, content]) => ({ address: `0.0.0.0:${port}`, transport: 'tcp', target: {
      allowlist: '127.0.0.1/32', http_protocols: protocols,
      server_tls: { cert: certPath, key: keyPath, optional: true },
      default_http_action: { type: 'serve-message', status_code: 200, content },
    } })),
    { address: `0.0.0.0:${selectionPort}`, transport: 'tcp', targets: [
      ['192.0.2.1/32', 'localhost', undefined, 'wrong source'],
      ['127.0.0.1/32', 'localhost', ['http/1.1', 'none'], 'selected h1'],
      ['127.0.0.1/32', 'localhost', undefined, 'selected h2'],
      ['127.0.0.1/32', 'empty.localhost', [], 'empty alpn'],
      ['127.0.0.1/32', 'null.localhost', null, 'null alpn'],
    ].map(([allowlist, name, alpn, content]) => ({
      allowlist,
      server_tls: { cert: certPath, key: keyPath, sni_hostnames: [name], alpn_protocols: alpn },
      default_http_action: { type: 'serve-message', status_code: 200, content },
    })) },
  ]));
  child = spawn(binary, ['-t', '1', configPath]);
  childClosed = new Promise(resolve => child.once('close', resolve));
  child.on('error', error => { throw error; });
  const capture = bytes => { logs = (logs + bytes).slice(-65536); };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);
  while ((logs.match(/Listening \(TCP\)/g) ?? []).length < 7) {
    assert.equal(child.exitCode, null, logs);
    await delay(25, undefined, { signal });
  }
  const client = track(http2.connect(`https://127.0.0.1:${tlsPort}`, { rejectUnauthorized: false, servername: 'localhost' }));
  await once(client, 'connect', { signal });
  assert.equal(client.alpnProtocol, 'h2');
  for (let i = 0; i < 2; i++) {
    const result = await get(client);
    assert.equal(result.body, 'h2 backend');
    assert.deepEqual(result.headers['set-cookie'], ['a=1', 'b=2']);
  }
  assert.equal(backendConnections, 1);
  assert.equal(pushDisabled, true);
  await duplex(client);
  const h1 = await get(client, '/h1/');
  assert.equal(h1.body, 'h1 backend');
  assert.equal(h1.trailers['x-finished'], 'yes');
  const beforeUploads = parsedH1.length;
  const injection = Buffer.from('0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: other.test\r\n\r\n\x00\xff', 'latin1');
  await h1Upload(client, injection);
  await h1Upload(client, Buffer.from('second'));
  const parsedUploads = parsedH1.slice(beforeUploads);
  assert.equal(parsedUploads.length, 2);
  assert.deepEqual(parsedUploads.map(request => request.path), ['/h1/upload', '/h1/upload']);
  assert.deepEqual(parsedUploads[0].body, injection);
  assert.deepEqual(parsedUploads[1].body, Buffer.from('second'));
  assert.notEqual(parsedUploads[0].socket, parsedUploads[1].socket);
  assert.equal((await get(client, '/unix/')).body, 'unix h2');
  assert.equal((await get(client, '/static/')).body, 'public');
  const fileHead = await get(client, '/static/', 'HEAD');
  assert.equal(fileHead.headers['content-length'], '6');
  assert.equal(fileHead.body, '');
  assert.equal((await get(client, '/static/missing')).headers[':status'], 404);
  const escaped = await get(client, '/static/escape/');
  assert.equal(escaped.headers[':status'], 502);
  assert.equal(escaped.body, '');
  for (const path of ['/bad-pin/', '/untrusted/', '/bad-alpn/']) {
    assert.equal((await get(client, path)).headers[':status'], 502, path);
  }
  assert.equal(wrongAlpnBytes, 0);
  const fallback = await h1Get(tlsPort);
  assert.equal(fallback.body, 'h2 backend');
  assert.equal(fallback.response.socket?.alpnProtocol ?? 'http/1.1', 'http/1.1');
  assert.equal((await h1Get(tlsPort, { ALPNProtocols: [] })).body, 'h2 backend');
  assert.equal((await h1Get(tlsPort, { ALPNProtocols: ['legacy-http'] })).body, 'h2 backend');
  for (const chunked of [false, true]) {
    await h1ToH2Upload(tlsPort, Buffer.concat([Buffer.alloc(131072, 'u'), injection]), chunked);
  }
  const clear = track(http2.connect(`http://127.0.0.1:${clearPort}`));
  assert.equal((await get(clear)).body, 'clear h2');
  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'PRINT']) {
    assert.equal(await clearH1Get(clearPort, method), 'clear h2');
  }
  // The same listener accepts TLS and plaintext; ClientHello read-ahead must replay intact.
  for (const scheme of ['http', 'https']) {
    const automatic = track(http2.connect(`${scheme}://127.0.0.1:${autoPort}`, { rejectUnauthorized: false, servername: 'localhost' }));
    assert.equal((await get(automatic)).body, 'automatic');
    if (scheme === 'https') assert.equal(automatic.alpnProtocol, 'h2');
    const strict = track(http2.connect(`${scheme}://127.0.0.1:${h2OnlyPort}`, { rejectUnauthorized: false, servername: 'localhost' }));
    assert.equal((await get(strict)).body, 'h2 only');
    const denied = track(http2.connect(`${scheme}://127.0.0.1:${h1OnlyPort}`, { rejectUnauthorized: false, servername: 'localhost' }));
    await assert.rejects(get(denied));
  }
  assert.equal(await clearH1Get(autoPort), 'automatic');
  assert.equal((await h1Get(autoPort)).body, 'automatic');
  assert.equal((await h1Get(autoPort, { ALPNProtocols: [] })).body, 'automatic');
  // Negotiated H1 and absent ALPN must not sniff, even for an H1 extension named PRI.
  assert.equal((await h1Get(autoPort, { method: 'PRI' })).body, 'automatic');
  assert.equal((await h1Get(autoPort, { method: 'PRI', ALPNProtocols: [] })).body, 'automatic');
  await assert.rejects(clearH1Get(autoPort, 'PRI'));
  assert.equal(await clearH1Get(h1OnlyPort), 'h1 only');
  assert.equal((await h1Get(h1OnlyPort)).body, 'h1 only');
  assert.equal((await h1Get(h1OnlyPort, { ALPNProtocols: [] })).body, 'h1 only');
  await assert.rejects(clearH1Get(h2OnlyPort));
  await assert.rejects(h1Get(h2OnlyPort));
  await assert.rejects(h1Get(h2OnlyPort, { ALPNProtocols: [] }));
  const selected = track(http2.connect(`https://127.0.0.1:${selectionPort}`, { rejectUnauthorized: false, servername: 'localhost' }));
  assert.equal((await get(selected)).body, 'selected h2');
  assert.equal((await h1Get(selectionPort)).body, 'selected h1');
  assert.equal((await h1Get(selectionPort, { ALPNProtocols: [] })).body, 'selected h1');
  await assert.rejects(h1Get(selectionPort, { servername: 'unknown.localhost' }));
  for (const name of ['empty', 'null']) {
    for (const offered of [[], ['h2', 'http/1.1']]) {
      const result = await h1Get(selectionPort, { servername: `${name}.localhost`, ALPNProtocols: offered });
      assert.equal(result.body, `${name} alpn`);
      assert.equal(result.alpn, false);
    }
  }
  const authenticated = track(http2.connect(`https://127.0.0.1:${authPort}`, { rejectUnauthorized: false, servername: 'localhost', cert, key }));
  assert.equal((await get(authenticated)).body, 'authenticated');
  const anonymous = track(http2.connect(`https://127.0.0.1:${authPort}`, { rejectUnauthorized: false, servername: 'localhost' }));
  await assert.rejects(get(anonymous));
  assert.doesNotMatch(logs, /panicked/);
  if (peerFailure) throw peerFailure;
  console.log('HTTP/2 smoke passed: plaintext detection, protocol allowlists, derived TLS ALPN, optional TLS replay, H1 fallback, H2/H1/H2 translation, independent bidirectional upload parsing, isolation, duplex, 1xx, trailers, reuse, Unix, pins, verification, mTLS.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  for (const session of sessions) session.destroy();
  for (const socket of sockets) socket.destroy();
  if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  if (childClosed) await childClosed;
  await Promise.all(servers.filter(server => server.listening).map(server => new Promise(resolve => server.close(resolve))));
  rmSync(directory, { recursive: true, force: true });
}
