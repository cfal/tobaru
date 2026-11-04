import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { once } from 'node:events';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import { homedir } from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { setTimeout as delay } from 'node:timers/promises';

const binary = path.resolve(process.argv[2] ?? 'target/debug/tobaru');
const signal = AbortSignal.timeout(120_000);
const sockets = new Set();
const servers = [];
const children = [];
const agents = [];
const sessions = [];
let root;
let allowRelay = true;
const carriers = [];
const portReservations = [];
let retryStartup = false;

function track(socket) {
  sockets.add(socket);
  socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
  return socket;
}

async function listen(server, address) {
  servers.push(server);
  server.on('connection', track);
  server.listen(address ?? { host: '0.0.0.0', port: 0 });
  await once(server, 'listening', { signal });
  return typeof server.address() === 'string' ? server.address() : server.address().port;
}

async function reservePort() {
  const server = net.createServer(socket => socket.destroy());
  portReservations.push(server);
  server.listen(0, '0.0.0.0');
  await once(server, 'listening', { signal });
  return server.address().port;
}

async function releasePorts() {
  await Promise.all(portReservations.splice(0).map(server =>
    new Promise(resolve => server.close(resolve))));
}

async function certificate(name) {
  const certPath = path.join(root, `${name}.pem`);
  const keyPath = path.join(root, `${name}.key`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore', timeout: 10_000 });
  const cert = await readFile(certPath);
  return { certPath, keyPath, cert, key: await readFile(keyPath), pin: new X509Certificate(cert).fingerprint256 };
}

function launch(config, { limitedFds = false } = {}) {
  const command = limitedFds ? '/bin/sh' : binary;
  const args = limitedFds
    ? ['-c', 'ulimit -n 64 || exit; exec "$@"', 'tunnel-fd-test', binary, '-t', '1', config]
    : ['-t', '1', config];
  const child = spawn(command, args, { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, RUST_LOG: 'info' } });
  child.logs = '';
  child.ready = false;
  child.stderr.on('data', bytes => { child.logs = (child.logs + bytes).slice(-64_000); });
  child.closed = once(child, 'close');
  children.push(child);
  return child;
}

async function eventually(operation, milliseconds = 15_000) {
  const deadline = Date.now() + milliseconds;
  let last;
  do {
    signal.throwIfAborted();
    try { return await operation(); } catch (error) { last = error; }
    await delay(100, undefined, { signal });
  } while (Date.now() < deadline);
  throw last;
}

function request(port, url, agent = false) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port, path: url, agent, signal, timeout: 2000 }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { body += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body }));
      response.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('HTTP timeout')));
    req.on('error', reject);
  });
}

async function rejectedRequest(port, url, agent = false) {
  await assert.rejects(request(port, url, agent), { code: 'ECONNRESET' });
}

function readBytes(socket, count) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let length = 0;
    const timer = setTimeout(() => finish(new Error(`Timed out reading ${count} bytes`)), 3000);
    function finish(error) {
      clearTimeout(timer);
      socket.off('data', data);
      socket.off('error', finish);
      socket.off('end', ended);
      if (error) reject(error); else resolve(Buffer.concat(chunks));
    }
    function ended() { finish(new Error('Unexpected EOF')); }
    function data(chunk) {
      chunks.push(chunk);
      length += chunk.length;
      if (length >= count) finish();
    }
    socket.on('data', data);
    socket.once('error', finish);
    socket.once('end', ended);
  });
}

async function raw(port) {
  const socket = track(net.connect({ host: '127.0.0.1', port }));
  const greeting = readBytes(socket, 6);
  await once(socket, 'connect', { signal });
  assert.equal((await greeting).toString(), 'ready\n');
  return socket;
}

async function echo(socket, text) {
  const received = readBytes(socket, Buffer.byteLength(text));
  socket.write(text);
  assert.equal((await received).toString(), text);
}

function h2Request(session, url) {
  return new Promise((resolve, reject) => {
    const stream = session.request({ ':path': url },
      { signal: AbortSignal.any([signal, AbortSignal.timeout(3000)]) });
    let body = '';
    stream.setEncoding('utf8');
    stream.on('data', data => { body += data; });
    stream.on('end', () => resolve(body));
    stream.on('error', reject);
    stream.on('close', () => reject(new Error(`H2 stream closed before completion: ${url}`)));
    stream.end();
  });
}

function frame(message) {
  const body = Buffer.from(JSON.stringify(message));
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(body.length);
  return Buffer.concat([prefix, body]);
}

async function rejectedTls(port, identity, message, { alpn = 'tobaru-reverse/2', requireAlpn = false } = {}) {
  const socket = track(tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false,
    cert: identity?.cert, key: identity?.key, ALPNProtocols: [alpn] }));
  let bytes = 0;
  let negotiated;
  socket.on('data', chunk => { bytes += chunk.length; });
  socket.once('secureConnect', () => {
    negotiated = socket.alpnProtocol;
    socket.write(frame(message));
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('Unauthenticated connection was not rejected')); }, 3000);
    socket.once('close', () => { clearTimeout(timer); resolve(); });
  });
  assert.equal(bytes, 0, 'Rejected peer received a successful protocol response');
  if (requireAlpn) assert.equal(negotiated, 'tobaru-reverse/2', 'Metadata rejection must follow TLS setup');
}

async function assertAcceptRecovery(hubIdentity, agentIdentity, originPort, webPort) {
  const hubPort = await reservePort();
  const publicPort = await reservePort();
  const ordinaryPort = await reservePort();
  const publicPath = path.join(root, 'fd-public.json');
  const clientPath = path.join(root, 'fd-client.json');
  await writeFile(publicPath, JSON.stringify([
    { tunnel_server: 'edge', address: `0.0.0.0:${hubPort}`,
      server_tls: { cert: hubIdentity.certPath, key: hubIdentity.keyPath },
      peers: { home: { client_fingerprints: [agentIdentity.pin], services: ['raw'] } } },
    { address: `0.0.0.0:${publicPort}`, target: { allowlist: 'all',
      location: { tunnel: { server: 'edge', peer: 'home', service: 'raw' } } } },
    { address: `0.0.0.0:${ordinaryPort}`, target: { allowlist: 'all', http_protocols: ['http1'],
      default_http_action: { type: 'forward', location: `127.0.0.1:${webPort}` } } },
  ]));
  await writeFile(clientPath, JSON.stringify([{ tunnel_client: 'home', server: `127.0.0.1:${hubPort}`,
    client_tls: { verify: false, server_fingerprints: [hubIdentity.pin], sni_hostname: 'localhost',
      cert: agentIdentity.certPath, key: agentIdentity.keyPath },
    services: { raw: { location: `127.0.0.1:${originPort}` } },
  }]));
  await releasePorts();
  const hub = launch(publicPath, { limitedFds: true });
  const client = launch(clientPath);
  const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  agents.push(httpAgent);
  const fillers = [];
  let active;
  try {
    await eventually(async () => assert.equal(JSON.parse((await request(ordinaryPort, '/before', httpAgent)).body).path, '/before'));
    const ordinary = Object.values(httpAgent.freeSockets).flat()[0];
    assert(ordinary && !ordinary.destroyed);
    active = await eventually(() => raw(publicPort));
    hub.ready = true;
    client.ready = true;
    for (let cycle = 0; cycle < 2; cycle++) {
      const logOffset = hub.logs.length;
      async function logged(pattern) {
        await eventually(() => {
          assert.equal(hub.exitCode, null, hub.logs);
          assert.equal(hub.signalCode, null, hub.logs);
          assert.match(hub.logs.slice(logOffset), pattern);
        }, 5000);
      }
      // Incomplete ordinary requests hold FDs without the tunnel handshake timeout.
      for (let i = 0; i < 96; i++) {
        const socket = track(net.connect(ordinaryPort, '127.0.0.1'));
        socket.once('connect', () => socket.write('GET /held HTTP/1.1\r\nHost: localhost\r\n'));
        fillers.push(socket);
      }
      await logged(/TCP accept failed.*\(os error 24\)/);
      fillers.push(track(net.connect(hubPort, '127.0.0.1')));
      await logged(/Tunnel accept failed.*\(os error 24\)/);
      // Keep descriptors held across the one-second accept retry.
      await delay(1500, undefined, { signal });
      await echo(active, `under-pressure-${cycle}`);
      assert.equal(JSON.parse((await request(ordinaryPort, '/during', httpAgent)).body).path, '/during');
      assert.equal(Object.values(httpAgent.freeSockets).flat()[0], ordinary);
      assert(!ordinary.destroyed);
      assert.doesNotMatch(hub.logs.slice(logOffset), /Tunnel accept recovered/);

      for (const socket of fillers.splice(0)) socket.destroy();
      const fresh = await eventually(() => raw(publicPort));
      await echo(fresh, `recovered-${cycle}`);
      fresh.destroy();
      await echo(active, `survived-${cycle}`);
      await eventually(async () => assert.equal(JSON.parse((await request(ordinaryPort, '/after')).body).path, '/after'));
      assert.equal(JSON.parse((await request(ordinaryPort, '/survived', httpAgent)).body).path, '/survived');
      assert.equal(Object.values(httpAgent.freeSockets).flat()[0], ordinary);
      await logged(/Tunnel accept recovered/);
      await logged(/TCP accept recovered/);
      assert.equal(hub.exitCode, null, hub.logs);
      assert.equal(hub.signalCode, null, hub.logs);
      assert.doesNotMatch(hub.logs, /panicked/);
    }
  } finally {
    for (const socket of fillers) socket.destroy();
    active?.destroy();
    httpAgent.destroy();
    for (const child of [client, hub]) {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }
    await Promise.all([client.closed, hub.closed]);
  }
}

try {
  const tmp = path.join(homedir(), 'tmp');
  await mkdir(tmp, { recursive: true });
  root = await mkdtemp(path.join(tmp, 'tobaru-reverse-tunnel-'));
  const hubIdentity = await certificate('hub');
  const agentIdentity = await certificate('agent');
  const stranger = await certificate('stranger');
  let rawAccepts = 0;
  const rawPort = await listen(net.createServer({ allowHalfOpen: true }, socket => {
    rawAccepts++;
    socket.write('ready\n');
    socket.on('data', data => socket.write(data));
    socket.on('end', () => socket.end('finished'));
  }));
  let httpAccepts = 0;
  let cachedOrigin;
  const web = http.createServer((req, res) => {
    if (req.url === '/pre-reload-cache') cachedOrigin = req.socket;
    res.setHeader('set-cookie', 'test=yes; Path=/');
    res.end(JSON.stringify({ path: req.url, host: req.headers.host }));
  });
  web.keepAliveTimeout = 60_000;
  const upgradeHeaders = 'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n';
  web.on('upgrade', (_req, socket, head) => {
    socket.write(upgradeHeaders);
    if (head.length) socket.write(head);
    socket.on('data', data => socket.write(data));
  });
  web.on('connection', () => httpAccepts++);
  const webPort = await listen(web);
  const h2 = http2.createServer();
  h2.on('session', session => { sessions.push(session); session.on('error', () => {}); });
  h2.on('stream', (stream, headers) => { stream.respond({ ':status': 200 }); stream.end(`h2:${headers[':path']}`); });
  const h2Port = await listen(h2);
  const secureWebPort = await listen(https.createServer(hubIdentity, (req, res) => res.end(`tls:${req.url}`)));
  const secureH2 = http2.createSecureServer(hubIdentity);
  secureH2.on('session', session => { sessions.push(session); session.on('error', () => {}); });
  secureH2.on('stream', (stream, headers) => { stream.respond({ ':status': 200 }); stream.end(`h2tls:${headers[':path']}`); });
  const secureH2Port = await listen(secureH2);
  const unixPath = path.join(root, 'origin.sock');
  await listen(net.createServer(socket => socket.pipe(socket)), unixPath);

  const hubPort = await reservePort();
  const relayPort = await listen(net.createServer({ allowHalfOpen: true }, incoming => {
    if (!allowRelay) { incoming.destroy(); return; }
    const outgoing = track(net.connect({ port: hubPort, host: '127.0.0.1', allowHalfOpen: true }));
    const carrier = { incoming, outgoing };
    carriers.push(carrier);
    incoming.pipe(outgoing).pipe(incoming);
    incoming.on('close', () => outgoing.destroy());
    outgoing.on('close', () => incoming.destroy());
  }));
  const publicRaw = await reservePort();
  const publicHttp = await reservePort();
  const publicUnix = await reservePort();
  const publicPass = await reservePort();
  const publicRawTls = await reservePort();
  const services = ['web', 'raw', 'unix', 'h2', 'secure', 'secure_h2', 'spare'];
  const destination = service => ({ tunnel: { server: 'edge', peer: 'home', service } });
  const paths = {};
  for (const [prefix, service, upstream, innerTls] of [
    ['/home/', 'web', 'http1', false], ['/h2/', 'h2', 'http2', false],
    ['/secure/', 'secure', 'http1', true], ['/secure-h2/', 'secure_h2', 'http2', true],
  ]) {
    const location = destination(service);
    if (innerTls) location.client_tls = { verify: false, server_fingerprints: [hubIdentity.pin], sni_hostname: 'localhost' };
    paths[prefix] = { http_action: { type: 'forward', upstream_protocol: upstream, location, replacement_path: '/' } };
  }
  paths['/bad-pin/'] = { http_action: { type: 'forward', location: {
    ...destination('secure'), client_tls: { verify: false, server_fingerprints: [stranger.pin], sni_hostname: 'localhost' },
  } } };
  const publicConfig = [
    { tunnel_server: 'edge', address: `0.0.0.0:${hubPort}`, server_tls: { cert: hubIdentity.certPath, key: hubIdentity.keyPath },
      peers: { home: { client_fingerprints: [agentIdentity.pin], services } } },
    { address: `0.0.0.0:${publicRaw}`, target: { allowlist: 'all', location: destination('raw') } },
    { address: `0.0.0.0:${publicUnix}`, target: { allowlist: 'all', location: destination('unix') } },
    { address: `0.0.0.0:${publicPass}`, target: { allowlist: 'all', location: destination('secure'), server_tls: { mode: 'passthrough' } } },
    { address: `0.0.0.0:${publicHttp}`, target: { allowlist: 'all', http_protocols: ['http1', 'http2'], http_paths: paths,
      default_http_action: { type: 'serve-message', status_code: 404 } } },
    { address: `0.0.0.0:${publicRawTls}`, target: { allowlist: 'all', location: destination('raw'),
      server_tls: { cert: hubIdentity.certPath, key: hubIdentity.keyPath } } },
  ];
  const clientConfig = [{ tunnel_client: 'home', server: `127.0.0.1:${relayPort}`,
    client_tls: { verify: false, server_fingerprints: [hubIdentity.pin], sni_hostname: 'localhost', cert: agentIdentity.certPath, key: agentIdentity.keyPath },
    services: Object.fromEntries(Object.entries({ web: webPort, raw: rawPort, h2: h2Port, secure: secureWebPort, secure_h2: secureH2Port, spare: rawPort })
      .map(([name, port]) => [name, { location: `127.0.0.1:${port}` }])),
  }];
  clientConfig[0].services.unix = { location: unixPath };
  const publicPath = path.join(root, 'public.json');
  const clientPath = path.join(root, 'client.json');
  await writeFile(publicPath, JSON.stringify(publicConfig));
  await writeFile(clientPath, JSON.stringify(clientConfig));
  for (const config of [publicPath, clientPath]) {
    const result = spawnSync(binary, ['-t', '1', '--dry-run', config], { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 0, result.stderr);
  }
  const badPath = path.join(root, 'invalid.json');
  async function invalidConfig(config) {
    await writeFile(badPath, JSON.stringify(config));
    const result = spawnSync(binary, ['-t', '1', '--dry-run', badPath], { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.status, 1, `Invalid config accepted: ${JSON.stringify(config)}\n${result.stderr}`);
    assert.doesNotMatch(result.stderr, /panicked/);
  }
  for (const patch of [
    client => { client.client_tls.verify = false; client.client_tls.server_fingerprints = []; },
    client => { client.client_tls.alpn_protocols = ['h2']; },
    client => { client.services.web.location = destination('web'); },
    client => { client.services.web.location = { address: `127.0.0.1:${webPort}`, client_tls: true }; },
    client => { client.max_data_connections = null; },
    client => { client.tunnel_server = 'conflicting-role'; },
  ]) {
    const bad = structuredClone(clientConfig);
    patch(bad[0]);
    await invalidConfig(bad);
  }
  await invalidConfig([...clientConfig, ...structuredClone(clientConfig)]);
  for (const patch of [
    config => { config[1].address = config[0].address; },
    config => { config.push({ ...structuredClone(config[0]), address: '127.0.0.1:1' }); },
    config => { config[0].peers.other = structuredClone(config[0].peers.home); },
    config => { config[0].peers.home.services.push('web'); },
    config => { config[0].max_handshakes = 1025; },
    config => { config[0].peers.home.idle_connections = 0; },
    config => { config[0].peers.home.idle_connections = 4; },
    config => { config[1].target.location.tunnel.service = 'missing'; },
    config => { config[1].target.location.client_tls = { verify: true }; },
    config => { config[1].target.location.client_tls = { verify: true, sni_hostname: null }; },
    config => { config[1].target.location.client_tls = { verify: true, sni_hostname: 'bad name' }; },
  ]) {
    const bad = structuredClone(publicConfig);
    patch(bad);
    await invalidConfig(bad);
  }
  await releasePorts();
  const publicChild = launch(publicPath);
  const clientChild = launch(clientPath);
  const liveCarriers = () => carriers.filter(carrier => !carrier.incoming.destroyed && !carrier.outgoing.destroyed);
  await eventually(() => assert.match(clientChild.logs, /Tunnel client home registered/));
  publicChild.ready = true;
  clientChild.ready = true;
  const registeredCarriers = carriers.length;
  await delay(500, undefined, { signal });
  assert.equal(liveCarriers().length, 1, 'Registration must create only the control connection');
  assert.equal(carriers.length, registeredCarriers, 'Data channels must not be created without demand');
  assert.equal(rawAccepts, 0);
  assert.equal(httpAccepts, 0);
  const controlCarrier = liveCarriers()[0];
  assert(controlCarrier);
  const first = await raw(publicRaw);
  await echo(first, 'first-demand');
  first.destroy();
  await eventually(() => assert.equal(liveCarriers().length, 1));
  await delay(500, undefined, { signal });
  assert.equal(carriers.length, registeredCarriers + 1, 'Completed demand must not replenish a spare');
  assert.equal(liveCarriers().length, 1);
  await eventually(async () => assert.equal((await request(publicHttp, '/home/start')).status, 200));

  const hello = { type: 'control_hello', version: 2, peer: 'home', services: ['web'] };
  await rejectedTls(hubPort, undefined, hello);
  await rejectedTls(hubPort, stranger, hello);
  await rejectedTls(hubPort, agentIdentity, { ...hello, peer: 'impostor' }, { requireAlpn: true });
  await rejectedTls(hubPort, agentIdentity, hello, { alpn: 'h2' });
  await rejectedTls(hubPort, agentIdentity, { ...hello, version: 1 }, { alpn: 'tobaru-reverse/1' });
  await rejectedTls(hubPort, agentIdentity, { ...hello, version: 1 }, { requireAlpn: true });
  await rejectedTls(hubPort, agentIdentity, { type: 'data_hello', version: 2, peer: 'home', session_id: '0'.repeat(32), channel_id: '1'.repeat(32) }, { requireAlpn: true });

  const httpAgent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  agents.push(httpAgent);
  const response = await request(publicHttp, '/home/a?x=1', httpAgent);
  assert.equal(JSON.parse(response.body).path, '/a?x=1');
  assert.deepEqual(response.headers['set-cookie'], ['test=yes; Path=/']);
  assert.equal(JSON.parse(response.body).host, `127.0.0.1:${publicHttp}`);
  const beforeReuse = httpAccepts;
  const reused = await request(publicHttp, '/home/again', httpAgent);
  assert.equal(reused.status, 200);
  assert.equal(JSON.parse(reused.body).path, '/again');
  assert.equal(httpAccepts, beforeReuse);
  assert.equal((await request(publicHttp, '/h2/a')).body, 'h2:/a');
  assert.equal((await request(publicHttp, '/secure/b')).body, 'tls:/b');
  assert.equal((await request(publicHttp, '/secure-h2/c')).body, 'h2tls:/c');
  await rejectedRequest(publicHttp, '/bad-pin/');
  assert.equal((await request(publicHttp, '/secure/still-usable')).body, 'tls:/still-usable');
  const upgrade = track(net.connect(publicHttp, '127.0.0.1'));
  await once(upgrade, 'connect', { signal });
  const upgraded = readBytes(upgrade, Buffer.byteLength(upgradeHeaders + 'read-ahead'));
  upgrade.write('GET /home/upgrade HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nread-ahead');
  const upgradeReply = (await upgraded).toString();
  assert.match(upgradeReply, /101 Switching Protocols/);
  assert(upgradeReply.endsWith('read-ahead'));
  await echo(upgrade, 'upgraded');
  const frontendH2 = http2.connect(`http://127.0.0.1:${publicHttp}`);
  sessions.push(frontendH2);
  frontendH2.on('error', () => {});
  assert.equal(JSON.parse(await h2Request(frontendH2, '/home/h2-front')).path, '/h2-front');
  assert.equal(await h2Request(frontendH2, '/h2/d'), 'h2:/d');
  assert.equal(await h2Request(frontendH2, '/secure-h2/e'), 'h2tls:/e');

  const passthrough = track(tls.connect({ host: '127.0.0.1', port: publicPass, servername: 'localhost', rejectUnauthorized: false }));
  await once(passthrough, 'secureConnect', { signal });
  const passReply = readBytes(passthrough, 13);
  passthrough.write('GET /passthrough HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  assert.match((await passReply).toString(), /^HTTP\/1\.1 200 /);
  passthrough.destroy();
  const terminated = track(tls.connect({ host: '127.0.0.1', port: publicRawTls,
    servername: 'localhost', rejectUnauthorized: false }));
  const terminatedGreeting = readBytes(terminated, 6);
  await once(terminated, 'secureConnect', { signal });
  assert.equal((await terminatedGreeting).toString(), 'ready\n');
  await echo(terminated, 'tls-terminated-raw');
  terminated.destroy();
  const unix = track(net.connect(publicUnix, '127.0.0.1'));
  await once(unix, 'connect', { signal });
  await echo(unix, 'unix');
  unix.destroy();

  const beforeBurst = rawAccepts;
  const burst = await Promise.all(Array.from({ length: 12 }, () => raw(publicRaw)));
  await Promise.all(burst.map((socket, i) => echo(socket, `burst-${i}`)));
  assert.equal(rawAccepts - beforeBurst, 12, 'Demand must drain beyond the four in-flight creation credits');
  const active = burst.pop();
  for (const socket of burst) socket.destroy();
  const half = await raw(publicRaw);
  const finished = readBytes(half, 8);
  half.end();
  assert.equal((await finished).toString(), 'finished');
  half.destroy();

  allowRelay = false;
  const disconnectOffset = clientChild.logs.length;
  controlCarrier.incoming.destroy();
  controlCarrier.outgoing.destroy();
  await eventually(() => assert.match(clientChild.logs.slice(disconnectOffset), /Tunnel client home disconnected/));
  await eventually(() => rejectedRequest(publicHttp, '/home/new-physical'));
  await echo(active, 'control-lost');
  await echo(upgrade, 'upgrade-control-lost');
  assert.equal(JSON.parse((await request(publicHttp, '/home/reused', httpAgent)).body).path, '/reused');
  assert.equal(await h2Request(frontendH2, '/h2/reused'), 'h2:/reused');
  allowRelay = true;
  await eventually(async () => assert.equal((await request(publicHttp, '/home/reconnected')).status, 200));

  for (const invalidate of [
    config => { config[0].max_connections = 0; },
    config => { config[1].address = config[0].address; },
  ]) {
    const invalid = structuredClone(publicConfig);
    invalidate(invalid);
    const logOffset = publicChild.logs.length;
    await writeFile(publicPath, JSON.stringify(invalid));
    await eventually(() => assert.match(publicChild.logs.slice(logOffset), /Config reload rejected/));
    await echo(active, 'invalid-reload-preserved');
  }
  const stale = track(tls.connect({ host: '127.0.0.1', port: hubPort, rejectUnauthorized: false,
    cert: agentIdentity.cert, key: agentIdentity.key, ALPNProtocols: ['tobaru-reverse/2'] }));
  await once(stale, 'secureConnect', { signal });
  const reloadSignal = AbortSignal.any([signal, AbortSignal.timeout(5000)]);
  const activeClosed = once(active, 'close', { signal: reloadSignal });
  const staleClosed = once(stale, 'close', { signal: reloadSignal });
  await request(publicHttp, '/home/pre-reload-cache', httpAgent);
  assert(cachedOrigin && !cachedOrigin.destroyed);
  const cachedOriginClosed = once(cachedOrigin, 'close', { signal: reloadSignal });
  const cachedFrontend = Object.values(httpAgent.freeSockets).flat()[0];
  assert(cachedFrontend && !cachedFrontend.destroyed);
  // Removing an unused export must not prevent the remaining intersection registering.
  publicConfig[0].peers.home.services = services.filter(name => name !== 'spare');
  await writeFile(publicPath, JSON.stringify(publicConfig));
  await Promise.all([activeClosed, staleClosed, cachedOriginClosed]);
  await eventually(async () => assert.equal((await request(publicHttp, '/home/reloaded')).status, 200));
  assert(!cachedFrontend.destroyed, 'Idle H1 frontend should survive backend revocation');
  await rejectedRequest(publicHttp, '/home/retired-generation', httpAgent);
  assert.equal((await request(publicHttp, '/home/new-generation', httpAgent)).status, 200);
  assert.match(clientChild.logs, /exports not accepted/);

  const clientActive = await raw(publicRaw);
  const clientClosed = once(clientActive, 'close', { signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]) });
  await writeFile(clientPath, `${JSON.stringify(clientConfig)}\n`);
  await clientClosed;
  await eventually(async () => assert.equal((await request(publicHttp, '/home/client-reloaded')).status, 200));
  clientChild.kill('SIGKILL');
  await clientChild.closed;
  await eventually(() => rejectedRequest(publicHttp, '/home/offline'));
  launch(clientPath);
  await eventually(async () => assert.equal((await request(publicHttp, '/home/restarted')).status, 200));
  assert.equal(publicChild.exitCode, null);
  await assertAcceptRecovery(hubIdentity, agentIdentity, rawPort, webPort);
  console.log('reverse tunnel smoke passed: mTLS, demand-only channels, TCP/Unix, half-close, H1/H2, origin TLS, control loss, reload, reconnect, FD exhaustion recovery');
} catch (error) {
  for (const child of children) console.error(child.logs);
  retryStartup = process.argv[3] !== '--startup-retry' && children.some(child =>
    !child.ready && child.exitCode !== null && /Address already in use/i.test(child.logs));
  if (!retryStartup) throw error;
} finally {
  for (const agent of agents) agent.destroy();
  for (const session of sessions) session.destroy();
  for (const socket of sockets) socket.destroy();
  for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  await Promise.all(children.map(child => child.closed));
  for (const server of servers) await new Promise(resolve => server.close(resolve));
  await releasePorts();
  if (root) await rm(root, { recursive: true, force: true });
}

if (retryStartup) {
  console.error('Retrying reverse tunnel smoke after a startup port collision');
  const result = spawnSync(process.execPath, [process.argv[1], binary, '--startup-retry'],
    { stdio: 'inherit', timeout: 125_000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, 'Reverse tunnel smoke retry failed');
}
