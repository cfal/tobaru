import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const binary = resolve(process.argv[2] ?? join(root, 'target/release/tobaru'));
const scratch = join(homedir(), 'tmp');
mkdirSync(scratch, { recursive: true });
const directory = mkdtempSync(join(scratch, 'tobaru-http-smoke-'));
const signal = AbortSignal.timeout(15_000);
const sockets = new Set();
const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
let connections = 0;
let child;
let childClosed;
let childError;
let logs = '';

const backend = http.createServer((request, response) => {
  const chunks = [];
  request.on('data', chunk => chunks.push(chunk));
  request.on('end', () => {
    const body = request.url === '/echo' ? Buffer.concat(chunks) : Buffer.from('working');
    response.writeHead(200, {
      'Content-Length': body.length,
      'Set-Cookie': ['a=1', 'a=2'],
    });
    response.end(body);
  });
});
backend.on('connection', socket => {
  connections++;
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
});

async function listen(server) {
  server.listen(0, '0.0.0.0');
  await once(server, 'listening', { signal });
  return server.address().port;
}

async function close(server) {
  if (server.listening) {
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  }
}

function request(port, method, path, body) {
  return new Promise((resolve, reject) => {
    let continues = 0;
    const req = http.request({
      hostname: '127.0.0.1', port, method, path, agent, signal,
      headers: body ? { 'Content-Length': body.length, Expect: '100-continue' } : {},
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ response, body: Buffer.concat(chunks), continues }));
      response.on('error', reject);
    });
    req.on('error', reject);
    if (body) {
      req.on('continue', () => {
        continues++;
        if (continues === 1) req.end(body);
      });
      req.flushHeaders();
    } else {
      req.end();
    }
  });
}

const reservation = net.createServer();
try {
  const backendPort = await listen(backend);
  const port = await listen(reservation);
  await close(reservation);
  const config = [{ address: `0.0.0.0:${port}`, transport: 'tcp', target: {
    allowlist: '127.0.0.1/32',
    default_http_action: { type: 'forward', location: `127.0.0.1:${backendPort}` },
  } }];
  const configPath = join(directory, 'config.json');
  writeFileSync(configPath, JSON.stringify(config));
  child = spawn(binary, ['-t', '1', configPath]);
  childClosed = new Promise(resolve => child.once('close', resolve));
  child.on('error', error => { childError = error; });
  const capture = bytes => { logs = (logs + bytes).slice(-65536); };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);

  for (;;) {
    if (childError) throw childError;
    if (child.exitCode !== null || child.signalCode !== null) throw new Error('Proxy exited during startup');
    try {
      const ready = await request(port, 'GET', '/');
      assert.equal(ready.response.statusCode, 200);
      break;
    } catch (error) {
      if (error.code !== 'ECONNREFUSED') throw error;
      await delay(25, undefined, { signal });
    }
  }

  const ordinary = await request(port, 'GET', '/');
  assert.equal(ordinary.response.statusCode, 200);
  assert.equal(ordinary.body.toString(), 'working');
  assert.deepEqual(ordinary.response.headers['set-cookie'], ['a=1', 'a=2']);
  const head = await request(port, 'HEAD', '/');
  assert.equal(head.response.statusCode, 200);
  assert.equal(head.body.length, 0);
  assert.equal(head.response.headers['content-length'], '7');
  const payload = Buffer.alloc(128 * 1024, 'x');
  const echoed = await request(port, 'POST', '/echo', payload);
  assert.equal(echoed.response.statusCode, 200);
  assert.deepEqual(echoed.body, payload);
  assert.equal(echoed.continues, 1);
  assert.equal(connections, 1, 'Sequential requests must reuse their backend');

  const socket = new net.Socket({ signal });
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
  socket.connect(port, '127.0.0.1');
  await once(socket, 'connect', { signal });
  let wire = '';
  socket.on('data', data => { wire += data; });
  socket.write('GET / HTTP/1.1\r\nHost: localhost\r\n\r\nGET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');
  await once(socket, 'end', { signal });
  socket.destroy();
  assert.equal((wire.match(/HTTP\/1\.1 200/g) ?? []).length, 2);
  assert.equal((wire.match(/working/g) ?? []).length, 2);
  assert.equal(connections, 2, 'Each frontend connection owns its backend');
  console.log('HTTP CLI smoke passed: config/TCP dispatch, backend reuse, HEAD, ordered cookies, Expect, 128 KiB echo, pipelining.');
} catch (error) {
  console.error(logs);
  throw error;
} finally {
  agent.destroy();
  for (const socket of sockets) socket.destroy();
  if (child) {
    child.kill('SIGTERM');
    const killTimer = setTimeout(() => child.kill('SIGKILL'), 1000);
    try {
      await childClosed;
    } finally {
      clearTimeout(killTimer);
    }
  }
  await close(reservation);
  await close(backend);
  rmSync(directory, { recursive: true, force: true });
}
