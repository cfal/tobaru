import assert from 'node:assert/strict';
import http from 'node:http';
import http2 from 'node:http2';
import net from 'node:net';
import { once } from 'node:events';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

const binary = resolve(process.argv[2] ?? 'target/debug/tobaru');
const scratch = join(homedir(), 'tmp');
mkdirSync(scratch, { recursive: true });
const root = mkdtempSync(join(scratch, 'tobaru-static-cli-'));
const directory = join(root, 'www');
const signal = AbortSignal.timeout(30_000);
const env = { ...process.env, RUST_LOG: 'info' };

function checkExit(args, status = 0, pattern) {
  const result = spawnSync(binary, ['-t', '1', ...args], {
    cwd: directory, env, encoding: 'utf8', timeout: 5000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, status, `${args.join(' ')}\n${result.stderr}`);
  assert.doesNotMatch(result.stderr, /panicked/);
  assert.doesNotMatch(result.stdout, /Listening/);
  if (pattern) assert.match(result.stderr, pattern);
  return result;
}

async function withServer(args, test) {
  const child = spawn(binary, ['-t', '1', 'static', '-a', '0.0.0.0', '-p', '0', ...args], {
    cwd: directory, env, stdio: ['ignore', 'pipe', 'pipe'], timeout: 10_000, killSignal: 'SIGKILL',
  });
  const closed = new Promise(resolve => child.once('close', resolve));
  let output = '';
  let errors = '';
  child.stderr.on('data', bytes => { errors += bytes; });
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  try {
    const port = await new Promise((resolve, reject) => {
      child.stdout.on('data', bytes => {
        output += bytes;
        const match = output.match(/Listening \(TCP\): 0\.0\.0\.0:(\d+)/);
        if (match) resolve(Number(match[1]));
      });
      child.once('error', reject);
      child.once('exit', (code, signal) => reject(new Error(`Server exited ${code}/${signal}: ${errors}`)));
    });
    assert.notEqual(port, 0);
    await test(port, agent);
    assert.equal(child.exitCode, null, errors);
    assert.equal(child.signalCode, null, errors);
    assert.match(errors, /Serving directory:/);
    assert.match(errors, /allows all source addresses.*dotfiles/);
    assert.doesNotMatch(errors, /panicked/);
  } finally {
    agent.destroy();
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed;
  }
}

function request(port, agent, method, path) {
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: '127.0.0.1', port, agent, method, path, signal }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString() }));
      response.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

async function checkHttp2(port, cache) {
  const client = http2.connect(`http://127.0.0.1:${port}`);
  client.on('error', () => {});
  try {
    for (const [method, path, status, body] of [
      ['GET', '/index.html?test=1', 200, 'index'], ['HEAD', '/', 200, ''],
      ['GET', '/missing', 404, 'Not Found'], ['HEAD', '/missing', 404, ''],
      ['GET', '/empty/', 404, 'Not Found'], ['GET', '/not-file/', 404, 'Not Found'],
    ]) {
      const stream = client.request({ ':method': method, ':path': path }, { signal });
      const response = once(stream, 'response', { signal });
      const chunks = [];
      stream.on('data', chunk => chunks.push(chunk));
      const ended = once(stream, 'end', { signal });
      const [headers] = await response;
      await ended;
      assert.equal(headers[':status'], status);
      assert.equal(headers['cache-control'], status === 200 ? `max-age=${cache}` : undefined);
      assert.equal(headers['content-type'], status === 200 ? 'text/html' : 'text/plain');
      if (status === 404) assert.equal(headers['content-length'], String(Buffer.byteLength('Not Found')));
      assert.equal(Buffer.concat(chunks).toString(), body);
    }
  } finally {
    const closed = once(client, 'close');
    client.destroy();
    await closed;
  }
}

const reservation = net.createServer();
try {
  mkdirSync(join(directory, 'sub'), { recursive: true });
  mkdirSync(join(directory, 'empty'));
  mkdirSync(join(directory, 'not-file', 'index.html'), { recursive: true });
  mkdirSync(join(directory, '-dash'));
  mkdirSync(join(directory, 'dist space'));
  writeFileSync(join(directory, 'index.html'), 'index');
  writeFileSync(join(directory, 'sub', 'hello world.txt'), 'hello');
  writeFileSync(join(directory, '.env'), 'dotfile fixture');
  writeFileSync(join(directory, '-dash', 'index.html'), 'dash');
  writeFileSync(join(directory, 'dist space', 'index.html'), 'dist');
  writeFileSync(join(root, 'outside.txt'), 'must not be served');
  symlinkSync(join(root, 'outside.txt'), join(directory, 'escape.txt'));
  mkdirSync(join(directory, 'escape-index'));
  symlinkSync(join(root, 'outside.txt'), join(directory, 'escape-index', 'index.html'));
  writeFileSync(join(directory, 'static'), JSON.stringify([{
    address: '0.0.0.0:0', transport: 'tcp', target: {
      allowlist: '127.0.0.1', protocol: 'http',
      default_http_action: { type: 'serve-message', status_code: 200 },
    },
  }]));

  checkExit(['--help'], 0, /static \[STATIC OPTIONS\]/);
  checkExit(['static', '--help'], 0, /--cache SECONDS/);
  const invalidPort = checkExit(['static', '-p', 'invalid'], 1, /STATIC OPTIONS:/);
  assert.doesNotMatch(invalidPort.stderr, /CONFIG PATH/);
  const defaults = checkExit(['--dry-run', 'static'], 0, /Dry run complete/);
  assert.doesNotMatch(defaults.stderr, /allows all source addresses/);
  checkExit(['--dry-run', './static'], 0, /Dry run complete/);
  checkExit(['--dry-run', './static', 'static'], 1, /Duplicate listener/);
  checkExit(['static', '--dry-run', '--address', '::1', '--port', '0', '--cache', '0']);
  for (const args of [
    ['static', '-a'], ['static', '-a', 'invalid'], ['static', '-p', '65536'],
    ['static', '-p'], ['static', '-p', '1', '--port', '2'], ['static', '-c'],
    ['static', '-c', 'bad'], ['static', '-c', '-1'], ['static', '-c', '0', '--cache', '0'],
    ['static', '--unknown'], ['static', 'a', 'b'], ['static', '--clear-iptables-all'],
    ['--clear-iptables-matching', 'static', '--dry-run'],
    ['static', '--dry-run', 'missing'], ['static', '--dry-run', 'index.html'],
  ]) checkExit(args, 1);

  for (const [args, cache] of [[[], 3600], [['-c', '0'], 0], [['--cache', '60'], 60]]) {
    await withServer(args, async (port, agent) => {
      for (const [method, path, status, body] of [
        ['GET', '/', 200, 'index'], ['HEAD', '/', 200, ''],
        ['GET', '/index.html?test=1', 200, 'index'],
        ['GET', '/sub/hello%20world.txt', 200, 'hello'],
        ['GET', '/missing', 404, 'Not Found'], ['HEAD', '/missing', 404, ''],
        ['GET', '/empty/', 404, 'Not Found'], ['GET', '/not-file/', 404, 'Not Found'],
        ['GET', '/.env', 200, 'dotfile fixture'], ['POST', '/', 501, ''],
      ]) {
        const response = await request(port, agent, method, path);
        assert.equal(response.status, status, `${method} ${path}`);
        assert.equal(response.body, body, `${method} ${path}`);
        if (status === 200) assert.equal(response.headers['cache-control'], `max-age=${cache}`);
        if (status === 404) {
          assert.equal(response.headers['content-type'], 'text/plain');
          assert.equal(response.headers['content-length'], String(Buffer.byteLength('Not Found')));
          assert.equal(response.headers['cache-control'], undefined);
        }
        if (path === '/sub/hello%20world.txt') assert.equal(response.headers['content-type'], 'text/plain');
      }
      for (const path of ['/../outside.txt', '/%2e%2e/outside.txt', '/escape.txt', '/escape-index/']) {
        await assert.rejects(request(port, agent, 'GET', path), error => error.code === 'ECONNRESET');
      }
      await checkHttp2(port, cache);
    });
  }
  for (const [args, body] of [[['dist space'], 'dist'], [['--', '-dash'], 'dash']]) {
    await withServer(args, async (port, agent) => {
      assert.equal((await request(port, agent, 'GET', '/')).body, body);
    });
  }
  await withServer(['-c', '0'], async (port, agent) => {
    writeFileSync(join(directory, 'index.html'), 'edited');
    assert.equal((await request(port, agent, 'GET', '/')).body, 'edited');
  });

  reservation.listen(0, '0.0.0.0');
  await once(reservation, 'listening', { signal });
  const occupied = String(reservation.address().port);
  checkExit(['static', '-a', '0.0.0.0', '-p', occupied, '--dry-run'], 0, /Dry run complete/);
  checkExit(['static', '-a', '0.0.0.0', '-p', occupied], 1, /Listener .* failed:/);
  console.log('Static CLI checks passed: parsing, roots, H1/H2, cache, containment, edits, dry-run, bind failures.');
} finally {
  if (reservation.listening) await new Promise(resolve => reservation.close(resolve));
  rmSync(root, { recursive: true, force: true });
}
