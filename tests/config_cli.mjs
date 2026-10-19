import assert from 'node:assert/strict';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

const binary = resolve(process.argv[2] ?? 'target/debug/tobaru');
for (const scheme of ['tcp', 'udp']) {
  for (const [host, exposed] of [
    ['127.0.0.1', false], ['127.2.3.4', false], ['[::1]', false],
    ['[::ffff:127.0.0.1]', false], ['localhost', false],
    ['0.0.0.0', true], ['[::]', true], ['192.0.2.1', true],
    ['[2001:db8::1]', true], ['[::ffff:192.0.2.1]', true],
  ]) {
    const result = spawnSync(binary, ['--dry-run', `${scheme}://${host}:9000?target=192.0.2.123:8123`], {
      encoding: 'utf8', timeout: 5000, env: { ...process.env, RUST_LOG: 'warn' },
    });
    assert.equal(result.status, 0, `${scheme}://${host}: ${result.stderr}`);
    const warnings = result.stderr.split('\n').filter(line => line.includes('allows all source addresses'));
    assert.equal(warnings.length, exposed ? 1 : 0, `${scheme}://${host}: ${result.stderr}`);
    assert(!warnings.join('\n').includes('192.0.2.123'), 'warning leaked destination');
    if (exposed) assert(warnings[0].includes('built-in firewall rules disabled'));
  }
}

const tmp = join(homedir(), 'tmp');
mkdirSync(tmp, { recursive: true });
const root = mkdtempSync(join(tmp, 'tobaru-cidr-config-'));
try {
  const configPath = join(root, 'config.json');
  const cert = join(root, 'cert.pem');
  const key = join(root, 'key.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key,
    '-out', cert, '-days', '1', '-subj', '/CN=localhost'], { stdio: 'ignore', timeout: 10_000 });

  function check(config, duplicate = false) {
    writeFileSync(configPath, JSON.stringify(config));
    const result = spawnSync(binary, ['-t', '1', '--dry-run', configPath], {
      encoding: 'utf8', timeout: 5000, env: { ...process.env, RUST_LOG: 'warn' },
    });
    const context = `${JSON.stringify(config)}\n${result.stderr}`;
    assert.ifError(result.error);
    assert.doesNotMatch(result.stderr, /panicked/, context);
    assert.equal(result.status, duplicate ? 1 : 0, context);
    if (duplicate) assert.match(result.stderr, /duplicated/, context);
  }

  const firewallLog = join(root, 'firewall.log');
  const firewallBin = join(root, 'bin');
  mkdirSync(firewallBin);
  for (const command of ['iptables', 'ip6tables']) {
    writeFileSync(join(firewallBin, command), `#!/bin/sh
printf '%s' "\${0##*/}" >> "$FIREWALL_LOG"
printf ' %s' "$@" >> "$FIREWALL_LOG"
printf '\\n' >> "$FIREWALL_LOG"
`, { mode: 0o755 });
  }

  async function checkFirewall(config, expectedSource) {
    writeFileSync(configPath, JSON.stringify([config]));
    writeFileSync(firewallLog, '');
    const child = spawn(binary, ['-t', '1', configPath], {
      timeout: 5000, killSignal: 'SIGKILL',
      env: { ...process.env, PATH: firewallBin, FIREWALL_LOG: firewallLog, RUST_LOG: 'warn' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const closed = new Promise(resolve => child.once('close', resolve));
    let output = '';
    let errors = '';
    child.stderr.on('data', data => { errors += data; });
    try {
      await new Promise((resolve, reject) => {
        child.stdout.on('data', data => {
          output += data;
          if (output.includes(`Listening (${config.transport.toUpperCase()})`)) resolve();
        });
        child.once('error', reject);
        child.once('exit', (code, signal) => reject(new Error(`Startup failed: ${code}/${signal}\n${errors}`)));
      });
      const commands = readFileSync(firewallLog, 'utf8').trim().split('\n').map(line => line.split(' '));
      const context = `${JSON.stringify(config)}\n${JSON.stringify(commands)}`;
      const accepts = commands.filter(args => args[0] === 'iptables' && args.includes('ACCEPT'));
      assert.deepEqual(accepts.map(args => args[args.indexOf('-s') + 1]),
        expectedSource === null ? [] : [expectedSource], context);
      for (const command of ['iptables', 'ip6tables']) {
        assert.equal(commands.filter(args => args[0] === command && args.includes('DROP')).length, 1, context);
      }
      assert.equal(commands.filter(args => args[0] === 'ip6tables' && args.includes('ACCEPT')).length, 1, context);
      assert(commands.filter(args => args.includes('-A'))
        .every(args => args[args.indexOf('--protocol') + 1] === config.transport), context);
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      await closed;
    }
  }

  const accepted = [
    ['192.0.2.123/26'],
    ['2001:db8:1234:5678:ffff::1/65'],
    ['192.0.2.1/32', '192.0.2.200/24'],
    ['192.0.2.200/24', '192.0.2.1/32'],
    ['2001:db8::1/128', '2001:db8::ffff/64'],
    ['2001:db8::ffff/64', '2001:db8::1/128'],
    ['all', '0.0.0.0/0'],
  ];
  const duplicates = [
    ['192.0.2.123/26', '192.0.2.64/26'],
    ['192.0.2.123/26', '::ffff:192.0.2.64/122'],
    ['2001:db8:1234:5678:ffff::1/65', '2001:db8:1234:5678:8000::/65'],
  ];
  for (const [transport, serverTls] of [
    ['tcp', undefined],
    ['tcp', { mode: 'passthrough' }],
    ['tcp', { cert, key }],
    ['udp', undefined],
  ]) {
    const target = allowlist => ({ allowlist, location: '127.0.0.1:9', server_tls: serverTls });
    const server = targets => ({ address: '0.0.0.0:0', transport, iptables: false, targets });
    for (const grouped of [false, true]) {
      const config = allowlist => grouped
        ? [{ group: 'clients', ip_masks: allowlist }, server([target('clients')])]
        : [server([target(allowlist)])];
      for (const allowlist of accepted) check(config(allowlist));
      for (const pair of duplicates) {
        check(config(pair), true);
        check(config([...pair].reverse()), true);
      }
    }
    for (const pair of duplicates) {
      check([server(pair.map(target))], transport === 'udp');
    }
    for (const [allowlist, expectedSource] of [
      ['::ffff:192.0.2.123/81', '0.0.0.0/0'],
      ['::ffff:192.0.2.123/95', '0.0.0.0/0'],
      ['::ffff:192.0.2.123/80', '0.0.0.0/0'],
      ['::ffff:192.0.2.123/96', '0.0.0.0/0'],
      ['::ffff:192.0.2.123/97', '128.0.0.0/1'],
      ['::ffff:192.0.2.123/122', '192.0.2.64/26'],
      ['192.0.2.123/26', '192.0.2.64/26'],
      ['all', '0.0.0.0/0'],
      ['2001:db8::1234/64', null],
      ['0:0:0:0:0:ff:c000:27b/88', null],
      ['::192.0.2.123/122', null],
      ['::1/128', null],
    ]) {
      await checkFirewall({ ...server([target(allowlist)]), iptables: true }, expectedSource);
    }
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}
console.log('Configuration CLI checks passed');
