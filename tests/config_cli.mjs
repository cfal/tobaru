import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}
console.log('Configuration CLI checks passed');
