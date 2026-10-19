import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

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
console.log('Configuration CLI checks passed');
