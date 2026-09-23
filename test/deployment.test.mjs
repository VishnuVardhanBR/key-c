import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { loadDeployment } from '../deployment.mjs';

const valid = { hostname: 'computer.example.net', identity_hostname: 'auth.example.net',
  team_domain: 'fixture.cloudflareaccess.com', access_audience: 'a'.repeat(64),
  owner_email: 'operator@example.net', owner_username: 'operator', owner_name: 'Operator',
  key_aaguid: '11111111-1111-1111-1111-111111111111' };

function fixture(t) {
  const folder = mkdtempSync(join(tmpdir(), 'key-c-config-')), path = join(folder, 'deployment.json');
  t.after(() => rmSync(folder, { recursive: true, force: true }));
  const python = () => spawnSync('python3', ['-c',
    'import sys; sys.path.insert(0,"bin"); from deployment import load_deployment; load_deployment(sys.argv[1])', path]);
  return { path, python, write: config => writeFileSync(path, JSON.stringify(config)) };
}

test('gateway and provisioning read the same explicit operator configuration', t => {
  const f = fixture(t); f.write(valid);
  assert.deepEqual(loadDeployment(f.path), valid);
  assert.equal(f.python().status, 0);
});

test('missing configuration never falls back to a deployment identity', t => {
  const f = fixture(t);
  assert.throws(() => loadDeployment(f.path), /ENOENT/);
  assert.notEqual(f.python().status, 0);
});

test('both configuration readers reject templates and incomplete or unsafe identities', t => {
  const f = fixture(t);
  assert.throws(() => loadDeployment(new URL('../config/deployment.example.json', import.meta.url)));
  for (const change of [{ hostname: 'computer.example.com' }, { hostname: 'https://wrong.test/path' },
    { identity_hostname: valid.hostname }, { team_domain: 'untrusted.invalid' },
    { access_audience: '' }, { owner_email: 'owner@example.com' }, { owner_name: '' }, { key_aaguid: 'unset' }]) {
    f.write({ ...valid, ...change });
    assert.throws(() => loadDeployment(f.path));
    assert.notEqual(f.python().status, 0);
  }
});
