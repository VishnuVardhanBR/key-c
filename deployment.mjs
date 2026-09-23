import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function loadDeployment(path = join(homedir(), 'Library/Application Support/key-c/secrets/deployment.json')) {
  const config = JSON.parse(readFileSync(path, 'utf8'));
  const host = /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i;
  for (const field of ['hostname', 'identity_hostname', 'team_domain']) {
    const value = config[field];
    if (typeof value !== 'string' || !host.test(value) || value.includes('example.com') || value.startsWith('your-team.'))
      throw new Error(`Configure ${field} in private deployment.json.`);
  }
  if (!config.team_domain.endsWith('.cloudflareaccess.com') || config.hostname === config.identity_hostname)
    throw new Error('Use separate app/identity hosts and a Cloudflare Access team domain.');
  if (!/^[a-f0-9]{64}$/i.test(config.access_audience ?? '')) throw new Error('Configure the Access application audience.');
  if (typeof config.owner_email !== 'string' || !config.owner_email.includes('@') || config.owner_email.endsWith('@example.com'))
    throw new Error('Configure the owner email.');
  if (!/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(config.key_aaguid ?? ''))
    throw new Error('Configure the YubiKey model AAGUID.');
  for (const field of ['owner_username', 'owner_name'])
    if (typeof config[field] !== 'string' || !config[field].trim()) throw new Error(`Configure ${field}.`);
  return config;
}
