"""Read operator settings kept outside the public checkout."""
import json
from pathlib import Path
import re


def load_deployment(path=None):
    path = path or Path.home() / 'Library/Application Support/key-c/secrets/deployment.json'
    config = json.loads(Path(path).read_text())
    for field in ('hostname', 'identity_hostname', 'team_domain'):
        value = config.get(field)
        if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', value, re.I) or 'example.com' in value or value.startswith('your-team.'):
            raise ValueError(f'Configure {field} in private deployment.json.')
    if not config['team_domain'].endswith('.cloudflareaccess.com') or config['hostname'] == config['identity_hostname']:
        raise ValueError('Use separate app/identity hosts and a Cloudflare Access team domain.')
    if not re.fullmatch(r'[a-f0-9]{64}', config.get('access_audience', ''), re.I):
        raise ValueError('Configure the Access application audience.')
    if not isinstance(config.get('owner_email'), str) or '@' not in config['owner_email'] or config['owner_email'].endswith('@example.com'):
        raise ValueError('Configure the owner email.')
    if not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', config.get('key_aaguid', ''), re.I):
        raise ValueError('Configure the YubiKey model AAGUID.')
    for field in ('owner_username', 'owner_name'):
        if not isinstance(config.get(field), str) or not config[field].strip():
            raise ValueError(f'Configure {field}.')
    return config
