#!/usr/bin/env node
import { loadDeployment } from '../deployment.mjs';
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';

const runtime = join(homedir(), 'Library/Application Support/key-c');
const deployment = loadDeployment();
const child = spawn(process.execPath, [join(runtime, 'paseo/node_modules/@getpaseo/cli/bin/paseo'),
  'daemon', 'run'], { stdio: 'inherit', env: { ...process.env,
    PATH: `${dirname(process.execPath)}:${process.env.PATH ?? ''}`,
    PASEO_HOME: join(homedir(), '.paseo'),
    PASEO_LISTEN: '127.0.0.1:6767', PASEO_WEB_UI_ENABLED: 'true',
    PASEO_HOSTNAMES: deployment.hostname,
    PASEO_LOG_CONSOLE_LEVEL: 'warn', PASEO_LOG_FILE_LEVEL: 'warn',
  } });
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
child.on('exit', code => process.exit(code ?? 0));
child.on('error', () => { console.error('Paseo could not start.'); process.exit(1); });
