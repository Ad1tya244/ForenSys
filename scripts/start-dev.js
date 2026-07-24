const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const CWD = process.cwd();

const isPrivileged = process.argv.includes('--privileged') || process.argv.includes('-p');

// Find python executable in .venv
let pythonPath = path.join(CWD, 'backend', '.venv', 'bin', 'python');
if (!fs.existsSync(pythonPath)) {
  // Try python3 fallback
  pythonPath = 'python3';
}

console.log(`[ForenSys Launcher] Starting backend using python: ${pythonPath}${isPrivileged ? ' (under sudo/privileged mode)' : ''}`);
if (isPrivileged) {
  console.log('\x1b[33m%s\x1b[0m', '⚠️  [ForenSys Launcher] Privileged mode requested. Please enter your administrator password below if prompted:');
}

// Start Python Backend
const backendCmd = isPrivileged ? 'sudo' : pythonPath;
const backendArgs = isPrivileged 
  ? [pythonPath, path.join(CWD, 'backend', 'main.py')] 
  : [path.join(CWD, 'backend', 'main.py')];

const backend = spawn(backendCmd, backendArgs, {
  stdio: 'inherit',
  env: process.env,
  cwd: path.join(CWD, 'backend'),
});

backend.on('error', (err) => {
  console.error('[ForenSys Launcher] Failed to start Python backend:', err);
});

const http = require('http');

let frontend = null;

function waitForBackend(callback) {
  const check = () => {
    const req = http.get('http://127.0.0.1:8000/api/health', (res) => {
      if (res.statusCode === 200) {
        callback();
      } else {
        setTimeout(check, 150);
      }
    });
    req.on('error', () => {
      setTimeout(check, 150);
    });
    req.end();
  };
  check();
}

console.log('[ForenSys Launcher] Waiting for Python backend on port 8000 to be ready...');
waitForBackend(() => {
  console.log('\x1b[32m%s\x1b[0m', '[ForenSys Launcher] ✅ Python backend is live on http://127.0.0.1:8000! Starting Next.js frontend...');
  frontend = spawn('npx', ['next', 'dev'], {
    stdio: 'inherit',
    env: process.env,
    shell: true,
  });

  frontend.on('error', (err) => {
    console.error('[ForenSys Launcher] Failed to start Next.js frontend:', err);
  });
});

// Cleanup function to terminate both child processes
const cleanup = () => {
  console.log('\n[ForenSys Launcher] Shutting down services...');
  
  if (backend) {
    try {
      backend.kill('SIGTERM');
      console.log('[ForenSys Launcher] Stopped Python backend.');
    } catch (e) {}
  }
  
  if (frontend) {
    try {
      frontend.kill('SIGTERM');
      console.log('[ForenSys Launcher] Stopped Next.js frontend.');
    } catch (e) {}
  }
  
  process.exit();
};

// Listen to terminal exit / interrupt events to ensure clean shutdowns
process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
process.on('exit', cleanup);
