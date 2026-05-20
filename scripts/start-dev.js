const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const CWD = process.cwd();

// Find python executable in .venv
let pythonPath = path.join(CWD, 'backend', '.venv', 'bin', 'python');
if (!fs.existsSync(pythonPath)) {
  // Try python3 fallback
  pythonPath = 'python3';
}

console.log(`[ForenSys Launcher] Starting backend using python: ${pythonPath}`);

// Start Python Backend
const backend = spawn(pythonPath, [path.join(CWD, 'backend', 'main.py')], {
  stdio: 'inherit',
  env: process.env,
});

backend.on('error', (err) => {
  console.error('[ForenSys Launcher] Failed to start Python backend:', err);
});

// Start Next.js Frontend
console.log('[ForenSys Launcher] Starting Next.js frontend dev server...');
const frontend = spawn('npx', ['next', 'dev'], {
  stdio: 'inherit',
  env: process.env,
  shell: true,
});

frontend.on('error', (err) => {
  console.error('[ForenSys Launcher] Failed to start Next.js frontend:', err);
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
