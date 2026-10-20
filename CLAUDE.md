# ForenSys: agent guidelines

## Hard constraints (set by the project owner)
1. **Never manipulate real firewalls, processes or the OS.** No `pfctl`, `iptables`, `kill`/`os.kill`/`psutil` terminate,
   `ifconfig`, file quarantine, etc. All "remediation" is *logical*:
   - **Block IP** = add the IP to `soar_engine.blocked_ips`; the BPF/Scapy packet sniffer (`collectors/traffic.py`)
     then ignores all telemetry to/from that IP until a human **manually unblocks** it from the UI/API.
   - Other actions (kill process, quarantine, ...) are recorded in history as simulated containment only.
   - Docs and UI copy must say "perimeter blocklist", never "pfctl / PF rule".
2. **Do not run `git commit` / `git push` (or create branches/PRs) unless the user explicitly says so.** The owner commits.
3. Standard workflow every detection must follow:
   `attack detected -> incident raised -> auto-remediation (logical IP block etc.) -> forensic evidence captured & sealed -> logged in remediation history`.

## Layout
- `backend/` FastAPI + pipeline (collectors -> normalizer -> state_engine -> rules -> correlation -> soar_engine / evidence).
- `app/dashboard/*`, `lib/app-store.ts`, `lib/api-client.ts`: Next.js dashboard fed by `/ws` snapshots.
- Run: `npm run dev` (simulated packets) or `npm run dev:privileged` (real Scapy capture).
- Tests: `backend/.venv/bin/python -m unittest discover -s backend/tests -p "test_*.py"` (run from repo root with `-t backend`).
