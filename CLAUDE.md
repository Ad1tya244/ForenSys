# ForenSys: agent guidelines

## Hard constraints (set by the project owner)
1. **Never manipulate real firewalls, processes or the OS.** No `pfctl`, `iptables`, `kill`/`os.kill`/`psutil` terminate,
   `ifconfig`, file quarantine, etc. All "remediation" is *logical*:
   - **Block IP** = add the IP to the perimeter registry (`soar_engine.blocked_ips`); the BPF/Scapy packet sniffer
     (`collectors/traffic.py`) then ignores all telemetry to/from that IP until a human **manually unblocks** it from the UI/API.
     An unblocked IP stays listed (status `released`) so it can be re-blocked.
   - Other actions (sinkhole domain, quarantine process, ...) are recorded in history as simulated/logical containment only.
   - Docs and UI copy must say "perimeter blocklist", never "pfctl / PF rule".
2. **Do not run `git commit` / `git push` (or create branches/PRs) unless the user explicitly says so.** The owner commits.
3. Standard workflow every detection must follow:
   `attack detected -> incident raised -> auto-remediation (logical IP block etc.) -> forensic evidence captured & sealed -> logged in remediation history`.

## Layout
- `backend/` FastAPI + pipeline: collectors -> normalizer -> state_engine -> rules -> correlation -> `pipeline/response.py`
  (orchestrates `soar_engine` containment -> `evidence` sealing -> history + `metrics` incident ledger).
- `backend/pipeline/metrics.py`: persisted incident ledger + MTTD/MTTR statistics (source for Analytics and Reports).
- `backend/reporting/`: dependency-free PDF writer (`pdf.py`) and the incident / SOC-summary report builders.
- `app/dashboard/*`, `lib/app-store.ts`, `lib/api-client.ts`: Next.js dashboard fed by `/ws` snapshots; shared helpers go in `lib/`.
- `docs/REAL_ATTACK_DEMOS.md`: two-laptop real-traffic demo runbook (no in-dashboard attack simulator).
- Run: `npm run dev` (simulated packets only) or `npm run dev:privileged` (real Scapy capture; needed to see real attacks).
- Tests: `backend/.venv/bin/python -m unittest discover -s backend/tests -p "test_*.py"` (run from repo root with `-t backend`).

## Invariants to keep
- **Metrics are real.** MTTD = detection - first observed attacker activity; MTTR = detection -> last containment action
  (evidence sealing excluded). Never clamp, hard-code or fabricate these; uncontained incidents have no MTTR (excluded, not 0).
- **Security:** no hard-coded or default credentials anywhere in the login path; `/ws` requires a first-message `{type:"auth", token}` (never a URL token); no default JWT secret
  (`auth_utils` generates one into `backend/.env`); CORS stays limited to localhost/LAN origins; every mutating or
  evidence-bearing REST endpoint goes through `check_permissions`. Keep `SECURITY.md` truthful when these change.
- **Trust, don't alert on ourselves:** ForenSys components/dependencies (`mysqld`, backend Python, Next.js) are trusted via
  `AssetTrustManager` *only* with the right process **and** an expected port/loopback bind.
- **Clear History vs Reset Lab:** clearing the audit log must never release active containment; only Reset Lab does (and also
  clears the ledger/evidence/alerts).
- **Tests must not touch real runtime data** (`remediation_history.json`, `perimeter_registry.json`, `evidence_vault.json`,
  `incident_ledger.json`, `backend/.env`, `rules.json`, `config.json`). Point engines at temp paths (see `Pipeline` in
  `backend/tests/test_workflow.py`) and don't start the app lifespan (it backfills the ledger).
- **Next.js:** keep `experimental.turbopackFileSystemCacheForDev: false` in `next.config.mjs` (the dev cache corrupts inside
  cloud-synced folders); `page.tsx` files may only export the default component; don't run `next build` in the repo while a
  dev server is running (they share `.next`).
