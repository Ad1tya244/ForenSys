# Security Policy

ForenSys is a security tool, so its own security matters. This document explains how to report a vulnerability, what the project protects, how it is designed to resist attack, and - just as importantly - where it is **known to be weak**.

## Contents

1. [Supported versions](#1-supported-versions)
2. [Reporting a vulnerability](#2-reporting-a-vulnerability)
3. [Scope](#3-scope)
4. [Security model](#4-security-model)
5. [Controls in detail](#5-controls-in-detail)
6. [Deployment hardening checklist](#6-deployment-hardening-checklist)
7. [Known limitations](#7-known-limitations)
8. [Data leaving your machine](#8-data-leaving-your-machine)
9. [Responsible use](#9-responsible-use)
10. [Security testing](#10-security-testing)
11. [Past issues](#11-past-issues)

---

## 1. Supported versions

ForenSys is a pre-1.0 project maintained by one person. Only the latest commit on the `main` branch receives security fixes; there are no maintained release branches.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Anything older | ❌ - please update |

## 2. Reporting a vulnerability

**Please do not open a public issue for a security problem.**

1. Use GitHub's private reporting: open the repository's **Security** tab → **Report a vulnerability**
   (<https://github.com/Ad1tya244/ForenSys/security/advisories/new>).
2. Include: what is affected (endpoint, file, page), the impact, clear reproduction steps or a proof of concept, the commit you tested, and your environment (OS, run mode - `npm run dev` or `dev:privileged`).
3. Do not include real credentials, tokens or other people's data in the report.

**What to expect (best effort, solo maintainer):** an acknowledgement within about a week, a fix or mitigation plan for confirmed issues as soon as practical, and credit in the release notes if you want it. Please allow a reasonable period for a fix before any public disclosure (coordinated disclosure).

## 3. Scope

**In scope**

- Authentication or session flaws: login bypass, token forgery or reuse, refresh-cookie handling, WebSocket authentication bypass.
- Authorization flaws: reaching data or actions without the required RBAC permission, privilege escalation between roles.
- Injection: command, SQL, path traversal (evidence, report and artifact paths), header injection, PDF/report content injection.
- Disclosure of secrets or telemetry to unauthenticated parties (including the live `/ws` stream and `/api/*`).
- Flaws in containment logic: e.g. tricking ForenSys into blocking its own host, bypassing self-protection, or tampering with sealed evidence without detection.

**Out of scope**

- Denial of service against a local development instance.
- Attacks that already require root or code execution as the user running ForenSys.
- Missing HTTPS/TLS on `localhost` development setups (see [deployment hardening](#6-deployment-hardening-checklist)).
- Findings that only exist because you deliberately exposed the dev servers to an untrusted network.
- Social engineering, physical access, and vulnerabilities in third-party dependencies with no practical impact on ForenSys (report those upstream).

## 4. Security model

**What ForenSys protects:** the confidentiality and integrity of the telemetry it collects (connections, processes, logs, packet headers), the forensic evidence it seals, the user accounts, and the correctness of its own containment decisions.

**Trust boundaries**

| Boundary | Trust assumption |
|---|---|
| Browser ⇄ Next.js (`:3000`) / FastAPI (`:8000`) | Untrusted network. Every API call and the WebSocket must authenticate; origins are restricted. |
| Frontend ⇄ backend | Bearer access token (short-lived) + `HttpOnly` refresh cookie. |
| Backend ⇄ host OS | The backend reads telemetry and **never** changes firewall rules, kills processes or modifies files outside its own data directory. |
| Backend ⇄ MySQL | Trusted local database holding accounts only. |
| Observed traffic / log content | **Untrusted input.** It is parsed defensively and rendered as text (including in PDFs). |

**Design principle:** remediation is *logical*. A block is an entry in a registry that the packet sniffer consults; it cannot cut off a host or damage the system if it is wrong, and every action is auditable and reversible.

## 5. Controls in detail

### Authentication and sessions

| Control | Detail |
|---|---|
| Password storage | bcrypt. Older accounts that still carry a salted SHA-256 hash are accepted but are **not** automatically upgraded (see [limitations](#7-known-limitations)). |
| Credentials | **No default or hard-coded passwords.** Accounts without a password hash cannot log in. |
| Access token | JWT (HS256), 15-minute lifetime, sent as a Bearer header and kept in memory. |
| Refresh token | JWT, 7 days, `HttpOnly`, `SameSite=Lax` cookie. Cannot be used as an access token. |
| Signing secret | `JWT_SECRET_KEY` from `backend/.env`. If missing or weak, a strong random secret is generated and saved (file mode `600`). The old public default is rejected. Rotating the secret signs everyone out. |
| WebSocket | `/ws` accepts a connection but sends **nothing** until the first message `{"type":"auth","token":...}` carries a valid access token for an active user. Otherwise it closes with code `4003`. The token is never placed in the URL (so it stays out of access logs and history). Streams are cut when the token expires and the client renews its session. |

### Authorization (RBAC)

Four roles map to twelve permissions (`view_alerts`, `manage_alerts`, `view_incidents`, `manage_incidents`, `view_forensics`, `export_forensics`, `view_analytics`, `run_hunt`, `manage_playbooks`, `view_logs`, `manage_settings`, `manage_users`). Every mutating or evidence-bearing REST endpoint goes through `check_permissions(...)` on the backend; the UI hiding a button is a convenience, not a control. Examples: PDF incident reports need `view_forensics`, blocking/unblocking and Reset Lab need `manage_playbooks`, changing detection thresholds needs `manage_settings` (config API) or `manage_playbooks` / the admin role (rules API).

### Network exposure

- **CORS** allows only `localhost`, `127.0.0.1`, private RFC 1918 ranges and `*.local` origins (with credentials). Arbitrary internet origins are rejected, which prevents a malicious website from using your session cookie to call the API.
- Incident IDs used in file names and headers are validated (`^[A-Za-z0-9_-]{1,40}$`) to prevent header injection and path traversal.
- All subprocess calls (`lsof`, `arp`, `log`, `tail`) use argument lists, never a shell.

### Evidence integrity

Every incident's evidence package is sealed with a SHA-256 digest of its canonical payload (including the containment actions and artifact hashes). Reports recompute the digest and print **VERIFIED** or **MISMATCH**, so later modification of the vault is detectable. The headers-only `capture.pcap` carries its own SHA-256 inside the sealed payload.

> The digest detects accidental or unsophisticated modification. It is not a signature: someone with write access to the whole backend directory could alter a package *and* recompute its hash.

### Self-protection and safe remediation

- `AssetTrustManager` stops ForenSys from alerting on or containing itself (its PIDs, project path, local interface IPs, loopback traffic) and its dependencies (`mysqld`, the Python backend, the Next.js dev server) - **only** when both the process identity and an expected port/loopback bind match.
- Containment never targets local host addresses or loopback; skipped actions are logged as such.
- Clearing the audit log can never release active containment; only the explicit, confirmation-gated *Reset Lab* does.

### Report generation

PDFs are produced by a small built-in writer. All text is forced into the font encoding and escaped, so hostile log or packet content (parentheses, backslashes, control characters, non-Latin text) cannot break out of the document structure. No external renderer, template engine or HTML is involved.

## 6. Deployment hardening checklist

ForenSys targets a workstation or lab. If you run it anywhere another machine can reach it:

- [ ] **Complete first-run setup immediately**, on a trusted network. Until the first administrator exists, `/api/auth/setup` is open to anyone who can reach the backend.
- [ ] **Do not expose ports 3000/8000 to the internet.** The backend listens on all interfaces (`0.0.0.0:8000`) by design so another device on your LAN can use the dashboard; restrict it with a host firewall or bind it to loopback if you do not need that.
- [ ] **Terminate TLS** (reverse proxy such as Caddy/nginx) and set the refresh-cookie `secure` flag to `True` in `backend/main.py` (it is `False` so plain-HTTP localhost works).
- [ ] Keep `backend/.env` at mode `600`, and never commit it (it is git-ignored). It holds the database password and JWT secret.
- [ ] Use a **dedicated MySQL user** with rights only on the `forensys` database instead of `root`.
- [ ] Set `GEMINI_API_KEY` (server-side) only if you accept the [data flow](#8-data-leaving-your-machine); never use a `NEXT_PUBLIC_` variable for it - that would ship the key to every browser.
- [ ] **Privileged mode:** `npm run dev:privileged` executes `backend/main.py` and the backend's Python environment **as root**. Keep the project directory and `backend/.venv` owned by you and not writable by other users or untrusted processes, otherwise anything that can modify them gains root on the next launch.
- [ ] Remove stale `backend/users.json` / `backend/deleted_evidence.json` left over from older versions.
- [ ] Back up `backend/evidence_vault.json` and `backend/evidence/` if the evidence matters; they are stored unencrypted.

## 7. Known limitations

These are real, currently open weaknesses. They are acceptable for a local single-user lab and should be fixed before any wider deployment.

| # | Limitation | Impact / mitigation |
|---|---|---|
| 1 | **No login rate limiting or account lockout** | Online password guessing against `/api/auth/login` is not throttled. Use long passphrases; keep the backend off untrusted networks. |
| 2 | **Refresh cookie is not `Secure`** and there is no built-in TLS | Over plain HTTP, tokens can be sniffed on the network. Use TLS in front of the app outside localhost. |
| 3 | **First-run admin setup is unauthenticated** | Whoever reaches the backend first can claim the admin account. Complete setup before exposing the host. |
| 4 | **`/api/chat` (Iris) does not verify the session** | Anyone who can reach port 3000 can send prompts that spend your Gemini quota and read model answers about whatever context they supply. Leave `GEMINI_API_KEY` unset on shared networks. |
| 5 | **Evidence, ledger and history are plain JSON on disk**, protected only by filesystem permissions | A local attacker with file access can read them and, with enough access, rewrite them together with their hashes. |
| 6 | **Backend binds to all interfaces** | See the hardening checklist. |
| 7 | **Single-host design** | There is no agent authentication or transport security for remote collectors because there are no remote collectors. |
| 8 | **Heuristic detection** | Rules are threshold-based; they can be evaded by slow or distributed activity and can false-positive on unusual-but-benign traffic. |
| 9 | **A user profile (not a token) is cached in `localStorage`** | Readable by any script running in the page origin; keep the frontend free of untrusted scripts. |
| 10 | **Legacy salted-SHA-256 password hashes are not upgraded to bcrypt on login** | Affects only accounts created by very old versions. Reset those users' passwords from the RBAC page so they are re-hashed with bcrypt. |

## 8. Data leaving your machine

ForenSys is local-first, but three optional/ambient features contact third parties:

| Feature | Destination | What is sent |
|---|---|---|
| IP geolocation | `ipapi.co` | **Public** remote IP addresses seen in your connections (private/LAN addresses are never sent). Results are cached. |
| Threat blocklist | `rules.emergingthreats.net` | A download of the public blocklist; nothing about you is sent. |
| Iris AI copilot (only if `GEMINI_API_KEY` is set) | `generativelanguage.googleapis.com` (Google Gemini) | Your question plus the alert, incident and metrics context supplied by the browser. Without a key, a local rules-based fallback runs and nothing leaves the machine. |

## 9. Responsible use

ForenSys's demos and docs include real attack techniques (port scans, floods, brute force, reverse shells). **Run them only against systems and networks you own or have explicit written permission to test.** Unauthorized scanning or attacking of other systems is illegal in most jurisdictions. The maintainer accepts no responsibility for misuse.

## 10. Security testing

`backend/tests/test_security.py` guards the controls above and runs with the normal test suite:

```bash
cd backend && .venv/bin/python -m unittest discover -s tests -p "test_*.py" -t .
```

It verifies: WebSocket rejection of missing, malformed, forged, refresh-type, expired and inactive-user tokens; that no snapshot data is sent before authentication; that a token in the URL does not authenticate; expired-token streams are closed; CORS accepts LAN/localhost origins and rejects internet origins; the JWT secret is strong and the old public default is rejected; and that **no hard-coded password can log in**. Other test modules cover evidence integrity (tampering is flagged) and report generation with hostile input.

Dependency versions are pinned in `backend/requirements.txt` and `package.json`; run `pip-audit` and `npm audit` periodically.

## 11. Past issues

Disclosed for transparency; all are fixed on `main`.

| Issue | Fix |
|---|---|
| **Login accepted hard-coded passwords** (`password`, `admin`, `password123`, ...) for any active account, and accounts with no password hash were silently given `password123` | Backdoor and default-password assignment removed; regression tests added. Any legacy account without a real hash can no longer sign in. |
| **JWT signing secret fell back to a public default**, and `.env` was read too late to override it | Secret is loaded correctly, a strong one is generated when missing, and the old default is rejected. |
| **`/ws` streamed all telemetry to unauthenticated clients**, and the token travelled in the URL | First-message authentication, `4003` close on failure, expiry enforcement. |
| **CORS allowed any origin with credentials** | Restricted to localhost / private-LAN / `.local` origins. |
