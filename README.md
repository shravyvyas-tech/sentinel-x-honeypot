<div align="center">

# 🛡️ SENTINEL-X
### Deception Command — Multi-Protocol Honeypot & Live Threat Dashboard

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-informational)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

**A single-file Python honeypot that emulates 14 real-world services, logs every attacker interaction, cross-checks their real-world location across 3 GeoIP sources, maps your own local network devices, and visualizes everything on a live 3D globe.**

</div>

---

## ⚠️ Before you start — read this

> This tool is built for **education, home-lab security research, and authorized
> monitoring only.** Running exposed network services that capture third-party
> traffic can be restricted by law depending on where you live and where you host
> it. **Never deploy this on a network or server you don't own or don't have
> explicit written permission to monitor.** You are fully responsible for how
> you use it. See [Legal & Disclaimer](#️-legal--disclaimer).

---

## 📸 What it looks like

### 1. Secure login — with brute-force lockout
The dashboard itself is protected by an authenticated login screen. After too many
wrong attempts from the same IP, it locks out automatically (configurable).

![Login screen](screenshots/01-login.png)

### 2. Live 3D attack globe
Every connection — yours and attackers' — is geolocated and plotted on a rotating
3D Earth in real time, along with a live telemetry feed and per-port hit counters.

![Dashboard globe view](screenshots/02-dashboard-globe.png)

### 3. Threat radar + service listeners
A radar-style sweep shows active sources at a glance, next to a live list of every
emulated service and its port/protocol.

![Threat radar and service listeners](screenshots/03-threat-radar.png)

### 4. Full searchable log viewer
Every single packet/command an attacker sends is logged with timestamp, severity,
source IP, port, raw data, and the reason it was flagged — filterable and
downloadable.

![Log viewer](screenshots/04-logs.png)

### 5. Port & service manager
Turn any of the 14 emulated services on/off, change the port it listens on, and
edit its banner — all from the browser, no code editing required.

![Port and service management](screenshots/05-ports.png)

### 6. System configuration
Control listen address, session timeout, alert thresholds, the Discord/Slack
webhook, and admin-panel lockout settings — all live, no restart needed for most
changes.

![System configuration](screenshots/06-config.png)

### 7. Shield — anti-detection mode
Locks your service fingerprints so scanners always see a consistent signature,
adds random timing jitter, tarpits aggressive scanners, and auto-bans detected
scanning tools.

![Shield anti-detection panel](screenshots/07-shield.png)

---

## ✨ Full feature list

- **14 emulated services**: HTTP, HTTPS, FTP, SSH, Telnet, SMTP, MySQL, Redis,
  PostgreSQL, POP3, IMAP, DNS, SNMP, TFTP
- **Live 3D globe** (Three.js) — see every connection plotted geographically in
  real time, color-coded by type (you / attacker / shielded-scanner)
- **Multi-source GeoIP cross-check** — queries **MaxMind GeoLite2** (offline),
  **ip-api.com**, and **ipinfo.io** in parallel, merges the results, and gives
  you a confidence rating (`HIGH` / `MEDIUM` / `LOW`) based on how closely the
  independent sources agree
- **VPN / Proxy / Datacenter detection** — flags attacker IPs that are exit
  nodes or hosting-provider IPs, so you know when the shown location is *not*
  the attacker's real one
- **UDP spoof-risk tagging** — UDP-based hits (DNS, SNMP, TFTP) are explicitly
  labeled "source IP spoofable, not handshake-verified," since UDP has no
  3-way handshake to confirm the sender. TCP-based hits (SSH, FTP, HTTP, etc.)
  **cannot** be meaningfully spoofed, because the handshake must complete —
  these are tagged as trustworthy
- **Local network device mapping (ARP scan)** — SentinelX scans your own LAN
  and plots every connected device (phone, laptop, router, smart TV, etc.) on
  the same dashboard, showing **IP address + MAC address + hostname** for
  each one. This is how you tell "an attacker from the internet" apart from
  "my own phone on the same WiFi" — see the [VPN & Local Network Tracing](#-vpn--local-network-device-tracing) section below
- **Shield mode** (anti-fingerprinting):
  - Locks banners to one fixed signature so repeat scanners can't tell your
    config changed
  - Random timing jitter to defeat timing-based fingerprinting
  - Tarpit mode to slow down aggressive automated scanners
  - Auto-detects and temporary-bans known scanner behavior
- **Brute-force & rate-limit detection** with severity scoring (INFO → LOW →
  MEDIUM → HIGH → CRITICAL)
- **Admin-panel login lockout** — the dashboard's *own* login is protected from
  brute-forcing (separate from the honeypot's brute-force detection)
- **Discord / Slack webhook alerts** — get pinged instantly when a
  HIGH/CRITICAL event fires
- **Full event export** — download filtered logs as JSON/CSV from the Export tab
- **Hardened by default**:
  - Passwords hashed with `scrypt` (not plaintext, not fast-crackable MD5/SHA1)
  - All data files (`auth.json`, `config.json`, `events.jsonl`, `shield.json`)
    written with `0600` permissions (owner-only read/write)
  - Strict Content-Security-Policy, `X-Content-Type-Options`,
    `Referrer-Policy`, and `Permissions-Policy` headers on the dashboard
  - Dashboard binds to `127.0.0.1` by default — not exposed to the internet
    unless you explicitly change it

---

## 🧭 VPN & Local Network Device Tracing

This is one of the most useful parts of the dashboard, so here's exactly how it
works and how to read it.

### A) Tracing your *own* local network (devices on your WiFi/LAN)

SentinelX periodically runs an **ARP scan** on your local network. ARP (Address
Resolution Protocol) is how devices on the same network find each other's
hardware (MAC) address — every device, every router, every phone replies to it,
so nothing can hide from it the way it can hide from internet-based IP lookups.

**What you get for every local device:**

| Field | What it tells you |
|---|---|
| **IP address** | The device's current address on your LAN (e.g. `192.168.1.23`) |
| **MAC address** | The hardware address burned into the device's network chip — doesn't change even if the IP does |
| **Hostname** (when available) | The device's name on the network, e.g. `android-phone`, `DESKTOP-ABC123` |

**How to see it:**
1. Open the **Dashboard** tab
2. Local devices appear on the 3D globe near your own marker, and in the
   side list
3. Click on any local device marker/row → a **"LOCAL DEVICE"** panel opens
   showing its IP, MAC, and hostname

**Why this matters:** if you ever see a connection hitting your honeypot ports
from an IP in your own private range (`10.x.x.x`, `192.168.x.x`, `172.16–31.x.x`),
the dashboard tags it `Private: YES` and skips GeoIP (because private IPs have
no real-world location). Instead, **cross-reference its MAC address against this
local device list** — this tells you exactly which device on your own network
triggered it (which is usually just your own phone/laptop testing something, but
occasionally it's an actual unknown device that shouldn't be on your network).

### B) Tracing attackers who use a VPN / proxy

This is the important part to understand honestly, because no tool — this one
included — can promise something that isn't technically possible:

- When an attacker connects **through a VPN, proxy, or Tor**, the IP that
  reaches your honeypot is the **VPN exit server's IP**, not the attacker's
  real one. TCP still completes its handshake normally (VPNs don't break
  TCP), so the connection is "real," but the *location* it resolves to is the
  VPN provider's server location (e.g. "Netherlands" or "Singapore"), not
  wherever the attacker is actually sitting.
- SentinelX **detects this** using the `proxy`/`hosting` flags returned by the
  GeoIP sources, and shows a clear warning on that attacker's dossier:
  > ⚠️ VPN/PROXY or DATACENTER/HOSTING IP detected — the location shown is the
  > exit node, not the attacker's real one.
- **What this does *not* do:** it cannot unmask the real IP behind a VPN. That
  is only possible with legal process against the VPN provider (court order /
  subpoena for their connection logs, if they keep any) — no honeypot,
  GeoIP service, or script can bypass that. Anyone claiming otherwise is
  misrepresenting what's technically possible.
- **UDP-based attacks are a separate risk**: UDP has no handshake, so a UDP
  packet's source IP *can* be spoofed/forged outright (not just hidden behind
  a VPN). SentinelX labels every UDP-sourced event with a spoof-risk warning
  for exactly this reason — treat UDP source IPs as *unverified*, while
  TCP source IPs are handshake-verified and safe to trust as "real" (even if
  that real IP happens to belong to a VPN server).

---

## 🚀 Step-by-step installation guide

### Step 1 — Install Python
You need **Python 3.8 or newer**.
- Check if you already have it:
  ```bash
  python3 --version
  ```
- If not installed, download from <https://www.python.org/downloads/> (Windows/macOS)
  or install via your package manager on Linux:
  ```bash
  sudo apt install python3 python3-pip      # Debian/Ubuntu
  ```

### Step 2 — Get the code
**Option A — clone with Git:**
```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```
**Option B — download ZIP:**
Click the green **Code → Download ZIP** button on the GitHub repo page, extract
it anywhere, then open a terminal in that folder.

### Step 3 — Install the optional GeoIP package
```bash
pip install geoip2 --break-system-packages
```
*(If this package or the MaxMind database below is missing, the tool still
works fine — it just falls back to the online GeoIP sources only.)*

### Step 4 — (Optional, recommended) Set up offline GeoIP
This makes location lookups faster, removes rate limits, and improves the
confidence score.
1. Create a **free** account: <https://www.maxmind.com/en/geolite2/signup>
   (no credit card required)
2. Go to *Manage License Keys* → generate a new key (also free)
3. Download the database:
   ```bash
   wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz" -O geolite.tar.gz
   tar -xzf geolite.tar.gz
   ```
4. Find the extracted `GeoLite2-City.mmdb` file and move it into a folder
   named `sx_data` next to `honey.py`:
   ```bash
   mkdir -p sx_data
   mv GeoLite2-*/GeoLite2-City.mmdb sx_data/
   ```

### Step 5 — Run it
```bash
python3 honey.py
```
You'll see startup logs confirming which services started and whether GeoIP
sources loaded successfully.

### Step 6 — Open the dashboard
Go to:
```
http://127.0.0.1:8080
```
in your browser.

### Step 7 — Create your admin account
The **first time only**, click **"Create one"** on the login screen to sign up
an admin account. After that, signup is disabled by default (so no one else
can register), and you log in normally with your username/password.

### Step 8 — Configure what you need
- **Ports tab** → enable/disable services, change ports/banners
- **Config tab** → set your Discord/Slack webhook, tweak lockout settings,
  toggle geolocation
- **Shield tab** → turn on anti-detection mode (recommended for anything
  facing the internet)

### Step 9 — (If exposing it beyond your own machine) Open firewall ports
Only do this if you actually intend to expose the honeypot to the internet
(e.g. on a VPS) — **never do this on your home network/router** unless you
fully understand the exposure:
```bash
# Example for Ubuntu/Debian with ufw — adjust ports to what you enabled
sudo ufw allow 8081/tcp   # HTTP
sudo ufw allow 2222/tcp   # SSH
# ...repeat for whichever services you enabled
```
The **dashboard** (port `8080`) binds to `127.0.0.1` only by default and is
**not** reachable from outside your machine unless you deliberately change
`listen_address` in Config — leave it as-is unless you know exactly why you're
changing it.

---

## 🗂️ Project structure

```
honey.py                      # the entire application — one file
sx_data/                      # created automatically on first run — DO NOT COMMIT
  ├─ auth.json                # hashed admin credentials (scrypt)
  ├─ config.json              # your live configuration
  ├─ events.jsonl             # full event/attack log
  ├─ shield.json              # shield/fingerprint lock state
  └─ GeoLite2-City.mmdb       # optional offline GeoIP database (you add this)
screenshots/                  # README images
.gitignore                    # excludes sx_data/ from version control
README.md                     # this file
```

> 🔒 **`sx_data/` is excluded via `.gitignore` on purpose.** It contains your
> admin password hash and complete attacker logs. Never commit or upload it
> anywhere public.

---

## ⚙️ Configuration reference

| Setting | Where | What it does |
|---|---|---|
| `listen_address` | Config tab | Network interface the honeypot *services* bind to |
| `web_session_timeout` | Config tab | How long a dashboard login session stays valid (seconds) |
| `alert.threshold` | Config tab | Minimum severity (1–4) that counts as an "alert" |
| `alert.webhook` | Config tab | Discord/Slack webhook URL — fires on HIGH/CRITICAL events |
| `web_lockout.attempts` | Config tab | Failed dashboard-login attempts before lockout |
| `web_lockout.ban` | Config tab | Lockout duration in seconds |
| `geo.enabled` | Config tab | Turn GeoIP lookups on/off entirely |
| Per-service `enabled` / `port` / `banner` | Ports tab | Toggle, move, or disguise any of the 14 services |
| Shield `jitter` / `tarpit` / decoy | Shield tab | Anti-fingerprinting behavior |

---

## 🧩 Known limitations (please read)

Being upfront about this matters more than overselling the tool:

- **IP geolocation is never GPS-exact.** Even with 3 cross-checked sources,
  expect city/region-level accuracy at best — this is a limitation of IP
  geolocation as a technology, not something any tool can fully solve.
- **VPN/Proxy/Tor traffic resolves to the exit node**, not the attacker's real
  location. The dashboard flags this clearly when detected, but cannot reverse
  it — that requires legal process against the provider.
- **UDP source IPs can be spoofed** since UDP has no handshake. TCP source
  IPs effectively cannot be, since the 3-way handshake must complete for any
  data exchange to happen.
- **Free-tier online GeoIP APIs are rate-limited.** Add the offline MaxMind
  database (Step 4 above) if you expect high traffic.
- This is a **honeypot**, not a firewall or IDS/IPS — it does not block
  attacks, it observes and logs them.

---

## ⚖️ Legal & Disclaimer

This project is provided strictly for **educational purposes, personal
research, and authorized security testing** (e.g. your own home lab or a
system you have explicit written permission to monitor).

Intercepting, logging, or monitoring network traffic from third parties
without authorization may violate computer-misuse, wiretapping, or
data-protection laws depending on your country and where the system is
hosted. **You are solely responsible** for ensuring your deployment complies
with all applicable laws and your hosting provider's terms of service. The
author(s) of this project accept no liability for misuse or damages arising
from its use.

---

## 📄 License

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE)
for details. *(Replace with your preferred license before publishing if MIT
doesn't fit your needs.)*

---

<div align="center">

**If this project helped you, consider starring ⭐ the repo.**

</div>
