# SentryShield

**Lightweight WAF and reverse proxy with bot protection, built with FastAPI.**

SentryShield er en lettvekts Web Application Firewall (WAF) og reverse proxy bygget med FastAPI. Designet for å beskytte e-handelsplattformer mot uønsket scraping, bots og angrep.

---

## Features / Funksjoner

- 🛡️ **Rate limiting** — IP-basert struping med sliding window algorithm
- 🍯 **Honeypot** — Automatisk svartelisting av IPs som treffer skjulte endepunkter
- 🤖 **JS Challenge** — HMAC-signert cookie-utfordring som stopper dumme botter
- 🚫 **Bot/Agent blocking** — Blokkerer kjente scraper user-agents (scrapy, curl, wget)
- 🔒 **Path blocking** — Automatisk 404 på kjente angrepsstier (.env, wp-admin, .git)
- 📝 **JSONL Logging** — Strukturert logging av alle hendelser med IP, type og timestamp
- ⚡ **Async proxy** — Full async reverse proxy med httpx

---

## Architecture / Arkitektur 

Browser → Nginx → SentryShield (8080) → Next.js / App (3000)
↓
API direkte → FastAPI (8000)

---

## Quick Start
```bash
pip install fastapi uvicorn httpx pyyaml
uvicorn shield_server:app --host 0.0.0.0 --port 8080
```

---

## Configuration / Konfigurasjon

Edit `shield_config.yaml`:
```yaml
server:
  upstream: "http://localhost:3000"
  port: 8080
security:
  rate_limit:
    window_sec: 60
    max_requests_per_ip: 120
  honeypot:
    enabled: true
    path: "/__hp__"
  js_challenge:
    enabled: true
```

---

## Built with / Bygget med

- [FastAPI](https://fastapi.tiangolo.com/)
- [httpx](https://www.python-httpx.org/)
- [Uvicorn](https://www.uvicorn.org/)
- [PyYAML](https://pyyaml.org/)

---

