import time, json, httpx, yaml, os, hmac, hashlib, secrets
from collections import deque, defaultdict
from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse, HTMLResponse

CFG = yaml.safe_load(open("/srv/novastack/shield/shield_config.yaml"))
UPSTREAM = CFG["server"]["upstream"].rstrip("/")
LOG_FILE = CFG["logging"]["file"]
SECRET = secrets.token_hex(32)

app = FastAPI(title="SentryShield")
client = httpx.AsyncClient(timeout=10, follow_redirects=True)
RATE = defaultdict(lambda: deque())
BLACKLIST = set()

def now(): return int(time.time())

def log_event(ip, event_type, path, ua=""):
    if not CFG["logging"]["enabled"]: return
    entry = json.dumps({"t": now(), "ip": ip, "event": event_type, "path": path, "ua": ua})
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")

def rate_check(ip, limit, win):
    dq = RATE[(ip, limit, win)]; t = now()
    while dq and t - dq[0] > win: dq.popleft()
    if len(dq) >= limit: return False
    dq.append(t); return True

def make_challenge_cookie():
    ts = str(now())
    sig = hmac.new(SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"

def verify_challenge_cookie(val):
    try:
        ts, sig = val.rsplit(".", 1)
        expected = hmac.new(SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()
        ttl = CFG["security"]["js_challenge"]["ttl_sec"]
        return hmac.compare_digest(sig, expected) and now() - int(ts) < ttl
    except: return False

JS_CHALLENGE_HTML = """<!DOCTYPE html>
<html><head><title>Checking...</title></head>
<body>
<script>
document.cookie = "__ss_ch={token}; path=/; max-age=3600";
setTimeout(() => location.reload(), 500);
</script>
<p>Verifiserer nettleser...</p>
</body></html>"""

@app.api_route("/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"])
async def proxy(req: Request, path: str):
    ip = req.client.host
    ua = req.headers.get("user-agent", "")
    full_path = "/" + path

    if ip in BLACKLIST:
        log_event(ip, "blacklist_block", full_path, ua)
        return PlainTextResponse("Forbidden", status_code=403)

    honeypot_path = CFG["security"]["honeypot"]["path"]
    if CFG["security"]["honeypot"]["enabled"] and full_path == honeypot_path:
        BLACKLIST.add(ip)
        log_event(ip, "honeypot_hit", full_path, ua)
        return PlainTextResponse("Not Found", status_code=404)

    for bp in CFG["security"].get("blocked_paths", []):
        if full_path.startswith(bp):
            log_event(ip, "blocked_path", full_path, ua)
            return PlainTextResponse("Not Found", status_code=404)

    for ba in CFG["security"].get("blocked_agents", []):
        if ba.lower() in ua.lower():
            log_event(ip, "blocked_agent", full_path, ua)
            return PlainTextResponse("Forbidden", status_code=403)

    if path.startswith("api/"):
        lim = CFG["security"]["rate_limit_data"]["max_requests_per_ip"]
        win = CFG["security"]["rate_limit_data"]["window_sec"]
    else:
        lim = CFG["security"]["rate_limit"]["max_requests_per_ip"]
        win = CFG["security"]["rate_limit"]["window_sec"]

    if not rate_check(ip, lim, win):
        log_event(ip, "rate_limit", full_path, ua)
        return PlainTextResponse("Too Many Requests", status_code=429)

    if CFG["security"]["js_challenge"]["enabled"] and req.method == "GET" and not path.startswith("api/"):
        cookie_val = req.cookies.get("__ss_ch", "")
        if not verify_challenge_cookie(cookie_val):
            token = make_challenge_cookie()
            log_event(ip, "js_challenge", full_path, ua)
            return HTMLResponse(JS_CHALLENGE_HTML.replace("{token}", token))

    url = f"{UPSTREAM}/{path}".rstrip("/")
    qs = req.url.query
    if qs: url = f"{url}?{qs}"
    body = await req.body()
    headers = dict(req.headers)
    headers.pop("host", None)
    headers.pop("accept-encoding", None)
    r = await client.request(req.method, url, content=body, headers=headers)
    log_event(ip, "pass", full_path, ua)
    resp_headers = dict(r.headers)
    resp_headers.pop("content-encoding", None)
    resp_headers.pop("transfer-encoding", None)
    return Response(content=r.content, status_code=r.status_code, headers=resp_headers)
