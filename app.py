# --- IMPORTS ---
from flask import (
    Flask, request, render_template, redirect, url_for, make_response,
    jsonify, send_from_directory, flash, session, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import uuid
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import random
import string
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys
import re
import hashlib
import secrets

# Import from db_util
from db_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip,
    get_all_used_ips, is_ip_used, is_ip_bad,
    log_bad_proxy, get_bad_proxies_list,
    get_all_system_logs, add_log_entry,
    clear_all_system_logs, clear_user_stats, clear_all_api_usage,
    add_api_usage_log, get_all_api_usage_logs,
    get_user_stats_summary,
    add_bulk_proxies, get_random_proxies_from_pool, get_pool_stats, clear_proxy_pool,
    get_daily_api_usage_for_user, update_api_credits, get_pool_preview,
    get_all_users, add_user, delete_user, update_user_fetch_permission, update_user_role, update_user_api_limit,
    add_recent_checks, get_pending_checks, mark_recent_check_copied,
    update_username, update_password,
    get_user_by_id, get_user_by_username, get_user_by_api_key, set_user_api_key_hash
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)
_secret = os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    # Never fall back to a key that is visible in the repo. A random key keeps the app
    # safe but logs everyone out on each cold start, so set FLASK_SECRET_KEY on Vercel.
    logging.getLogger(__name__).critical("FLASK_SECRET_KEY is not set! Using a random key.")
    _secret = secrets.token_hex(32)
app.secret_key = _secret
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",   # blocks cross-site POSTs (CSRF) in modern browsers
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"

BLOCKED_IPS = {"192.168.1.50", "10.0.0.5"}

class User(UserMixin):
    def __init__(self, id, username, password, role="user", can_fetch=False, api_limit=None):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.can_fetch = can_fetch
        self.api_limit = api_limit
    
    @property
    def is_admin(self):
        return self.role == "admin"
    
    @property 
    def is_guest(self):
        return self.role == "guest"

@login_manager.user_loader
def load_user(user_id):
    """Load user from Supabase database."""
    user_data = get_user_by_id(user_id)
    if user_data:
        return User(
            id=user_data['id'], 
            username=user_data['username'], 
            password=None, 
            role=user_data['role'], 
            can_fetch=user_data['can_fetch'],
            api_limit=user_data.get('api_limit')
        )
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_user_ip():
    # Vercel sets X-Real-IP / X-Forwarded-For itself and overwrites client values.
    ip = request.headers.get('X-Real-IP') or request.headers.get('X-Forwarded-For')
    if ip:
        return ip.split(',')[0].strip()
    return request.remote_addr or "Unknown"

DEFAULT_SETTINGS = {
    "MAX_PASTE": 30,
    "FRAUD_SCORE_LEVEL": 0,
    "MAX_WORKERS": 5,
    "SCAMALYTICS_API_KEY": "",
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/",
    "SCAMALYTICS_USERNAME": "",
    "ANNOUNCEMENT": "",
    "API_CREDITS_USED": "N/A",
    "API_CREDITS_REMAINING": "N/A",
    "CONSECUTIVE_FAILS": 0,
    "SYSTEM_PAUSED": "FALSE",
    "ABC_GENERATION_URL": "",
    "SX_GENERATION_URL": "",   # stored in Supabase settings
    "PASTE_INPUT_DISABLED": "FALSE",
    "FORCE_FETCH_FOR_USERS": "FALSE",
    "SHOW_911_BTN": "TRUE",
    "SHOW_SX_BTN": "FALSE",
    "SHOW_IPROYAL_BTN": "FALSE",
    "911_HOST": "eu.911proxy.net",
    "911_PORT": "2600",
    "911_PASS": "",            # stored in Supabase settings
    "911_USER_PREFIX": "",     # stored in Supabase settings
    "REQUEST_TIMEOUT": 4,
    "MIN_DELAY": 0.1,
    "MAX_DELAY": 0.3,
    "IP_STABLE_CHECKS": 1,
    "IP_STABLE_ATTEMPTS": 2,
    "IP_STABLE_DELAY_MIN": 0.0,
    "IP_STABLE_DELAY_MAX": 0.1,
    "EVENTS_JSON": "[]"
}

_SETTINGS_CACHE = None
_SETTINGS_CACHE_TIME = 0
CACHE_DURATION = 300

def get_app_settings(force_refresh=False):
    global _SETTINGS_CACHE, _SETTINGS_CACHE_TIME
    if not force_refresh and _SETTINGS_CACHE and (time.time() - _SETTINGS_CACHE_TIME < CACHE_DURATION):
        return _SETTINGS_CACHE
    
    try:
        db_settings = get_settings()
    except:
        db_settings = {}
    
    final_settings = DEFAULT_SETTINGS.copy()
    final_settings.update(db_settings)
    
    try:
        final_settings["MAX_PASTE"] = int(final_settings["MAX_PASTE"])
        final_settings["FRAUD_SCORE_LEVEL"] = int(final_settings["FRAUD_SCORE_LEVEL"])
        final_settings["MAX_WORKERS"] = int(final_settings["MAX_WORKERS"])
        final_settings["CONSECUTIVE_FAILS"] = int(final_settings.get("CONSECUTIVE_FAILS", 0))
    except:
        pass
    
    _SETTINGS_CACHE = final_settings
    _SETTINGS_CACHE_TIME = time.time()
    return final_settings

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
]

REQUEST_TIMEOUT = 5
MIN_DELAY = 0.5
MAX_DELAY = 1.5
IP_STABLE_CHECKS = 3
IP_STABLE_ATTEMPTS = 5
IP_STABLE_DELAY_MIN = 0.1
IP_STABLE_DELAY_MAX = 0.3

def parse_api_credentials(settings):
    raw_keys = settings.get("SCAMALYTICS_API_KEY", "")
    raw_users = settings.get("SCAMALYTICS_USERNAME", "")
    raw_urls = settings.get("SCAMALYTICS_API_URL", "")
    
    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]
    users = [u.strip() for u in raw_users.split(',') if u.strip()]
    urls = [u.strip() for u in raw_urls.split(',') if u.strip()]
    
    if not keys:
        return []
    
    if len(users) == 1 and len(keys) > 1:
        users = users * len(keys)
    
    if len(urls) == 1 and len(keys) > 1:
        urls = urls * len(keys)
    
    credentials = []
    for k, u, url in zip(keys, users, urls):
        credentials.append({"key": k, "user": u, "url": url})
    
    return credentials

def apply_performance_settings(settings):
    global REQUEST_TIMEOUT, MIN_DELAY, MAX_DELAY, IP_STABLE_CHECKS, IP_STABLE_ATTEMPTS, IP_STABLE_DELAY_MIN, IP_STABLE_DELAY_MAX
    try:
        REQUEST_TIMEOUT = float(settings.get("REQUEST_TIMEOUT", REQUEST_TIMEOUT))
        MIN_DELAY = float(settings.get("MIN_DELAY", MIN_DELAY))
        MAX_DELAY = float(settings.get("MAX_DELAY", MAX_DELAY))
        IP_STABLE_CHECKS = int(settings.get("IP_STABLE_CHECKS", IP_STABLE_CHECKS))
        IP_STABLE_ATTEMPTS = int(settings.get("IP_STABLE_ATTEMPTS", IP_STABLE_ATTEMPTS))
        IP_STABLE_DELAY_MIN = float(settings.get("IP_STABLE_DELAY_MIN", IP_STABLE_DELAY_MIN))
        IP_STABLE_DELAY_MAX = float(settings.get("IP_STABLE_DELAY_MAX", IP_STABLE_DELAY_MAX))
    except Exception:
        pass

def get_events(settings):
    raw_events = settings.get("EVENTS_JSON", "[]")
    try:
        events = json.loads(raw_events)
        return events if isinstance(events, list) else []
    except Exception:
        return []

def save_events(settings, events):
    update_setting("EVENTS_JSON", json.dumps(events))
    get_app_settings(force_refresh=True)

def build_done_checks(settings, username, limit=50):
    apply_performance_settings(settings)
    fraud_score = int(settings.get("FRAUD_SCORE_LEVEL", 0))
    checks = get_pending_checks(username, limit=200)
    filtered = []
    for check in checks:
        score = check.get("score")
        if score is None:
            continue
        try:
            score_int = int(score)
        except Exception:
            continue
        if score_int > fraud_score:
            continue
        proxy = check.get("proxy")
        ip = check.get("ip")
        if not proxy or not ip:
            continue
        current_ip = verify_ip_stability(proxy)
        if not current_ip or current_ip != ip:
            continue
        filtered.append(check)
        if len(filtered) >= limit:
            break
    return filtered

def normalize_proxy(line):
    """Accepts any common proxy notation and returns host:port:user:pass
    (or host:port for proxies without auth). Returns None if it doesn't fit.
      host:port:user:pass | user:pass@host:port | host:port@user:pass
      http(s)/socks5://user:pass@host:port | host:port
    """
    s = (line or "").strip()
    if not s or " " in s:
        return None
    s = re.sub(r"^[a-zA-Z0-9]+://", "", s).rstrip("/")
    host = port = user = pwd = None
    if "@" in s:
        left, right = s.rsplit("@", 1)
        lp = left.split(":", 1); rp = right.split(":", 1)
        if len(lp) == 2 and len(rp) == 2:
            if rp[1].isdigit():          # user:pass@host:port
                user, pwd, host, port = lp[0], lp[1], rp[0], rp[1]
            elif lp[1].isdigit():        # host:port@user:pass
                host, port, user, pwd = lp[0], lp[1], rp[0], rp[1]
    else:
        parts = s.split(":")
        if len(parts) == 4:
            host, port, user, pwd = parts
        elif len(parts) == 2:
            host, port = parts
    if not host or not port or not port.isdigit() or not (0 < int(port) < 65536):
        return None
    if user is not None and (not user or not pwd):
        return None
    return f"{host}:{port}:{user}:{pwd}" if user else f"{host}:{port}"

def validate_proxy_format(proxy_line):
    try:
        parts = proxy_line.strip().split(":")
        return len(parts) == 4 and all(part for part in parts)
    except:
        return False

def extract_ip_local(proxy_line):
    try:
        return proxy_line.split(':')[0].strip()
    except:
        return None

def make_proxy_session(proxy_line):
    """One session per proxy so repeat IP checks reuse the same connection."""
    host, port, user, pw = proxy_line.strip().split(":")
    session = requests.Session()
    session.proxies = {
        "http": f"http://{user}:{pw}@{host}:{port}",
        "https": f"http://{user}:{pw}@{host}:{port}"
    }
    retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def get_ip_from_proxy(proxy_line, session=None):
    if not validate_proxy_format(proxy_line):
        return None
    
    try:
        if session is None:
            session = make_proxy_session(proxy_line)
        proxy_dict = session.proxies
        
        response = session.get("https://ipv4.icanhazip.com", proxies=proxy_dict, 
                             timeout=max(1, REQUEST_TIMEOUT - 1), headers={"User-Agent": random.choice(USER_AGENTS)})
        response.raise_for_status()
        ip = response.text.strip()
        
        if ip and '.' in ip:
            return ip
        return None
    except:
        return None

def verify_ip_stability(proxy_line, required_stable_checks=None, max_attempts=None):
    """
    Verify that a proxy returns the same IP address multiple times.
    Returns the stable IP if consistent, None if unstable.
    """
    if not validate_proxy_format(proxy_line):
        return None
    
    seen_ips = set()
    stable_ip = None
    session = make_proxy_session(proxy_line)
    
    required_checks = IP_STABLE_CHECKS if required_stable_checks is None else required_stable_checks
    attempts = IP_STABLE_ATTEMPTS if max_attempts is None else max_attempts

    for attempt in range(attempts):
        ip = get_ip_from_proxy(proxy_line, session)
        
        if not ip:
            # If we can't get an IP at all, wait and retry
            time.sleep(random.uniform(IP_STABLE_DELAY_MIN, IP_STABLE_DELAY_MAX))
            continue
        
        seen_ips.add(ip)
        
        # If we have enough checks and all IPs are the same
        if len(seen_ips) == 1 and (attempt + 1) >= required_checks:
            stable_ip = ip
            break
        
        # If we see different IPs, it's unstable
        if len(seen_ips) > 1:
            logger.warning(f"Proxy {proxy_line.split(':')[0]} shows unstable IPs: {seen_ips}")
            return None
        
        # Small delay between checks
        if attempt < attempts - 1:
            time.sleep(random.uniform(IP_STABLE_DELAY_MIN, IP_STABLE_DELAY_MAX))
    
    try: session.close()
    except Exception: pass
    return stable_ip

def get_fraud_score_detailed(ip, proxy_line, credentials_list):
    if not validate_proxy_format(proxy_line) or not ip or not credentials_list:
        return None
    
    for cred in credentials_list:
        try:
            host, port, user, pw = proxy_line.strip().split(":")
            proxy_url = f"http://{user}:{pw}@{host}:{port}"
            proxies = {"http": proxy_url, "https": proxy_url}
            url = f"{cred['url'].rstrip('/')}/{cred['user']}/?key={cred['key']}&ip={ip}"
            
            resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, 
                              proxies=proxies, timeout=REQUEST_TIMEOUT)
            
            if resp.status_code == 200:
                data = resp.json()
                scam = data.get("scamalytics", {})
                
                if scam.get("status") == "error" and scam.get("error") == "out of credits":
                    add_log_entry("WARNING", f"Out of credits: {cred['user']}", ip="System")
                    update_setting("API_CREDITS_REMAINING", "0")
                    update_setting("API_CREDITS_USED", "N/A")
                    continue
                
                if scam.get("status") == "ok" and scam.get("credits"):
                    used = scam.get("credits", {}).get("used", 0)
                    remaining = scam.get("credits", {}).get("remaining", 0)
                    update_setting("API_CREDITS_USED", str(used))
                    update_setting("API_CREDITS_REMAINING", str(remaining))
                
                return data
        except:
            continue
    
    return None

class KnownIPs:
    """Set-like: `ip in KnownIPs(is_ip_used)` does a one-row DB lookup, cached per request."""
    def __init__(self, lookup):
        self.lookup = lookup
        self.cache = {}
    def __contains__(self, ip):
        ip = str(ip).strip()
        if ip not in self.cache:
            self.cache[ip] = bool(self.lookup(ip))
        return self.cache[ip]

def check_until_good(proxies, settings, fraud_level, credentials, strict=True, target_good=2):
    """Checks proxies in parallel and returns as soon as `target_good` unique good ones are found.
    Unstarted checks are cancelled; in-flight ones skip the Scamalytics call."""
    import threading
    stop = threading.Event()
    # IP checks run fully parallel (free). Scamalytics calls (paid) run a few at a time,
    # so once enough good proxies are found the rest never spend a credit.
    stop.scam_gate = threading.Semaphore(max(10, target_good * 5))
    stop.lock = threading.Lock()
    stop.good_ips = set()
    stop.target = target_good
    used_ips, bad_ips = KnownIPs(is_ip_used), KnownIPs(is_ip_bad)
    workers = max(1, min(int(settings.get("MAX_WORKERS", 5)), len(proxies) or 1))
    good, all_results, seen = [], [], set()
    stats = {"used": 0, "bad": 0, "api": 0, "unstable": 0, "error": 0}
    executor = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {executor.submit(single_check_proxy_detailed, p, fraud_level, credentials,
                                   used_ips, bad_ips, is_strict_mode=strict, stop_event=stop): p for p in proxies}
        for fut in as_completed(futures):
            res = fut.result()
            res["input"] = futures[fut]
            st = res["status"]
            if st == "skipped": continue
            if st == "used_cache": stats["used"] += 1
            elif st == "bad_cache": stats["bad"] += 1
            elif st == "unstable_ip": stats["unstable"] += 1
            elif st in ("success", "bad_score"): stats["api"] += 1
            else: stats["error"] += 1
            all_results.append(res)
            if res.get("proxy") and res["ip"] not in seen:
                seen.add(res["ip"])
                good.append(res)
                if len(good) >= target_good:
                    stop.set()
                    break
    finally:
        stop.set()
        executor.shutdown(wait=False, cancel_futures=True)
    return good, all_results, stats

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, used_ip_set, bad_ip_set, is_strict_mode=False, stop_event=None):
    res = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None, 
           "status": "error", "used": False, "cached_bad": False, "unstable": False}
    
    if not validate_proxy_format(proxy_line):
        return res
    
    # First verify IP stability
    # Stability: IP_STABLE_CHECKS from Settings (at least 2), with one spare attempt.
    required = max(2, int(IP_STABLE_CHECKS))
    ip = verify_ip_stability(proxy_line, required_stable_checks=required,
                             max_attempts=max(int(IP_STABLE_ATTEMPTS), required + 1))
    
    if not ip:
        # If we get None from verify_ip_stability, it means the IP was unstable
        res["status"] = "unstable_ip"
        res["unstable"] = True
        return res
    
    res["ip"] = ip
    
    if not ip:
        return res

    if str(ip).strip() in used_ip_set:
        res["used"] = True
        res["status"] = "used_cache"
        return res
    
    if str(ip).strip() in bad_ip_set:
        res["cached_bad"] = True
        res["status"] = "bad_cache"
        return res

    gate = getattr(stop_event, "scam_gate", None)
    if gate: gate.acquire()
    try:
        if stop_event is not None and stop_event.is_set():
            res["status"] = "skipped"   # enough good proxies already, save the Scamalytics credit
            return res
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
        data = get_fraud_score_detailed(ip, proxy_line, credentials_list)
    finally:
        if gate: gate.release()
    
    if data and data.get("scamalytics", {}).get("credits"):
        res["credits"] = data.get("scamalytics", {}).get("credits", {})
    
    try:
        ext_src = data.get("external_datasources", {}) if data else {}
        geo = {}
        mm = ext_src.get("maxmind_geolite2", {})
        if mm and "PREMIUM" not in mm.get("ip_country_code", ""):
            geo = {"country_code": mm.get("ip_country_code"), "state": mm.get("ip_state_name"), "city": mm.get("ip_city"), "postcode": mm.get("ip_postcode")}
        if not geo:
            db = ext_src.get("dbip", {})
            if db and "PREMIUM" not in db.get("ip_country_code", ""):
                geo = {"country_code": db.get("ip_country_code"), "state": db.get("ip_state_name"), "city": db.get("ip_city"), "postcode": db.get("ip_postcode")}
        res["geo"] = geo if geo else {"country_code": "N/A", "state": "N/A", "city": "N/A", "postcode": "N/A"}
    except:
        res["geo"] = {"country_code": "ERR", "state": "ERR", "city": "ERR", "postcode": "ERR"}
    
    if data and data.get("scamalytics"):
        scam = data.get("scamalytics", {})
        score = scam.get("scamalytics_score")
        res["score"] = score
        
        if scam.get("status") != "ok":
            return res
        
        try:
            score_int = int(score)
            res["score"] = score_int
            passed = True
            
            if score_int > fraud_score_level:
                passed = False
            
            if passed and is_strict_mode:
                if scam.get("scamalytics_risk") != "low": passed = False
                if scam.get("is_blacklisted_external") is True: passed = False
                pf = scam.get("scamalytics_proxy", {})
                for f in ["is_datacenter", "is_vpn", "is_apple_icloud_private_relay", "is_amazon_aws", "is_google"]:
                    if pf.get(f) is True: passed = False
                
            if passed:
                res["proxy"] = proxy_line
                res["status"] = "success"
                if stop_event is not None and hasattr(stop_event, "good_ips"):
                    with stop_event.lock:
                        stop_event.good_ips.add(ip)
                        if len(stop_event.good_ips) >= stop_event.target:
                            stop_event.set()   # tell waiting checks to skip Scamalytics right away
            elif score_int > fraud_score_level:
                try:
                    log_bad_proxy(proxy_line, ip, score_int)
                except:
                    pass
                res["status"] = "bad_score"
        except:
            pass
    
    return res

@app.before_request
def before_request_func():
    if get_user_ip() in BLOCKED_IPS: abort(404)
    if request.path.startswith(('/static', '/login', '/logout')) or request.path.endswith(('.ico', '.png')): return

def verify_password(user_data, password):
    """Checks a hashed password. Old plaintext passwords still work once,
    then get upgraded to a hash in Supabase automatically."""
    stored = (user_data or {}).get('password') or ''
    if stored.startswith(('scrypt:', 'pbkdf2:')):
        return check_password_hash(stored, password or '')
    if stored and password and secrets.compare_digest(stored, password):
        update_password(user_data['username'], generate_password_hash(password))
        return True
    return False

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin') if current_user.is_admin else url_for('index'))
    error = None
    if request.method == 'POST':
        import db_util as _db
        if _db.supabase is None:
            logger.critical("Login failed: Supabase not connected (SUPABASE_URL / SUPABASE_KEY missing for this environment).")
            return render_template('login.html', error='Database not connected. Check SUPABASE_URL and SUPABASE_KEY for this deployment.')
        user_data = get_user_by_username(request.form.get('username', ''))
        if user_data and verify_password(user_data, request.form.get('password', '')):
            u_obj = User(
                id=user_data['id'], 
                username=user_data['username'], 
                password=None, 
                role=user_data['role'], 
                can_fetch=user_data['can_fetch'],
                api_limit=user_data.get('api_limit')
            )
            login_user(u_obj, remember=(request.form.get('remember') == 'on'))
            next_p = request.args.get('next')
            if next_p and not current_user.is_admin and '/admin' in next_p: next_p = url_for('index')
            if current_user.is_admin and next_p == url_for('index'): next_p = url_for('admin')
            add_log_entry("INFO", f"User {u_obj.username} logged in.", ip=get_user_ip())
            return redirect(next_p or (url_for('admin') if current_user.is_admin else url_for('index')))
        error = 'Invalid Credentials.'
        add_log_entry("WARNING", f"Failed login: {request.form.get('username')}", ip=get_user_ip())
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    add_log_entry("INFO", f"User {current_user.username} logged out.", ip=get_user_ip())
    logout_user()
    return redirect(url_for('login'))

# --- 911 PROXY FETCH LOGIC ---
def rand_session(n=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

@app.route('/api/fetch-911-proxies')
@login_required
def fetch_911_proxies():
    if not current_user.can_fetch: return jsonify({"status": "error", "message": "Permission denied."}), 403
    settings = get_app_settings()
    TOTAL_PROXIES = int(settings.get("MAX_PASTE", 30))
    if not settings.get('911_PASS') or not settings.get('911_USER_PREFIX'):
        return jsonify({"status": "error", "message": "911 credentials not set in Settings."})
    state = request.args.get('state', 'washington').lower()
    
    proxies = []
    for _ in range(TOTAL_PROXIES):
        proxyUser = f"{settings['911_USER_PREFIX']}_area-US_state-{state}_session-{rand_session()}_life-120"
        proxies.append(f"{settings['911_HOST']}:{settings['911_PORT']}:{proxyUser}:{settings['911_PASS']}")
    
    return jsonify({"status": "success", "proxies": proxies})

# Standalone SX.ORG fetcher
@app.route('/api/fetch-sx-proxies')
@login_required
def fetch_sx_proxies():
    if not current_user.can_fetch: return jsonify({"status": "error", "message": "Permission denied."}), 403
    settings = get_app_settings()
    generation_url = settings.get("SX_GENERATION_URL", "").strip()
    max_paste_limit = int(settings.get("MAX_PASTE", 30))
    if not generation_url: return jsonify({"status": "error", "message": "SX Generation URL not set."})
    try:
        logger.info(f"Fetching SX proxies for {current_user.username}")
        response = requests.get(generation_url, timeout=10)
        if response.status_code == 200:
            content = response.text.strip()
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            if len(lines) > max_paste_limit: lines = lines[:max_paste_limit]
            return jsonify({"status": "success", "proxies": lines})
        return jsonify({"status": "error", "message": f"HTTP Error: {response.status_code}"})
    except Exception as e: return jsonify({"status": "error", "message": f"Server Error: {str(e)}"})

@app.route('/admin/pool', methods=['GET', 'POST'])
@admin_required
def admin_pool():
    settings = get_app_settings()
    if request.method == 'POST':
        if 'bulk_proxies' in request.form:
            raw = [l for l in request.form.get('bulk_proxies', '').splitlines() if l.strip()]
            normalized = []
            seen = set()
            for l in raw:
                p = normalize_proxy(l)
                if p and validate_proxy_format(p) and p not in seen:
                    seen.add(p); normalized.append(p)
            skipped = len(raw) - len(normalized)
            if normalized:
                count = add_bulk_proxies(normalized, "pool")
                msg = f"Added {count} proxies to the pool."
                if skipped: msg += f" Skipped {skipped} line(s) that were invalid, duplicated, or missing user:pass."
                flash(msg, "success")
            else:
                flash("No valid proxies. Use host:port:user:pass (user:pass@host:port also works).", "warning")
        elif 'clear_pool' in request.form:
            if clear_proxy_pool('all'):
                flash("Pool cleared.", "success")
            else:
                flash("Error clearing pool.", "danger")
        return redirect(url_for('admin_pool'))
    
    counts = get_pool_stats()
    preview = get_pool_preview(None)
    return render_template('admin_pool.html', counts=counts, settings=settings, preview=preview)

@app.route('/api/fetch-pool-proxies')
@login_required
def fetch_pool_proxies():
    if not current_user.can_fetch: return jsonify({"status": "error", "message": "Permission denied."}), 403
    settings = get_app_settings()
    limit = int(settings.get("MAX_PASTE", 30))
    proxies = get_random_proxies_from_pool(limit)
    if not proxies: return jsonify({"status": "error", "message": "Pool is empty!"})
    return jsonify({"status": "success", "proxies": proxies})

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    settings = get_app_settings()
    apply_performance_settings(settings)
    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    api_credentials = parse_api_credentials(settings)
    system_paused = str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    admin_bypass = False
    api_limit = None
    api_usage = None
    events = get_events(settings)
    today_str = datetime.date.today().isoformat()
    events_today = []
    if not current_user.is_guest:
        events_today = [e for e in events if e.get("date") == today_str]
    if current_user.is_authenticated and not current_user.is_admin and current_user.api_limit:
        api_limit = int(current_user.api_limit)
        api_usage = get_daily_api_usage_for_user(current_user.username)
    
    if current_user.is_guest:
        daily_usage = get_daily_api_usage_for_user(current_user.username)
        if daily_usage >= 150:
            return render_template("index.html", results=None, message="No good proxies found in this batch.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, api_limit=api_limit, api_usage=api_usage, events_today=events_today)
    if current_user.is_authenticated and not current_user.is_admin and current_user.api_limit:
        if api_usage >= api_limit:
            return render_template("index.html", results=None, message="API call limit reached for today. Contact an admin to increase your limit.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, api_limit=api_limit, api_usage=api_usage, events_today=events_today)
    
    force_fetch_for_users = str(settings.get("FORCE_FETCH_FOR_USERS", "FALSE")).upper() == "TRUE"
    paste_disabled_for_user = (current_user.role == "user" and force_fetch_for_users)
    
    if system_paused:
        if current_user.is_admin: admin_bypass = True
        else: return render_template("index.html", results=None, message="⚠️ System Under Maintenance.", max_paste=MAX_PASTE, settings=settings, system_paused=True, announcement=settings.get("ANNOUNCEMENT"), api_limit=api_limit, api_usage=api_usage, events_today=events_today)
    
    if request.method == "POST":
        if system_paused and not admin_bypass:
            return render_template("index.html", results=None, message="System Paused.", max_paste=MAX_PASTE, settings=settings, system_paused=True, api_limit=api_limit, api_usage=api_usage, events_today=events_today)
        
        if current_user.is_guest:
            daily_usage = get_daily_api_usage_for_user(current_user.username)
            if daily_usage >= 150:
                return render_template("index.html", results=[], message="No good proxies found in this batch.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, api_limit=api_limit, api_usage=api_usage, events_today=events_today)
        if current_user.is_authenticated and not current_user.is_admin and current_user.api_limit:
            if api_usage >= api_limit:
                return render_template("index.html", results=[], message="API call limit reached for today. Contact an admin to increase your limit.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, api_limit=api_limit, api_usage=api_usage, events_today=events_today)
        
        origin = request.form.get('proxy_origin', 'paste')
        if paste_disabled_for_user and origin != 'fetch' and 'proxytext' in request.form:
             return render_template("index.html", results=[], message="Submission rejected: Manual pasting is disabled. Please use the fetch buttons.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, paste_disabled_for_user=paste_disabled_for_user, api_limit=api_limit, api_usage=api_usage, events_today=events_today)
        
        proxies_input = request.form.get("proxytext", "").strip().splitlines()[:MAX_PASTE] if 'proxytext' in request.form else []
        if not proxies_input:
            return render_template("index.html", results=[], message="No proxies submitted.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), paste_disabled_for_user=paste_disabled_for_user, api_limit=api_limit, api_usage=api_usage, events_today=events_today)
        
        proxies_raw = [p.strip() for p in proxies_input if validate_proxy_format(p.strip())]
        
        good_proxy_results = []
        stats = {"used": 0, "bad": 0, "api": 0, "unstable": 0}
        target_good = 2
        
        if current_user.is_guest:
            daily_usage = get_daily_api_usage_for_user(current_user.username)
            remaining_calls = max(0, 150 - daily_usage)
            if remaining_calls < len(proxies_raw): proxies_raw = proxies_raw[:remaining_calls]
        if current_user.is_authenticated and not current_user.is_admin and api_limit:
            remaining_calls = max(0, api_limit - api_usage)
            if remaining_calls < len(proxies_raw): proxies_raw = proxies_raw[:remaining_calls]
        
        good_proxy_results, _all, stats = check_until_good(
            proxies_raw, settings, FRAUD_SCORE_LEVEL, api_credentials, strict=True, target_good=target_good)

        unique_results = []
        seen = set()
        for r in good_proxy_results:
            if r['ip'] not in seen:
                seen.add(r['ip'])
                unique_results.append(r)
        
        results = sorted(unique_results, key=lambda x: x.get('used', False))
        good_final = len(results)
        
        fails = settings.get("CONSECUTIVE_FAILS", 0)
        if good_final > 0 and fails > 0:
            update_setting("CONSECUTIVE_FAILS", "0")
            _SETTINGS_CACHE["CONSECUTIVE_FAILS"] = 0
        elif not good_final and proxies_raw:
            new_fails = fails + len(proxies_raw)
            update_setting("CONSECUTIVE_FAILS", str(new_fails))
            if new_fails > 1000:
                update_setting("SYSTEM_PAUSED", "TRUE")
                add_log_entry("CRITICAL", "Auto-paused.", ip="System")

        try:
            add_recent_checks(current_user.username, results)
        except:
            pass
        
        try: add_api_usage_log(current_user.username, get_user_ip(), len(proxies_input), stats["api"], good_final)
        except: pass
        
        msg_prefix = "⚠️ MAINTENANCE (Admin) - " if admin_bypass else ""
        if current_user.is_guest and good_final == 0: 
            message = "No good proxies found in this batch."
        else: 
            message = f"{msg_prefix}Found {good_final} good proxies. ({stats['used']} from cache, {stats['bad']} skipped bad, {stats['unstable']} unstable, {stats['api']} live checked)"
        
        return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, paste_disabled_for_user=paste_disabled_for_user, api_limit=api_limit, api_usage=api_usage, events_today=events_today)

    msg_prefix = "⚠️ MAINTENANCE (Admin)" if admin_bypass else ""
    return render_template("index.html", results=None, message=msg_prefix, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, paste_disabled_for_user=paste_disabled_for_user, api_limit=api_limit, api_usage=api_usage, events_today=events_today)

@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    data = request.get_json()
    proxy = data.get("proxy")
    ip = data.get("ip")
    if not proxy or not ip or not validate_proxy_format(proxy): return jsonify({"status": "error"}), 400
    if add_used_ip(ip, proxy, username=current_user.username):
        mark_recent_check_copied(current_user.username, proxy, ip)
        add_log_entry("INFO", f"Used: {ip}", ip=get_user_ip())
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

@app.route("/api/pending-checks")
@login_required
def pending_checks():
    settings = get_app_settings()
    checks = build_done_checks(settings, current_user.username, limit=50)
    return jsonify({"status": "success", "checks": checks})

@app.route("/api/mark-check-copied", methods=["POST"])
@login_required
def mark_check_copied():
    data = request.get_json() or {}
    proxy = data.get("proxy")
    ip = data.get("ip")
    if not proxy or not ip:
        return jsonify({"status": "error", "message": "Missing proxy or ip"}), 400
    if mark_recent_check_copied(current_user.username, proxy, ip):
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

@app.route("/done-checks")
@login_required
def done_checks():
    settings = get_app_settings()
    checks = build_done_checks(settings, current_user.username, limit=50)
    return render_template("done_checks.html", checks=checks)

@app.route("/myaccount", methods=["GET", "POST"])
@login_required
def my_account():
    settings = get_app_settings()
    api_limit = None
    api_usage = None
    api_balance = None
    if not current_user.is_admin and current_user.api_limit:
        api_limit = int(current_user.api_limit)
        api_usage = get_daily_api_usage_for_user(current_user.username)
        api_balance = max(0, api_limit - api_usage)

    if request.method == "POST":
        action = request.form.get("action")
        if action == "update_account":
            current_password = request.form.get("current_password")
            new_username = request.form.get("new_username", "").strip()
            new_password = request.form.get("new_password", "").strip()
            if not verify_password(get_user_by_username(current_user.username), current_password):
                flash("Current password is incorrect.", "danger")
            else:
                if new_username and new_username != current_user.username:
                    if update_username(current_user.username, new_username):
                        current_user.username = new_username
                        flash("Username updated.", "success")
                    else:
                        flash("Failed to update username.", "danger")
                if new_password:
                    if update_password(current_user.username, generate_password_hash(new_password)):
                        flash("Password updated.", "success")
                    else:
                        flash("Failed to update password.", "danger")
        elif action == "feedback":
            feedback = request.form.get("feedback", "").strip()
            if feedback:
                add_log_entry("INFO", f"Feedback from {current_user.username}: {feedback}", ip=get_user_ip())
                flash("Feedback sent. Thank you!", "success")
            else:
                flash("Feedback cannot be empty.", "danger")
        return redirect(url_for("my_account"))

    used_proxies = [row for row in get_all_used_ips() if row.get("User") == current_user.username][:200]
    pending_checks = get_pending_checks(current_user.username, limit=200)
    events = [] if current_user.is_guest else get_events(settings)
    has_api_key = bool((get_user_by_username(current_user.username) or {}).get("api_key_hash"))
    return render_template(
        "myaccount.html",
        has_api_key=has_api_key,
        api_limit=api_limit,
        api_usage=api_usage,
        api_balance=api_balance,
        used_proxies=used_proxies,
        pending_checks=pending_checks,
        events=events
    )

@app.route("/admin")
@admin_required
def admin():
    settings = get_app_settings()
    total_api = 0
    try:
        for log in get_all_api_usage_logs(): total_api += int(log.get("api_calls_count", 0))
    except: pass
    stats = {
        "max_paste": settings["MAX_PASTE"],
        "fraud_score_level": settings["FRAUD_SCORE_LEVEL"],
        "max_workers": settings["MAX_WORKERS"],
        "scamalytics_username": settings["SCAMALYTICS_USERNAME"],
        "api_credits_used": settings.get("API_CREDITS_USED", "N/A"),
        "api_credits_remaining": settings.get("API_CREDITS_REMAINING", "N/A"),
        "consecutive_fails": settings.get("CONSECUTIVE_FAILS"),
        "system_paused": settings.get("SYSTEM_PAUSED"),
        "total_api_calls_logged": total_api,
        "abc_generation_url": settings.get("ABC_GENERATION_URL"),
        "sx_generation_url": settings.get("SX_GENERATION_URL"),
        "force_fetch_for_users": settings.get("FORCE_FETCH_FOR_USERS", "FALSE")
    }
    reviews = [log for log in get_all_system_logs()[::-1] if "Feedback from" in log.get("Message", "")]
    page = max(1, int(request.args.get("page", 1)))
    per_page = 20
    recent = []
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=24)
    for row in get_all_used_ips():
        created_at = row.get("Date")
        if not created_at:
            continue
        try:
            timestamp = datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        except Exception:
            continue
        if timestamp >= cutoff:
            recent.append(row)
    start = (page - 1) * per_page
    end = start + per_page
    used_page = recent[start:end]
    has_prev = page > 1
    has_next = end < len(recent)
    return render_template(
        "admin.html",
        stats=stats,
        used_ips=used_page,
        announcement=settings.get("ANNOUNCEMENT"),
        settings=settings,
        page=page,
        has_prev=has_prev,
        has_next=has_next,
        reviews=reviews[:5]
    )

@app.route("/admin/reset-system", methods=["POST"])
@admin_required
def admin_reset_system():
    update_setting("CONSECUTIVE_FAILS", "0")
    update_setting("SYSTEM_PAUSED", "FALSE")
    get_app_settings(force_refresh=True)
    flash("System reset.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/toggle-maintenance", methods=["POST"])
@admin_required
def admin_toggle_maintenance():
    curr = get_app_settings()
    is_paused = str(curr.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_paused else "TRUE"
    if update_setting("SYSTEM_PAUSED", new_state):
        get_app_settings(force_refresh=True)
        flash(f"Maintenance {'Activated' if new_state=='TRUE' else 'Deactivated'}.", "success")
    else: flash("Failed to toggle.", "danger")
    return redirect(url_for("admin"))

@app.route("/admin/toggle-force-fetch", methods=["POST"])
@admin_required
def admin_toggle_force_fetch():
    curr = get_app_settings()
    is_forced = str(curr.get("FORCE_FETCH_FOR_USERS", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_forced else "TRUE"
    if update_setting("FORCE_FETCH_FOR_USERS", new_state):
        get_app_settings(force_refresh=True)
        flash(f"Force fetch for users {'Activated' if new_state=='TRUE' else 'Deactivated'}.", "success")
    else: flash("Failed to toggle.", "danger")
    return redirect(url_for("admin"))

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    """Handles user addition, deletion, and fetch permissions."""
    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username")
        if action == "add":
            role = request.form.get("role") or "user"
            if role not in {"admin", "user", "guest"}:
                flash("Invalid role selected.", "danger")
                return redirect(url_for("admin_users"))
            add_user(
                username, 
                generate_password_hash(request.form.get("password", "")),
                role, 
                "can_fetch" in request.form,
                request.form.get("api_limit") or None
            )
            flash(f"User {username} added.", "success")
        elif action == "delete":
            if username == current_user.username:
                flash("You cannot remove your own account.", "danger")
            else:
                delete_user(username)
                flash(f"User {username} removed.", "danger")
        elif action == "gen_api_key":
            new_key = "vpx_" + secrets.token_urlsafe(32)
            if set_user_api_key_hash(username, hashlib.sha256(new_key.encode()).hexdigest()):
                flash(f"New API key for {username} (shown once, copy it now): {new_key}", "success")
            else:
                flash("Could not create API key.", "danger")
        elif action == "revoke_api_key":
            set_user_api_key_hash(username, None)
            flash(f"API key for {username} revoked.", "warning")
        elif action == "toggle_fetch":
            update_user_fetch_permission(username, request.form.get("can_fetch") == "true")
            return jsonify({"status": "success"})
        elif action == "update_role":
            new_role = request.form.get("role")
            if new_role not in {"admin", "user", "guest"}:
                flash("Invalid role selected.", "danger")
            elif username == current_user.username and new_role != "admin":
                flash("You cannot change your own role away from admin.", "danger")
            else:
                update_user_role(username, new_role)
                flash(f"Updated role for {username}.", "success")
        elif action == "clear_stats":
            clear_user_stats(username)
            flash(f"Cleared stats for {username}.", "success")
        elif action == "update_limit":
            raw_limit = request.form.get("api_limit")
            new_limit = int(raw_limit) if raw_limit else None
            if new_limit is not None and new_limit < 0:
                flash("API limit must be a positive number.", "danger")
            else:
                update_user_api_limit(username, new_limit)
                flash(f"Updated API limit for {username}.", "success")
        return redirect(url_for("admin_users"))
    
    users = get_all_users()
    user_map = {u.get("username"): u for u in users}
    stats = get_user_stats_summary()
    for s in stats:
        try:
            last = datetime.datetime.fromisoformat(s['last_active'].replace('Z', '+00:00'))
            diff = datetime.datetime.now(datetime.timezone.utc) - last
            if diff.days > 7: s['status'] = 'Inactive'
            elif diff.total_seconds() > 86400: s['status'] = 'Offline'
            else: s['status'] = 'Active'
        except: s['status'] = 'Unknown'
        try:
            user_info = user_map.get(s.get("username"))
            api_limit = user_info.get("api_limit") if user_info else None
            role = user_info.get("role") if user_info else None
            if api_limit and role != "admin":
                usage = get_daily_api_usage_for_user(s.get("username"))
                remaining = max(0, int(api_limit) - usage)
                s["api_balance"] = f"{remaining}/{api_limit}"
            else:
                s["api_balance"] = ""
        except Exception:
            s["api_balance"] = ""
        
    return render_template("admin_users.html", stats=stats, users=users)

@app.route("/admin/logs")
@admin_required
def admin_logs():
    return render_template("admin_logs.html", logs=get_all_system_logs()[::-1])

@app.route("/admin/reviews")
@admin_required
def admin_reviews():
    logs = [log for log in get_all_system_logs()[::-1] if "Feedback from" in log.get("Message", "")]
    return render_template("admin_reviews.html", logs=logs)

@app.route("/admin/clear-logs", methods=["POST"])
@admin_required
def admin_clear_logs():
    clear_all_system_logs()
    return redirect(url_for('admin_logs'))

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    curr = get_app_settings()
    if request.method == "POST":
        f = request.form
        action = f.get("action")
        if action == "reset_api_usage":
            if clear_all_api_usage():
                flash("API usage has been reset.", "success")
            else:
                flash("Failed to reset API usage.", "danger")
            return redirect(url_for("admin_settings"))
        if action == "add_event":
            events = get_events(curr)
            title = f.get("event_title", "").strip()
            date = f.get("event_date", "").strip()
            message = f.get("event_message", "").strip()
            if not title or not date:
                flash("Event title and date are required.", "danger")
                return redirect(url_for("admin_settings"))
            events.append({
                "id": str(uuid.uuid4()),
                "title": title,
                "date": date,
                "message": message
            })
            save_events(curr, events)
            flash("Event added.", "success")
            return redirect(url_for("admin_settings"))
        if action == "delete_event":
            events = get_events(curr)
            event_id = f.get("event_id")
            events = [event for event in events if event.get("id") != event_id]
            save_events(curr, events)
            flash("Event removed.", "success")
            return redirect(url_for("admin_settings"))
        upd = {
            "MAX_PASTE": f.get("max_paste"),
            "FRAUD_SCORE_LEVEL": f.get("fraud_score_level"),
            "MAX_WORKERS": f.get("max_workers"),
            "REQUEST_TIMEOUT": f.get("request_timeout"),
            "MIN_DELAY": f.get("min_delay"),
            "MAX_DELAY": f.get("max_delay"),
            "IP_STABLE_CHECKS": f.get("ip_stable_checks"),
            "IP_STABLE_ATTEMPTS": f.get("ip_stable_attempts"),
            "IP_STABLE_DELAY_MIN": f.get("ip_stable_delay_min"),
            "IP_STABLE_DELAY_MAX": f.get("ip_stable_delay_max"),
            "SCAMALYTICS_API_KEY": f.get("scamalytics_api_key", "").strip(),
            "SCAMALYTICS_API_URL": f.get("scamalytics_api_url", "").strip(),
            "SCAMALYTICS_USERNAME": f.get("scamalytics_username", "").strip(),
            "ABC_GENERATION_URL": f.get("abc_generation_url", "").strip(),
            "SX_GENERATION_URL": f.get("sx_generation_url", "").strip(),
            "FORCE_FETCH_FOR_USERS": f.get("force_fetch_for_users", "FALSE"),
            "911_HOST": f.get("911_host"),
            "911_PORT": f.get("911_port"),
            "911_PASS": f.get("911_pass"),
            "911_USER_PREFIX": f.get("911_user_prefix")
        }
        for k, v in upd.items():
            if v is None:
                continue  # field not on the form: keep the value stored in Supabase
            if k in ("911_PASS", "SCAMALYTICS_API_KEY") and str(v).strip() == "":
                continue  # blank secret field = keep current secret
            update_setting(k, str(v))
            time.sleep(0.1)
        
        # Handle button toggles
        for toggle in ["SHOW_911_BTN", "SHOW_SX_BTN", "SHOW_IPROYAL_BTN"]:
            update_setting(toggle, "TRUE" if toggle in f else "FALSE")
            
        flash("Settings updated.", "success")
        curr = get_app_settings(force_refresh=True)
    events = get_events(curr)
    return render_template("admin_settings.html", settings=curr, events=events)

@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    val = request.form.get("announcement_text", "").strip() if "save_announcement" in request.form else ""
    update_setting("ANNOUNCEMENT", val)
    get_app_settings(force_refresh=True)
    return redirect(url_for("admin"))


@app.route("/delete-used-ip/<ip>", methods=["POST"])
@admin_required
def delete_used_ip_route(ip):
    delete_used_ip(ip)
    return redirect(url_for("admin"))

# =====================================================================
# --- PUBLIC JSON API (v1) --- authenticated with an API key
# Send the key as header:  X-API-Key: vpx_...
# (or  Authorization: Bearer vpx_...)
# =====================================================================
GUEST_DAILY_LIMIT = 150

def get_daily_limit(user):
    """Same limits as the web checker: admins unlimited, per-user api_limit, guests 150."""
    if user.is_admin:
        return None
    limits = []
    if user.api_limit:
        try: limits.append(int(user.api_limit))
        except (TypeError, ValueError): pass
    if user.is_guest:
        limits.append(GUEST_DAILY_LIMIT)
    return min(limits) if limits else None

def api_error(message, status=400, code="bad_request"):
    return jsonify({"status": "error", "code": code, "message": message}), status

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "").strip()
        if not key:
            auth = request.headers.get("Authorization", "")
            if auth.lower().startswith("bearer "):
                key = auth[7:].strip()
        if not key:
            return api_error("Missing API key.", 401, "unauthorized")
        user_data = get_user_by_api_key(key)
        if not user_data:
            return api_error("Invalid API key.", 401, "unauthorized")
        request.api_user = User(
            id=user_data['id'], username=user_data['username'],
            password=None, role=user_data['role'],
            can_fetch=user_data.get('can_fetch', False),
            api_limit=user_data.get('api_limit')
        )
        return f(*args, **kwargs)
    return decorated

def run_proxy_check(proxies_raw, settings, username, daily_limit, target_good=2, strict=True):
    """Same checking flow as the web form, returned as plain dicts."""
    api_credentials = parse_api_credentials(settings)
    fraud_level = settings["FRAUD_SCORE_LEVEL"]

    apply_performance_settings(settings)
    if daily_limit:
        remaining = max(0, daily_limit - get_daily_api_usage_for_user(username))
        proxies_raw = proxies_raw[:remaining]

    good, all_results, stats = check_until_good(
        proxies_raw, settings, fraud_level, api_credentials, strict=strict, target_good=target_good)

    try: add_recent_checks(username, good)   # shows up in Done Checks / My Account
    except Exception: pass
    try: add_api_usage_log(username, get_user_ip(), len(proxies_raw), stats["api"], len(good))
    except Exception: pass
    return good, all_results, stats, len(proxies_raw)


# --- API DASHBOARD: each user manages their own key and reads the docs ---
@app.route("/api-dashboard", methods=["GET", "POST"])
@login_required
def api_dashboard():
    new_key = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "generate":
            new_key = "vpx_" + secrets.token_urlsafe(32)
            if not set_user_api_key_hash(current_user.username, hashlib.sha256(new_key.encode()).hexdigest()):
                new_key = None
                flash("Could not create an API key. Try again.", "danger")
            else:
                add_log_entry("INFO", f"API key created by {current_user.username}", ip=get_user_ip())
        elif action == "revoke":
            set_user_api_key_hash(current_user.username, None)
            add_log_entry("INFO", f"API key revoked by {current_user.username}", ip=get_user_ip())
            flash("Your API key was revoked.", "warning")
            return redirect(url_for("api_dashboard"))

    user_row = get_user_by_username(current_user.username) or {}
    settings = get_app_settings()
    resp = make_response(render_template(
        "api_dashboard.html",
        has_key=bool(user_row.get("api_key_hash")),
        new_key=new_key,
        usage_today=get_daily_api_usage_for_user(current_user.username),
        daily_limit=get_daily_limit(current_user),
        max_paste=settings["MAX_PASTE"],
        base_url=request.host_url.rstrip("/"),
    ))
    resp.headers["Cache-Control"] = "no-store"   # never cache a page showing a key
    return resp

@app.route("/api/v1/me", methods=["GET"])
@api_key_required
def api_v1_me():
    u = request.api_user
    used_today = get_daily_api_usage_for_user(u.username)
    return jsonify({
        "status": "success",
        "user": {"username": u.username, "role": u.role},
        "usage_today": used_today,
        "daily_limit": get_daily_limit(u)
    })

@app.route("/api/v1/check", methods=["POST"])
@api_key_required
def api_v1_check():
    """
    Body (JSON): {"proxies": ["host:port:user:pass", ...],
                  "target_good": 2,   # optional, stop after this many good (1-20)
                  "strict": true,     # optional, admin only may set false
                  "verbose": false}   # optional, include every result
    """
    u = request.api_user
    settings = get_app_settings()
    if str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE" and not u.is_admin:
        return api_error("System under maintenance.", 503, "paused")

    data = request.get_json(silent=True) or {}
    proxies = data.get("proxies")
    if isinstance(proxies, str):
        proxies = proxies.splitlines()
    if not isinstance(proxies, list) or not proxies:
        return api_error("'proxies' must be a non-empty list of host:port:user:pass strings.")

    max_paste = settings["MAX_PASTE"]
    cleaned = [str(p).strip() for p in proxies[:max_paste]]
    valid = [p for p in cleaned if validate_proxy_format(p)]
    invalid = [p for p in cleaned if not validate_proxy_format(p)]
    if not valid:
        return api_error("No valid proxies (format host:port:user:pass).")

    daily_limit = get_daily_limit(u)
    if daily_limit and get_daily_api_usage_for_user(u.username) >= daily_limit:
        return api_error("Daily limit reached.", 429, "rate_limited")

    try: target_good = max(1, min(int(data.get("target_good", 2)), 20))
    except (TypeError, ValueError): target_good = 2
    strict = True if not u.is_admin else bool(data.get("strict", True))

    good, all_results, stats, checked = run_proxy_check(valid, settings, u.username, daily_limit, target_good, strict)

    def shape(r):
        return {"proxy": r.get("input"), "ip": r.get("ip"), "status": r.get("status"),
                "score": r.get("score"), "geo": r.get("geo", {})}

    body = {
        "status": "success",
        "good": [shape(r) for r in good],
        "stats": {**stats, "submitted": len(proxies), "checked": checked,
                  "invalid_format": len(invalid), "truncated_to": max_paste},
    }
    if data.get("verbose"):
        body["results"] = [shape(r) for r in all_results]
    return jsonify(body)

@app.route("/api/v1/mark-used", methods=["POST"])
@api_key_required
def api_v1_mark_used():
    """Body (JSON): {"proxy": "host:port:user:pass", "ip": "1.2.3.4"}"""
    data = request.get_json(silent=True) or {}
    proxy, ip = data.get("proxy"), data.get("ip")
    if not proxy or not ip or not validate_proxy_format(proxy):
        return api_error("'proxy' (host:port:user:pass) and 'ip' are required.")
    if add_used_ip(ip, proxy, username=request.api_user.username):
        add_log_entry("INFO", f"Used via API: {ip}", ip=get_user_ip())
        return jsonify({"status": "success"})
    return api_error("Could not save.", 500, "server_error")

@app.errorhandler(404)
def page_not_found(e): return render_template('error.html', error='Page not found.'), 404
@app.errorhandler(500)
def internal_server_error(e): return render_template('error.html', error='Server Error.'), 500

if __name__ == "__main__":
    add_log_entry("INFO", "Server starting up.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
