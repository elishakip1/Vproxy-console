# --- IMPORTS ---
from flask import (
    Flask, request, render_template, redirect, url_for,
    jsonify, send_from_directory, flash, session, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from functools import wraps
import os
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys
import re

# Import from db_util
from db_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip,
    get_all_used_ips,
    log_bad_proxy, get_bad_proxies_list,
    get_all_system_logs, add_log_entry,
    clear_all_system_logs,
    add_api_usage_log, get_all_api_usage_logs,
    get_user_stats_summary,
    add_bulk_proxies, get_random_proxies_from_pool, get_pool_stats, clear_proxy_pool,
    get_daily_api_usage_for_user, update_api_credits, get_pool_preview
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-super-secret-key-in-production")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"

BLOCKED_IPS = {"192.168.1.50", "10.0.0.5"}

class User(UserMixin):
    def __init__(self, id, username, password, role="user", can_fetch=False):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.can_fetch = can_fetch
    
    @property
    def is_admin(self):
        return self.role == "admin"
    
    @property 
    def is_guest(self):
        return self.role == "guest"

# Updated users as requested
users = {
    1: User(id=1, username="EL", password="ADMIN123", role="admin", can_fetch=True),
    2: User(id=2, username="Work2", password="password", role="user", can_fetch=True),
    #4: User(id=3, username="STONES", password="123STONES", role="guest", can_fetch=False),
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_user_ip():
    ip = request.headers.get('X-Forwarded-For')
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
    "SX_GENERATION_URL": "https://api.sx.org/port/list/rkocd4za052HM0HkruFuQvE6x37cMNsG.txt?proxy_template_id=3729&all=true&except_id[]=[]",
    "PYPROXY_RESET_URL": "",
    "PIAPROXY_RESET_URL": "",
    "PASTE_INPUT_DISABLED": "FALSE",
    "FORCE_FETCH_FOR_USERS": "FALSE"
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

def get_ip_from_proxy(proxy_line):
    if not validate_proxy_format(proxy_line):
        return None
    
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_dict = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}"
        }
        
        session = requests.Session()
        retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        response = session.get("https://ipv4.icanhazip.com", proxies=proxy_dict, 
                             timeout=REQUEST_TIMEOUT-1, headers={"User-Agent": random.choice(USER_AGENTS)})
        response.raise_for_status()
        ip = response.text.strip()
        
        if ip and '.' in ip:
            return ip
        return None
    except:
        return None

def verify_ip_stability(proxy_line, required_stable_checks=3, max_attempts=5):
    """
    Verify that a proxy returns the same IP address multiple times.
    Returns the stable IP if consistent, None if unstable.
    """
    if not validate_proxy_format(proxy_line):
        return None
    
    seen_ips = set()
    stable_ip = None
    
    for attempt in range(max_attempts):
        ip = get_ip_from_proxy(proxy_line)
        
        if not ip:
            # If we can't get an IP at all, wait and retry
            time.sleep(random.uniform(0.1, 0.3))
            continue
        
        seen_ips.add(ip)
        
        # If we have enough checks and all IPs are the same
        if len(seen_ips) == 1 and (attempt + 1) >= required_stable_checks:
            stable_ip = ip
            break
        
        # If we see different IPs, it's unstable
        if len(seen_ips) > 1:
            logger.warning(f"Proxy {proxy_line.split(':')[0]} shows unstable IPs: {seen_ips}")
            return None
        
        # Small delay between checks
        if attempt < max_attempts - 1:
            time.sleep(random.uniform(0.1, 0.3))
    
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

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, used_ip_set, bad_ip_set, is_strict_mode=False):
    res = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None, 
           "status": "error", "used": False, "cached_bad": False, "unstable": False}
    
    if not validate_proxy_format(proxy_line):
        return res
    
    # First verify IP stability
    ip = verify_ip_stability(proxy_line, required_stable_checks=3, max_attempts=5)
    
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

    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)
    
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin') if current_user.is_admin else url_for('index'))
    error = None
    if request.method == 'POST':
        user = next((u for u in users.values() if u.username == request.form.get('username')), None)
        if user and user.password == request.form.get('password'):
            login_user(user, remember=(request.form.get('remember') == 'on'))
            next_p = request.args.get('next')
            if next_p and not current_user.is_admin and '/admin' in next_p: next_p = url_for('index')
            if current_user.is_admin and next_p == url_for('index'): next_p = url_for('admin')
            add_log_entry("INFO", f"User {user.username} logged in.", ip=get_user_ip())
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

@app.route('/api/fetch-abc-proxies')
@login_required
def fetch_abc_proxies():
    if not current_user.can_fetch: return jsonify({"status": "error", "message": "Permission denied."}), 403
    settings = get_app_settings()
    generation_url = settings.get("ABC_GENERATION_URL", "").strip()
    max_paste_limit = int(settings.get("MAX_PASTE", 30))
    selected_state = request.args.get('state', '').lower()

    if not generation_url: return jsonify({"status": "error", "message": "ABC Generation URL not set."})
    try:
        parsed_url = urlparse(generation_url)
        query_params = parse_qs(parsed_url.query)
        
        # Logic to dynamically replace the state in the username parameter
        if selected_state:
            username_val = query_params.get('username', [''])[0]
            if 'st-' in username_val:
                new_username = re.sub(r'st-[a-zA-Z0-9]+', f'st-{selected_state}', username_val)
            else:
                new_username = username_val + f"-st-{selected_state}"
            query_params['username'] = [new_username]

        query_params['num'] = [str(max_paste_limit)]
        new_query_string = urlencode(query_params, doseq=True)
        final_url = urlunparse(parsed_url._replace(query=new_query_string))
        
        logger.info(f"Fetching proxies for {current_user.username}: {final_url}")
        response = requests.get(final_url, timeout=10)
        if response.status_code == 200:
            content = response.text.strip()
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            if len(lines) > max_paste_limit: lines = lines[:max_paste_limit]
            return jsonify({"status": "success", "proxies": lines})
        return jsonify({"status": "error", "message": f"HTTP Error: {response.status_code}"})
    except Exception as e: return jsonify({"status": "error", "message": f"Server Error: {str(e)}"})

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
            provider = request.form.get('provider', 'manual')
            text = request.form.get('bulk_proxies', '')
            lines = [l.strip() for l in text.splitlines() if validate_proxy_format(l)]
            if lines:
                count = add_bulk_proxies(lines, provider)
                flash(f"Added {count} proxies to {provider}.", "success")
            else:
                flash("No valid proxies.", "warning")
        elif 'clear_pool' in request.form:
            target = request.form.get('clear_target', 'all')
            if clear_proxy_pool(target):
                flash(f"Pool cleared ({target}).", "success")
            else:
                flash("Error clearing pool.", "danger")
        return redirect(url_for('admin_pool'))
    
    counts = get_pool_stats()
    preview_py = get_pool_preview('pyproxy')
    preview_pia = get_pool_preview('piaproxy')
    
    return render_template('admin_pool.html', counts=counts, settings=settings, preview_py=preview_py, preview_pia=preview_pia)

@app.route('/api/trigger-reset/<provider>')
@admin_required
def trigger_reset(provider):
    settings = get_app_settings()
    target_url = settings.get("PYPROXY_RESET_URL") if provider == 'pyproxy' else settings.get("PIAPROXY_RESET_URL")
    if not target_url: return jsonify({"status": "error", "message": "Reset URL not configured."})
    try:
        resp = requests.get(target_url, timeout=10)
        return jsonify({"status": "success", "message": f"Signal Sent. Response: {resp.text}"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

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
    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    api_credentials = parse_api_credentials(settings)
    system_paused = str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    admin_bypass = False
    
    if current_user.is_guest:
        daily_usage = get_daily_api_usage_for_user(current_user.username)
        if daily_usage >= 150:
            return render_template("index.html", results=None, message="No good proxies found in this batch.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False)
    
    force_fetch_for_users = str(settings.get("FORCE_FETCH_FOR_USERS", "FALSE")).upper() == "TRUE"
    paste_disabled_for_user = (current_user.role == "user" and force_fetch_for_users)
    
    if system_paused:
        if current_user.is_admin: admin_bypass = True
        else: return render_template("index.html", results=None, message="⚠️ System Under Maintenance.", max_paste=MAX_PASTE, settings=settings, system_paused=True, announcement=settings.get("ANNOUNCEMENT"))
    
    if request.method == "POST":
        if system_paused and not admin_bypass:
            return render_template("index.html", results=None, message="System Paused.", max_paste=MAX_PASTE, settings=settings, system_paused=True)
        
        if current_user.is_guest:
            daily_usage = get_daily_api_usage_for_user(current_user.username)
            if daily_usage >= 150:
                return render_template("index.html", results=[], message="No good proxies found in this batch.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False)
        
        origin = request.form.get('proxy_origin', 'paste')
        if paste_disabled_for_user and origin != 'fetch' and 'proxytext' in request.form:
             return render_template("index.html", results=[], message="Submission rejected: Manual pasting is disabled. Please use the fetch buttons.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, paste_disabled_for_user=paste_disabled_for_user)
        
        proxies_input = request.form.get("proxytext", "").strip().splitlines()[:MAX_PASTE] if 'proxytext' in request.form else []
        if not proxies_input:
            return render_template("index.html", results=[], message="No proxies submitted.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), paste_disabled_for_user=paste_disabled_for_user)
        
        used_rows = get_all_used_ips()
        used_ip_set = {str(r['IP']).strip() for r in used_rows if r.get('IP')}
        bad_rows = get_bad_proxies_list()
        bad_ip_set = set()
        for r in bad_rows:
            if r.get('ip'): bad_ip_set.add(str(r['ip']).strip())
            elif r.get('proxy'):
                local_ip = extract_ip_local(r['proxy'])
                if local_ip: bad_ip_set.add(local_ip)

        proxies_raw = [p.strip() for p in proxies_input if validate_proxy_format(p.strip())]
        
        good_proxy_results = []
        stats = {"used": 0, "bad": 0, "api": 0, "unstable": 0}
        target_good = 2
        
        if current_user.is_guest:
            daily_usage = get_daily_api_usage_for_user(current_user.username)
            remaining_calls = max(0, 150 - daily_usage)
            if remaining_calls < len(proxies_raw): proxies_raw = proxies_raw[:remaining_calls]
        
        batch_size = settings["MAX_WORKERS"]
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            for i in range(0, len(proxies_raw), batch_size):
                good_count = len([r for r in good_proxy_results if not r['used'] and not r['cached_bad']])
                if good_count >= target_good: break
                batch = proxies_raw[i : i + batch_size]
                futures = {executor.submit(single_check_proxy_detailed, p, FRAUD_SCORE_LEVEL, api_credentials, used_ip_set, bad_ip_set, is_strict_mode=True): p for p in batch}
                for f in as_completed(futures):
                    res = f.result()
                    if res["status"] == "used_cache": stats["used"] += 1
                    elif res["status"] == "bad_cache": stats["bad"] += 1
                    elif res["status"] == "unstable_ip": stats["unstable"] += 1
                    elif res["status"] in ["success", "bad_score"]: stats["api"] += 1
                    if res.get("proxy"): good_proxy_results.append(res)
                good_count = len([r for r in good_proxy_results if not r['used'] and not r['cached_bad']])
                if good_count >= target_good: break

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
        
        try: add_api_usage_log(current_user.username, get_user_ip(), len(proxies_input), stats["api"], good_final)
        except: pass
        
        # FIXED: Always include detailed stats in the message
        msg_prefix = "⚠️ MAINTENANCE (Admin) - " if admin_bypass else ""
        
        if good_final == 0:
            message = f"{msg_prefix}No good proxies found. ({stats['used']} from cache, {stats['bad']} skipped bad, {stats['unstable']} unstable, {stats['api']} live checked)"
        else:
            message = f"{msg_prefix}Found {good_final} good proxies. ({stats['used']} from cache, {stats['bad']} skipped bad, {stats['unstable']} unstable, {stats['api']} live checked)"
        
        return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, paste_disabled_for_user=paste_disabled_for_user)

    msg_prefix = "⚠️ MAINTENANCE (Admin)" if admin_bypass else ""
    return render_template("index.html", results=None, message=msg_prefix, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False, paste_disabled_for_user=paste_disabled_for_user)

@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    data = request.get_json()
    proxy = data.get("proxy")
    ip = data.get("ip")
    if not proxy or not ip or not validate_proxy_format(proxy): return jsonify({"status": "error"}), 400
    if add_used_ip(ip, proxy, username=current_user.username):
        add_log_entry("INFO", f"Used: {ip}", ip=get_user_ip())
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

@app.route("/admin")
@admin_required
def admin():
    settings = get_app_settings()
    total_api = 0
    try:
        for log in get_all_api_usage_logs(): total_api += int(log.get("api_calls_count", 0))
    except: pass
    stones_daily_usage = get_daily_api_usage_for_user("STONES")
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
    return render_template("admin.html", stats=stats, used_ips=get_all_used_ips(), announcement=settings.get("ANNOUNCEMENT"), settings=settings, stones_daily_usage=stones_daily_usage)

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

@app.route("/admin/users")
@admin_required
def admin_users():
    stats = get_user_stats_summary()
    for s in stats:
        try:
            last = datetime.datetime.fromisoformat(s['last_active'].replace('Z', '+00:00'))
            diff = datetime.datetime.now(datetime.timezone.utc) - last
            if diff.days > 7: s['status'] = 'Inactive'
            elif diff.total_seconds() > 86400: s['status'] = 'Offline'
            else: s['status'] = 'Active'
        except: s['status'] = 'Unknown'
    return render_template("admin_users.html", stats=stats)

@app.route("/admin/logs")
@admin_required
def admin_logs():
    return render_template("admin_logs.html", logs=get_all_system_logs()[::-1])

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
        upd = {
            "MAX_PASTE": f.get("max_paste"),
            "FRAUD_SCORE_LEVEL": f.get("fraud_score_level"),
            "MAX_WORKERS": f.get("max_workers"),
            "SCAMALYTICS_API_KEY": f.get("scamalytics_api_key", "").strip(),
            "SCAMALYTICS_API_URL": f.get("scamalytics_api_url", "").strip(),
            "SCAMALYTICS_USERNAME": f.get("scamalytics_username", "").strip(),
            "ABC_GENERATION_URL": f.get("abc_generation_url", "").strip(),
            "SX_GENERATION_URL": f.get("sx_generation_url", "").strip(),
            "PYPROXY_RESET_URL": f.get("pyproxy_reset_url", "").strip(),
            "PIAPROXY_RESET_URL": f.get("piaproxy_reset_url", "").strip(),
            "FORCE_FETCH_FOR_USERS": f.get("force_fetch_for_users", "FALSE")
        }
        for k, v in upd.items():
            update_setting(k, str(v))
            time.sleep(0.1)
        flash("Settings updated.", "success")
        curr = get_app_settings(force_refresh=True)
    return render_template("admin_settings.html", settings=curr)

@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    val = request.form.get("announcement_text", "").strip() if "save_announcement" in request.form else ""
    update_setting("ANNOUNCEMENT", val)
    get_app_settings(force_refresh=True)
    return redirect(url_for("admin"))

@app.route("/delete-used-ip/<ip>")
@admin_required
def delete_used_ip_route(ip):
    delete_used_ip(ip)
    return redirect(url_for("admin"))

@app.errorhandler(404)
def page_not_found(e): return render_template('error.html', error='Page not found.'), 404
@app.errorhandler(500)
def internal_server_error(e): return render_template('error.html', error='Server Error.'), 500

if __name__ == "__main__":
    add_log_entry("INFO", "Server starting up.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
