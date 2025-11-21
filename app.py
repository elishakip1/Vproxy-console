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
from concurrent.futures import ThreadPoolExecutor, as_completed, FIRST_COMPLETED, wait
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys

# --- CRITICAL: IMPORT FROM DB_UTIL ONLY ---
from db_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip,
    get_all_used_ips,
    log_bad_proxy, get_bad_proxies_list,
    get_all_system_logs, add_log_entry,
    clear_all_system_logs,
    add_api_usage_log, get_all_api_usage_logs,
    get_user_stats_summary,
    add_bulk_proxies, get_random_proxies_from_pool, get_pool_counts, clear_proxy_pool
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-super-secret-key-in-production")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"

# --- SILENT BLOCKLIST ---
BLOCKED_IPS = {"192.168.1.50", "10.0.0.5"}

class User(UserMixin):
    def __init__(self, id, username, password, role="user", can_fetch=False):
        self.id = id; self.username = username; self.password = password; self.role = role; self.can_fetch = can_fetch
    @property
    def is_admin(self): return self.role == "admin"

users = {
    1: User(id=1, username="Boss", password="ADMIN123", role="admin", can_fetch=True),
    2: User(id=2, username="Work", password="password", role="user", can_fetch=True),
    3: User(id=3, username="Guest", password="guestpassword", role="user", can_fetch=False),
}

@login_manager.user_loader
def load_user(user_id): return users.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_user_ip():
    ip = request.headers.get('X-Forwarded-For')
    if ip: return ip.split(',')[0].strip()
    return request.remote_addr or "Unknown"

DEFAULT_SETTINGS = { "MAX_PASTE": 30, "FRAUD_SCORE_LEVEL": 0, "MAX_WORKERS": 5, "SCAMALYTICS_API_KEY": "", "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/", "SCAMALYTICS_USERNAME": "", "ANNOUNCEMENT": "", "API_CREDITS_USED": "N/A", "API_CREDITS_REMAINING": "N/A", "STRICT_FRAUD_SCORE_LEVEL": 20, "CONSECUTIVE_FAILS": 0, "SYSTEM_PAUSED": "FALSE", "ABC_GENERATION_URL": "", "PYPROXY_RESET_URL": "", "PIAPROXY_RESET_URL": "" }

_SETTINGS_CACHE = None; _SETTINGS_CACHE_TIME = 0; CACHE_DURATION = 300
def get_app_settings(force_refresh=False):
    global _SETTINGS_CACHE, _SETTINGS_CACHE_TIME
    if not force_refresh and _SETTINGS_CACHE and (time.time() - _SETTINGS_CACHE_TIME < CACHE_DURATION): return _SETTINGS_CACHE
    try: db_settings = get_settings()
    except: db_settings = {}
    final_settings = DEFAULT_SETTINGS.copy(); final_settings.update(db_settings)
    try:
        final_settings["MAX_PASTE"] = int(final_settings["MAX_PASTE"])
        final_settings["FRAUD_SCORE_LEVEL"] = int(final_settings["FRAUD_SCORE_LEVEL"])
        final_settings["STRICT_FRAUD_SCORE_LEVEL"] = int(final_settings["STRICT_FRAUD_SCORE_LEVEL"])
        final_settings["MAX_WORKERS"] = int(final_settings["MAX_WORKERS"])
        final_settings["CONSECUTIVE_FAILS"] = int(final_settings.get("CONSECUTIVE_FAILS", 0))
    except: pass
    _SETTINGS_CACHE = final_settings; _SETTINGS_CACHE_TIME = time.time(); return final_settings

USER_AGENTS = [ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15" ]
REQUEST_TIMEOUT = 5; MIN_DELAY = 0.5; MAX_DELAY = 1.5

def parse_api_credentials(settings):
    raw_keys = settings.get("SCAMALYTICS_API_KEY", ""); raw_users = settings.get("SCAMALYTICS_USERNAME", ""); raw_urls = settings.get("SCAMALYTICS_API_URL", "")
    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]; users = [u.strip() for u in raw_users.split(',') if u.strip()]; urls = [u.strip() for u in raw_urls.split(',') if u.strip()]
    if not keys: return []
    if len(users) == 1 and len(keys) > 1: users = users * len(keys)
    if len(urls) == 1 and len(keys) > 1: urls = urls * len(keys)
    credentials = []
    for k, u, url in zip(keys, users, urls): credentials.append({"key": k, "user": u, "url": url})
    return credentials

def validate_proxy_format(proxy_line):
    try:
        parts = proxy_line.strip().split(":"); return len(parts) == 4 and all(part for part in parts)
    except: return False

def extract_ip_local(proxy_line):
    try: return proxy_line.split(':')[0].strip()
    except: return None

def get_ip_from_proxy(proxy_line):
    if not validate_proxy_format(proxy_line): return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_dict = { "http": f"http://{user}:{pw}@{host}:{port}", "https": f"http://{user}:{pw}@{host}:{port}" }
        session = requests.Session(); retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504]); session.mount('http://', HTTPAdapter(max_retries=retries)); session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get("https://ipv4.icanhazip.com", proxies=proxy_dict, timeout=REQUEST_TIMEOUT-1, headers={"User-Agent": random.choice(USER_AGENTS)})
        response.raise_for_status(); ip = response.text.strip()
        if ip and '.' in ip: return ip
        return None
    except: return None

def get_fraud_score_detailed(ip, proxy_line, credentials_list):
    if not validate_proxy_format(proxy_line) or not ip or not credentials_list: return None
    for cred in credentials_list:
        try:
            host, port, user, pw = proxy_line.strip().split(":")
            proxy_url = f"http://{user}:{pw}@{host}:{port}"
            proxies = { "http": proxy_url, "https": proxy_url }
            url = f"{cred['url'].rstrip('/')}/{cred['user']}/?key={cred['key']}&ip={ip}"
            resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, proxies=proxies, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json(); scam = data.get("scamalytics", {})
                if scam.get("status") == "error" and scam.get("error") == "out of credits": add_log_entry("WARNING", f"Out of credits: {cred['user']}", ip="System"); continue
                return data
        except: continue
    return None

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, is_strict_mode=False):
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    res = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None, "status": "error"}
    if not validate_proxy_format(proxy_line): return res
    ip = get_ip_from_proxy(proxy_line); res["ip"] = ip
    if not ip: return res
    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)
    if data and data.get("credits"): res["credits"] = data.get("credits")
    try:
        ext_src = data.get("external_datasources", {}) if data else {}; geo = {}
        mm = ext_src.get("maxmind_geolite2", {})
        if mm and "PREMIUM" not in mm.get("ip_country_code", ""): geo = {"country_code": mm.get("ip_country_code"), "state": mm.get("ip_state_name"), "city": mm.get("ip_city"), "postcode": mm.get("ip_postcode")}
        if not geo:
            db = ext_src.get("dbip", {})
            if db and "PREMIUM" not in db.get("ip_country_code", ""): geo = {"country_code": db.get("ip_country_code"), "state": db.get("ip_state_name"), "city": db.get("ip_city"), "postcode": db.get("ip_postcode")}
        res["geo"] = geo if geo else {"country_code": "N/A", "state": "N/A", "city": "N/A", "postcode": "N/A"}
    except: res["geo"] = {"country_code": "ERR", "state": "ERR", "city": "ERR", "postcode": "ERR"}
    
    if data and data.get("scamalytics"):
        scam = data.get("scamalytics", {}); score = scam.get("scamalytics_score"); res["score"] = score
        if scam.get("status") != "ok": return res
        try:
            score_int = int(score); res["score"] = score_int; passed = True
            if score_int > fraud_score_level: passed = False
            if passed and is_strict_mode:
                if scam.get("scamalytics_risk") != "low": passed = False
                if scam.get("is_blacklisted_external") is True: passed = False
                pf = scam.get("scamalytics_proxy", {})
                for f in ["is_datacenter", "is_vpn", "is_apple_icloud_private_relay", "is_amazon_aws", "is_google"]:
                    if pf.get(f) is True: passed = False
                ext_data = data.get("external_datasources", {})
                if ext_data.get("ip2proxy", {}).get("proxy_type") == "VPN": passed = False
                if ext_data.get("ip2proxy_lite", {}).get("ip_blacklisted") is True: passed = False
                firehol = ext_data.get("firehol", {})
                if firehol.get("ip_blacklisted_30") is True: passed = False
                if firehol.get("ip_blacklisted_1day") is True: passed = False
                if firehol.get("is_proxy") is True: passed = False
                ipsum = ext_data.get("ipsum", {})
                if ipsum.get("ip_blacklisted") is True: passed = False
                if ipsum.get("num_blacklists", 0) != 0: passed = False
                if ext_data.get("spamhaus_drop", {}).get("ip_blacklisted") is True: passed = False
                x4b = ext_data.get("x4bnet", {})
                for f in ["is_vpn", "is_datacenter", "is_tor", "is_blacklisted_spambot", "is_bot_operamini", "is_bot_semrush"]:
                    if x4b.get(f) is True: passed = False
                goog = ext_data.get("google", {})
                for f in ["is_google_general", "is_googlebot", "is_special_crawler", "is_user_triggered_fetcher"]:
                    if goog.get(f) is True: passed = False
            
            if passed: 
                res["proxy"] = proxy_line
                res["status"] = "success"
            elif score_int > fraud_score_level:
                try: log_bad_proxy(proxy_line, ip, score_int)
                except: pass
                res["status"] = "bad_score"
        except: pass
    return res

@app.before_request
def before_request_func():
    if get_user_ip() in BLOCKED_IPS: abort(404)
    if request.path.startswith(('/static', '/login', '/logout')) or request.path.endswith(('.ico', '.png')): return

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('admin') if current_user.is_admin else url_for('index'))
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
    if not generation_url: return jsonify({"status": "error", "message": "ABC Generation URL not set."})
    try:
        parsed_url = urlparse(generation_url)
        query_params = parse_qs(parsed_url.query)
        query_params['num'] = [str(max_paste_limit)]
        new_query_string = urlencode(query_params, doseq=True)
        final_url = urlunparse(parsed_url._replace(query=new_query_string))
        logger.info(f"Fetching proxies for {current_user.username}: {final_url}")
        response = requests.get(final_url, timeout=10)
        if response.status_code == 200:
            content = response.text.strip()
            if not content or "{" in content:
                 try:
                     json_data = response.json()
                     if json_data.get("code") != 0: return jsonify({"status": "error", "message": f"API Error: {json_data}"})
                 except: pass
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
            else: flash("No valid proxies.", "warning")
        elif 'clear_pool' in request.form:
            target = request.form.get('clear_target', 'all')
            if clear_proxy_pool(target): flash(f"Pool cleared ({target}).", "success")
            else: flash("Failed to clear.", "danger")
        elif 'save_urls' in request.form:
            update_setting("PYPROXY_RESET_URL", request.form.get("pyproxy_url", "").strip())
            update_setting("PIAPROXY_RESET_URL", request.form.get("piaproxy_url", "").strip())
            flash("URLs updated.", "success"); get_app_settings(force_refresh=True)
        return redirect(url_for('admin_pool'))
    
    counts = get_pool_counts()
    return render_template('admin_pool.html', counts=counts, settings=settings)

@app.route('/api/trigger-reset/<provider>')
@admin_required
def trigger_reset(provider):
    settings = get_app_settings()
    target_url = ""
    if provider == 'pyproxy': target_url = settings.get("PYPROXY_RESET_URL")
    elif provider == 'piaproxy': target_url = settings.get("PIAPROXY_RESET_URL")
    if not target_url: return jsonify({"status": "error", "message": "Reset URL not configured."})
    try:
        resp = requests.get(target_url, timeout=10)
        return jsonify({"status": "success", "message": f"Signal Sent. Response: {resp.text}"})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route('/api/fetch-pool-proxies/<provider>')
@login_required
def fetch_pool_proxies(provider):
    if not current_user.can_fetch: return jsonify({"status": "error", "message": "Permission denied."}), 403
    settings = get_app_settings()
    limit = int(settings.get("MAX_PASTE", 30))
    proxies = get_random_proxies_from_pool(limit, provider)
    if not proxies: return jsonify({"status": "error", "message": f"No {provider} proxies found in pool!"})
    return jsonify({"status": "success", "proxies": proxies})

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    settings = get_app_settings()
    MAX_PASTE = settings["MAX_PASTE"]; FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]; api_credentials = parse_api_credentials(settings)
    system_paused = str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    admin_bypass = False
    if system_paused:
        if current_user.is_admin: admin_bypass = True
        else: return render_template("index.html", results=None, message="⚠️ System Under Maintenance.", max_paste=MAX_PASTE, settings=settings, system_paused=True, announcement=settings.get("ANNOUNCEMENT"))
    
    if request.method == "POST":
        if system_paused and not admin_bypass: return render_template("index.html", results=None, message="System Paused.", max_paste=MAX_PASTE, settings=settings, system_paused=True)
        proxies_input = []
        if 'proxytext' in request.form: proxies_input = request.form.get("proxytext", "").strip().splitlines()[:MAX_PASTE]
        if not proxies_input: return render_template("index.html", results=[], message="No proxies submitted.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"))
        
        # --- IP-BASED CACHE LOGIC ---
        used_rows = get_all_used_ips()
        used_ip_set = {r['IP'] for r in used_rows if r.get('IP')}
        
        bad_rows = get_bad_proxies_list()
        bad_ip_set = set()
        for r in bad_rows:
            if r.get('ip'): 
                bad_ip_set.add(r['ip'])
            elif r.get('proxy'):
                local_ip = extract_ip_local(r['proxy'])
                if local_ip: bad_ip_set.add(local_ip)

        proxies_raw = [p.strip() for p in proxies_input if validate_proxy_format(p.strip())]
        
        good_proxy_results = []
        stats = {"used": 0, "bad": 0, "api": 0}
        target_good = 2
        batch_size = settings["MAX_WORKERS"]
        
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            for i in range(0, len(proxies_raw), batch_size):
                good_count = len([r for r in good_proxy_results if not r.get('used') and not r.get('cached_bad')])
                if good_count >= target_good: break

                batch = proxies_raw[i : i + batch_size]
                futures = {executor.submit(single_check_proxy_detailed, p, FRAUD_SCORE_LEVEL, api_credentials, is_strict_mode=True): p for p in batch}

                for f in as_completed(futures):
                    p_line = futures[f]
                    # MANUAL PRE-CHECK HERE TO COUNT CORRECTLY
                    local_ip = extract_ip_local(p_line)
                    if local_ip and local_ip in used_ip_set:
                        stats["used"] += 1
                        continue
                    if local_ip and local_ip in bad_ip_set:
                        stats["bad"] += 1
                        continue

                    try:
                        res = f.result()
                        if res["status"] == "used_cache": stats["used"] += 1
                        elif res["status"] == "bad_cache": stats["bad"] += 1
                        elif res["status"] in ["success", "bad_score"]: stats["api"] += 1
                        
                        if res.get("proxy"): good_proxy_results.append(res)
                    except: pass
                
                good_count = len([r for r in good_proxy_results if not r.get('used') and not r.get('cached_bad')])
                if good_count >= target_good: break

        unique_results = []; seen = set()
        for r in good_proxy_results:
            if r['ip'] not in seen: seen.add(r['ip']); unique_results.append(r)
        results = sorted(unique_results, key=lambda x: x.get('used', False))
        
        good_final = len(results)
        fails = settings.get("CONSECUTIVE_FAILS", 0)
        if good_final > 0 and fails > 0: update_setting("CONSECUTIVE_FAILS", "0"); _SETTINGS_CACHE["CONSECUTIVE_FAILS"] = 0
        elif not good_final and proxies_raw:
            new_fails = fails + len(proxies_raw); update_setting("CONSECUTIVE_FAILS", str(new_fails))
            if new_fails > 1000: update_setting("SYSTEM_PAUSED", "TRUE"); add_log_entry("CRITICAL", "Auto-paused.", ip="System")
        
        try: add_api_usage_log(current_user.username, get_user_ip(), len(proxies_input), stats["api"], good_final)
        except: pass
        
        msg_prefix = "⚠️ MAINTENANCE (Admin) - " if admin_bypass else ""
        details = []
        if stats["used"] > 0: details.append(f"{stats['used']} from cache")
        if stats["bad"] > 0: details.append(f"{stats['bad']} skipped bad")
        details.append(f"{stats['api']} live checked")
        
        message = f"{msg_prefix}Found {good_final} good proxies. ({', '.join(details)})"
        
        return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False)

    msg_prefix = "⚠️ MAINTENANCE (Admin)" if admin_bypass else ""
    return render_template("index.html", results=None, message=msg_prefix, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False)

@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    data = request.get_json()
    proxy = data.get("proxy"); ip = data.get("ip")
    if not proxy or not ip or not validate_proxy_format(proxy): return jsonify({"status": "error"}), 400
    if add_used_ip(ip, proxy, username=current_user.username):
        add_log_entry("INFO", f"Used: {ip}", ip=get_user_ip())
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

# ... (Include other admin routes: admin, reset-system, toggle-maintenance, users, logs, clear-logs, test, settings, announcement, delete-used-ip, error handlers) ...
# I am truncating here for brevity but assume all other admin routes from the previous robust version are included here.
# Be sure to copy the full file content provided in the logic above or simply ensure all those routes are present.

@app.route("/admin")
@admin_required
def admin():
    settings = get_app_settings()
    total_api = 0
    try:
         for log in get_all_api_usage_logs(): total_api += int(log.get("api_calls_count", 0))
    except: pass
    
    stats = {
        "max_paste": settings["MAX_PASTE"], "fraud_score_level": settings["FRAUD_SCORE_LEVEL"], "strict_fraud_score_level": settings["STRICT_FRAUD_SCORE_LEVEL"],
        "max_workers": settings["MAX_WORKERS"], "scamalytics_username": settings["SCAMALYTICS_USERNAME"],
        "api_credits_remaining": settings.get("API_CREDITS_REMAINING"), "api_credits_used": settings.get("API_CREDITS_USED"),
        "consecutive_fails": settings.get("CONSECUTIVE_FAILS"), "system_paused": settings.get("SYSTEM_PAUSED"),
        "total_api_calls_logged": total_api, "abc_generation_url": settings.get("ABC_GENERATION_URL")
    }
    return render_template("admin.html", stats=stats, used_ips=get_all_used_ips(), announcement=settings.get("ANNOUNCEMENT"))

@app.route("/admin/reset-system", methods=["POST"])
@admin_required
def admin_reset_system():
    update_setting("CONSECUTIVE_FAILS", "0"); update_setting("SYSTEM_PAUSED", "FALSE"); get_app_settings(force_refresh=True); flash("System reset.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/toggle-maintenance", methods=["POST"])
@admin_required
def admin_toggle_maintenance():
    curr = get_app_settings(); is_paused = str(curr.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_paused else "TRUE"
    if update_setting("SYSTEM_PAUSED", new_state):
        get_app_settings(force_refresh=True); flash(f"Maintenance {'Activated' if new_state=='TRUE' else 'Deactivated'}.", "success")
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
def admin_logs(): return render_template("admin_logs.html", logs=get_all_system_logs()[::-1])

@app.route("/admin/clear-logs", methods=["POST"])
@admin_required
def admin_clear_logs(): clear_all_system_logs(); return redirect(url_for("admin_logs"))

@app.route("/admin/test", methods=["GET", "POST"])
@admin_required
def admin_test():
    settings = get_app_settings(); MAX_PASTE = settings["MAX_PASTE"]; results = None; message = None
    if request.method == "POST":
        proxies_input = request.form.get("proxytext", "").strip().splitlines()[:MAX_PASTE]
        proxies_to_check = [p.strip() for p in proxies_input if validate_proxy_format(p.strip())]
        good = []
        with ThreadPoolExecutor(max_workers=min(settings["MAX_WORKERS"], len(proxies_to_check))) as ex:
            futures = {ex.submit(single_check_proxy_detailed, p, settings["STRICT_FRAUD_SCORE_LEVEL"], parse_api_credentials(settings), True): p for p in proxies_to_check}
            for f in as_completed(futures):
                res = f.result()
                if res.get("proxy"): good.append(res)
        results = good; message = f"Strict check found {len(results)} proxies."
    return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    curr = get_app_settings()
    if request.method == "POST":
        f = request.form
        upd = { "MAX_PASTE": f.get("max_paste"), "FRAUD_SCORE_LEVEL": f.get("fraud_score_level"), "STRICT_FRAUD_SCORE_LEVEL": f.get("strict_fraud_score_level"), "MAX_WORKERS": f.get("max_workers"), "SCAMALYTICS_API_KEY": f.get("scamalytics_api_key", "").strip(), "SCAMALYTICS_API_URL": f.get("scamalytics_api_url", "").strip(), "SCAMALYTICS_USERNAME": f.get("scamalytics_username", "").strip(), "ABC_GENERATION_URL": f.get("abc_generation_url", "").strip() }
        for k, v in upd.items(): update_setting(k, str(v)); time.sleep(0.2)
        flash("Settings updated.", "success"); curr = get_app_settings(force_refresh=True)
    return render_template("admin_settings.html", settings=curr)

@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    val = request.form.get("announcement_text", "").strip() if "save_announcement" in request.form else ""
    update_setting("ANNOUNCEMENT", val); get_app_settings(force_refresh=True)
    return redirect(url_for("admin"))

@app.route("/delete-used-ip/<ip>")
@admin_required
def delete_used_ip_route(ip): delete_used_ip(ip); return redirect(url_for("admin"))

@app.errorhandler(404)
def page_not_found(e): return render_template('error.html', error='Page not found.'), 404
@app.errorhandler(500)
def internal_server_error(e): return render_template('error.html', error='Server Error.'), 500

if __name__ == "__main__":
    add_log_entry("INFO", "Server starting up.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
