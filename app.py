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
    get_daily_api_usage_for_user, update_api_credits, get_pool_preview,
    get_all_users, create_user, update_user, delete_user, get_user_by_username, init_default_users,
    get_active_fetch_buttons, get_all_fetch_buttons, add_fetch_button, delete_fetch_button, delete_user_activity_logs
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
    def __init__(self, id, username, password, role="user", can_fetch=False, daily_api_limit=0):
        self.id = id; self.username = username; self.password = password; 
        self.role = role; self.can_fetch = can_fetch; self.daily_api_limit = daily_api_limit
    @property
    def is_admin(self): return self.role == "admin"
    @property 
    def is_guest(self): return self.role == "guest"
    def to_dict(self):
        return {'id': self.id, 'username': self.username, 'password': self.password, 'role': self.role, 'can_fetch': self.can_fetch, 'daily_api_limit': self.daily_api_limit}

def load_users_from_db():
    try:
        users_data = get_all_users()
        users_map = {}
        for user_data in users_data:
            user = User(id=user_data['id'], username=user_data['username'], password=user_data['password'], role=user_data.get('role', 'user'), can_fetch=user_data.get('can_fetch', False), daily_api_limit=user_data.get('daily_api_limit', 0))
            users_map[user.id] = user
        if not users_map:
            init_default_users()
            return load_users_from_db()
        return users_map
    except Exception as e:
        logger.error(f"Error loading users from DB: {e}")
        return {1: User(id=1, username="EL", password="ADMIN123", role="admin", can_fetch=True, daily_api_limit=0)}

users = load_users_from_db()

@login_manager.user_loader
def load_user(user_id):
    try: return users.get(int(user_id))
    except: return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_user_ip():
    ip = request.headers.get('X-Forwarded-For')
    return ip.split(',')[0].strip() if ip else (request.remote_addr or "Unknown")

DEFAULT_SETTINGS = {
    "MAX_PASTE": 30, "FRAUD_SCORE_LEVEL": 0, "MAX_WORKERS": 5, "SCAMALYTICS_API_KEY": "",
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/", "SCAMALYTICS_USERNAME": "",
    "ANNOUNCEMENT": "", "API_CREDITS_USED": "N/A", "API_CREDITS_REMAINING": "N/A",
    "CONSECUTIVE_FAILS": 0, "SYSTEM_PAUSED": "FALSE", "ABC_GENERATION_URL": "",
    "SX_GENERATION_URL": "https://api.sx.org/port/list/rkocd4za052HM0HkruFuQvE6x37cMNsG.txt?proxy_template_id=3729&all=true&except_id[]=[]",
    "PYPROXY_RESET_URL": "", "PIAPROXY_RESET_URL": "", "PASTE_INPUT_DISABLED": "FALSE", "FORCE_FETCH_FOR_USERS": "FALSE"
}

_SETTINGS_CACHE = None; _SETTINGS_CACHE_TIME = 0; CACHE_DURATION = 300

def get_app_settings(force_refresh=False):
    global _SETTINGS_CACHE, _SETTINGS_CACHE_TIME
    if not force_refresh and _SETTINGS_CACHE and (time.time() - _SETTINGS_CACHE_TIME < CACHE_DURATION):
        return _SETTINGS_CACHE
    try: db_settings = get_settings()
    except: db_settings = {}
    final_settings = DEFAULT_SETTINGS.copy(); final_settings.update(db_settings)
    try:
        final_settings["MAX_PASTE"] = int(final_settings["MAX_PASTE"])
        final_settings["FRAUD_SCORE_LEVEL"] = int(final_settings["FRAUD_SCORE_LEVEL"])
        final_settings["MAX_WORKERS"] = int(final_settings["MAX_WORKERS"])
        final_settings["CONSECUTIVE_FAILS"] = int(final_settings.get("CONSECUTIVE_FAILS", 0))
    except: pass
    _SETTINGS_CACHE = final_settings; _SETTINGS_CACHE_TIME = time.time(); return final_settings

USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"]
REQUEST_TIMEOUT = 5; MIN_DELAY = 0.5; MAX_DELAY = 1.5

def parse_api_credentials(settings):
    raw_keys = settings.get("SCAMALYTICS_API_KEY", ""); raw_users = settings.get("SCAMALYTICS_USERNAME", ""); raw_urls = settings.get("SCAMALYTICS_API_URL", "")
    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]; users_list = [u.strip() for u in raw_users.split(',') if u.strip()]; urls = [u.strip() for u in raw_urls.split(',') if u.strip()]
    if not keys: return []
    if len(users_list) == 1 and len(keys) > 1: users_list = users_list * len(keys)
    if len(urls) == 1 and len(keys) > 1: urls = urls * len(keys)
    return [{"key": k, "user": u, "url": url} for k, u, url in zip(keys, users_list, urls)]

def validate_proxy_format(proxy_line):
    try: parts = proxy_line.strip().split(":"); return len(parts) == 4 and all(part for part in parts)
    except: return False

def extract_ip_local(proxy_line):
    try: return proxy_line.split(':')[0].strip()
    except: return None

def get_ip_from_proxy(proxy_line):
    if not validate_proxy_format(proxy_line): return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_dict = {"http": f"http://{user}:{pw}@{host}:{port}", "https": f"http://{user}:{pw}@{host}:{port}"}
        session_req = requests.Session()
        retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
        session_req.mount('http://', HTTPAdapter(max_retries=retries)); session_req.mount('https://', HTTPAdapter(max_retries=retries))
        response = session_req.get("https://ipv4.icanhazip.com", proxies=proxy_dict, timeout=REQUEST_TIMEOUT-1, headers={"User-Agent": random.choice(USER_AGENTS)})
        response.raise_for_status(); ip = response.text.strip()
        return ip if (ip and '.' in ip) else None
    except: return None

def verify_ip_stability(proxy_line, required_stable_checks=3, max_attempts=5):
    if not validate_proxy_format(proxy_line): return None
    seen_ips = set()
    for attempt in range(max_attempts):
        ip = get_ip_from_proxy(proxy_line)
        if not ip: time.sleep(random.uniform(0.1, 0.3)); continue
        seen_ips.add(ip)
        if len(seen_ips) == 1 and (attempt + 1) >= required_stable_checks: return ip
        if len(seen_ips) > 1: return None
        if attempt < max_attempts - 1: time.sleep(random.uniform(0.1, 0.3))
    return None

def get_fraud_score_detailed(ip, proxy_line, credentials_list):
    if not validate_proxy_format(proxy_line) or not ip or not credentials_list: return None
    for cred in credentials_list:
        try:
            host, port, user, pw = proxy_line.strip().split(":")
            proxy_url = f"http://{user}:{pw}@{host}:{port}"
            proxies = {"http": proxy_url, "https": proxy_url}
            url = f"{cred['url'].rstrip('/')}/{cred['user']}/?key={cred['key']}&ip={ip}"
            resp = requests.get(url, headers={"User-Agent": random.choice(USER_AGENTS)}, proxies=proxies, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json(); scam = data.get("scamalytics", {})
                if scam.get("status") == "error" and scam.get("error") == "out of credits":
                    add_log_entry("WARNING", f"Out of credits: {cred['user']}", ip="System")
                    update_setting("API_CREDITS_REMAINING", "0"); continue
                if scam.get("status") == "ok" and scam.get("credits"):
                    update_setting("API_CREDITS_USED", str(scam.get("credits", {}).get("used", 0)))
                    update_setting("API_CREDITS_REMAINING", str(scam.get("credits", {}).get("remaining", 0)))
                return data
        except: continue
    return None

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, used_ip_set, bad_ip_set, is_strict_mode=False):
    res = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None, "status": "error", "used": False, "cached_bad": False, "unstable": False}
    if not validate_proxy_format(proxy_line): return res
    ip = verify_ip_stability(proxy_line, required_stable_checks=3, max_attempts=5)
    if not ip: res["status"] = "unstable_ip"; res["unstable"] = True; return res
    res["ip"] = ip
    if str(ip).strip() in used_ip_set: res["used"] = True; res["status"] = "used_cache"; return res
    if str(ip).strip() in bad_ip_set: res["cached_bad"] = True; res["status"] = "bad_cache"; return res
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)
    if data and data.get("scamalytics", {}).get("credits"): res["credits"] = data.get("scamalytics", {}).get("credits", {})
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
            if passed: res["proxy"] = proxy_line; res["status"] = "success"
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
    settings = get_app_settings(); gen_url = settings.get("ABC_GENERATION_URL", "").strip(); limit = int(settings.get("MAX_PASTE", 30)); state = request.args.get('state', '').lower()
    if not gen_url: return jsonify({"status": "error", "message": "ABC Generation URL not set."})
    try:
        parsed = urlparse(gen_url); params = parse_qs(parsed.query)
        if state:
            user_val = params.get('username', [''])[0]
            new_user = re.sub(r'st-[a-zA-Z0-9]+', f'st-{state}', user_val) if 'st-' in user_val else user_val + f"-st-{state}"
            params['username'] = [new_user]
        params['num'] = [str(limit)]; final_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        resp = requests.get(final_url, timeout=10)
        if resp.status_code == 200:
            lines = [l.strip() for l in resp.text.strip().splitlines() if l.strip()][:limit]
            return jsonify({"status": "success", "proxies": lines})
        return jsonify({"status": "error", "message": f"HTTP Error: {resp.status_code}"})
    except Exception as e: return jsonify({"status": "error", "message": f"Server Error: {str(e)}"})

@app.route('/api/fetch-sx-proxies')
@login_required
def fetch_sx_proxies():
    if not current_user.can_fetch: return jsonify({"status": "error", "message": "Permission denied."}), 403
    gen_url = get_app_settings().get("SX_GENERATION_URL", "").strip(); limit = int(get_app_settings().get("MAX_PASTE", 30))
    if not gen_url: return jsonify({"status": "error", "message": "SX Generation URL not set."})
    try:
        resp = requests.get(gen_url, timeout=10)
        if resp.status_code == 200:
            lines = [l.strip() for l in resp.text.strip().splitlines() if l.strip()][:limit]
            return jsonify({"status": "success", "proxies": lines})
        return jsonify({"status": "error", "message": f"HTTP Error: {resp.status_code}"})
    except Exception as e: return jsonify({"status": "error", "message": f"Server Error: {str(e)}"})

@app.route('/api/fetch-pool-provider/<provider>')
@login_required
def fetch_pool_provider(provider):
    if not current_user.can_fetch: return jsonify({"status": "error", "message": "Permission denied"}), 403
    limit = int(get_app_settings().get("MAX_PASTE", 30))
    proxies = get_random_proxies_from_pool(limit)
    return jsonify({"status": "success", "proxies": proxies})

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    settings = get_app_settings(); MAX_PASTE = settings["MAX_PASTE"]; FRAUD_LEVEL = settings["FRAUD_SCORE_LEVEL"]; api_credentials = parse_api_credentials(settings)
    system_paused = str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    dynamic_buttons = get_active_fetch_buttons() if current_user.can_fetch else []
    admin_bypass = current_user.is_admin and system_paused

    if current_user.is_guest and current_user.daily_api_limit > 0:
        if get_daily_api_usage_for_user(current_user.username) >= current_user.daily_api_limit:
            return render_template("index.html", results=None, message=f"Daily API limit reached ({current_user.daily_api_limit} calls).", max_paste=MAX_PASTE, settings=settings, dynamic_buttons=dynamic_buttons)
    
    paste_disabled = (current_user.role == "user" and str(settings.get("FORCE_FETCH_FOR_USERS", "FALSE")).upper() == "TRUE")

    if system_paused and not current_user.is_admin:
        return render_template("index.html", results=None, message="⚠️ System Under Maintenance.", max_paste=MAX_PASTE, settings=settings, system_paused=True, dynamic_buttons=dynamic_buttons)
    
    if request.method == "POST":
        if system_paused and not current_user.is_admin: return render_template("index.html", results=None, message="System Paused.", max_paste=MAX_PASTE, settings=settings, dynamic_buttons=dynamic_buttons)
        
        origin = request.form.get('proxy_origin', 'paste')
        if paste_disabled and origin != 'fetch' and 'proxytext' in request.form:
             return render_template("index.html", results=[], message="Manual pasting disabled.", max_paste=MAX_PASTE, settings=settings, dynamic_buttons=dynamic_buttons, paste_disabled_for_user=paste_disabled)

        proxies_input = request.form.get("proxytext", "").strip().splitlines()[:MAX_PASTE]
        if not proxies_input: return render_template("index.html", results=[], message="No proxies submitted.", max_paste=MAX_PASTE, settings=settings, dynamic_buttons=dynamic_buttons)
        
        used_ip_set = {str(r['IP']).strip() for r in get_all_used_ips() if r.get('IP')}
        bad_ip_set = set()
        for r in get_bad_proxies_list():
            if r.get('ip'): bad_ip_set.add(str(r['ip']).strip())
            elif r.get('proxy'):
                lip = extract_ip_local(r['proxy'])
                if lip: bad_ip_set.add(lip)

        proxies_raw = [p.strip() for p in proxies_input if validate_proxy_format(p.strip())]
        good_proxy_results = []; stats = {"used": 0, "bad": 0, "api": 0, "unstable": 0}
        
        with ThreadPoolExecutor(max_workers=settings["MAX_WORKERS"]) as executor:
            for i in range(0, len(proxies_raw), settings["MAX_WORKERS"]):
                if len([r for r in good_proxy_results if not r['used'] and not r['cached_bad']]) >= 2: break
                batch = proxies_raw[i : i + settings["MAX_WORKERS"]]
                futures = {executor.submit(single_check_proxy_detailed, p, FRAUD_LEVEL, api_credentials, used_ip_set, bad_ip_set, is_strict_mode=True): p for p in batch}
                for f in as_completed(futures):
                    res = f.result()
                    if res["status"] == "used_cache": stats["used"] += 1
                    elif res["status"] == "bad_cache": stats["bad"] += 1
                    elif res["status"] == "unstable_ip": stats["unstable"] += 1
                    elif res["status"] in ["success", "bad_score"]: stats["api"] += 1
                    if res.get("proxy"): good_proxy_results.append(res)

        unique_results = []; seen = set()
        for r in good_proxy_results:
            if r['ip'] not in seen: seen.add(r['ip']); unique_results.append(r)
        results = sorted(unique_results, key=lambda x: x.get('used', False))
        good_final = len(results)
        
        if good_final > 0: update_setting("CONSECUTIVE_FAILS", "0")
        elif proxies_raw:
            new_fails = settings.get("CONSECUTIVE_FAILS", 0) + len(proxies_raw)
            update_setting("CONSECUTIVE_FAILS", str(new_fails))
            if new_fails > 1000: update_setting("SYSTEM_PAUSED", "TRUE")
        
        add_api_usage_log(current_user.username, get_user_ip(), len(proxies_input), stats["api"], good_final)
        message = f"Found {good_final} good proxies."
        return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, dynamic_buttons=dynamic_buttons, paste_disabled_for_user=paste_disabled)

    return render_template("index.html", results=None, message="⚠️ MAINTENANCE (Admin)" if admin_bypass else "", max_paste=MAX_PASTE, settings=settings, dynamic_buttons=dynamic_buttons, paste_disabled_for_user=paste_disabled)

@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    data = request.get_json()
    proxy, ip = data.get("proxy"), data.get("ip")
    if not proxy or not ip or not validate_proxy_format(proxy): return jsonify({"status": "error"}), 400
    if add_used_ip(ip, proxy, username=current_user.username):
        add_log_entry("INFO", f"Used: {ip}", ip=get_user_ip())
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

@app.route("/admin")
@admin_required
def admin():
    settings = get_app_settings(); total_api = 0
    try:
        logs = get_all_api_usage_logs()
        total_api = sum(int(log.get("api_calls_count", 0)) for log in logs if log)
    except: total_api = "Error"
    stats = {
        "max_paste": settings["MAX_PASTE"], "fraud_score_level": settings["FRAUD_SCORE_LEVEL"], "max_workers": settings["MAX_WORKERS"],
        "scamalytics_username": settings["SCAMALYTICS_USERNAME"], "api_credits_used": settings.get("API_CREDITS_USED", "N/A"),
        "api_credits_remaining": settings.get("API_CREDITS_REMAINING", "N/A"), "consecutive_fails": settings.get("CONSECUTIVE_FAILS"),
        "system_paused": settings.get("SYSTEM_PAUSED"), "total_api_calls_logged": total_api, "abc_generation_url": settings.get("ABC_GENERATION_URL"),
        "sx_generation_url": settings.get("SX_GENERATION_URL"), "force_fetch_for_users": settings.get("FORCE_FETCH_FOR_USERS", "FALSE")
    }
    return render_template("admin.html", stats=stats, used_ips=get_all_used_ips(), announcement=settings.get("ANNOUNCEMENT"), settings=settings)

@app.route("/admin/add-button", methods=["POST"])
@admin_required
def admin_add_button():
    if add_fetch_button(request.form.get("name"), request.form.get("type"), request.form.get("target")):
        flash(f"Button '{request.form.get('name')}' created!", "success")
    return redirect(url_for('admin_settings'))

@app.route("/admin/delete-button/<int:btn_id>")
@admin_required
def admin_del_button(btn_id):
    if delete_fetch_button(btn_id): flash("Button removed.", "success")
    return redirect(url_for('admin_settings'))

@app.route("/admin/users")
@admin_required
def admin_users():
    stats = get_user_stats_summary()
    for s in stats:
        try:
            diff = datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(s['last_active'].replace('Z', '+00:00'))
            s['status'] = 'Active' if diff.total_seconds() < 86400 else 'Offline'
        except: s['status'] = 'Unknown'
    return render_template("admin_users.html", stats=stats)

@app.route("/admin/delete-user-activity/<username>")
@admin_required
def admin_delete_user_activity(username):
    if delete_user_activity_logs(username): flash(f"Activity for {username} cleared.", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/users/manage', methods=['GET'])
@admin_required
def admin_users_manage():
    users_refresh = load_users_from_db(); user_list = []
    for user in users_refresh.values():
        u_dict = user.to_dict(); u_dict['daily_api_usage'] = get_daily_api_usage_for_user(user.username); user_list.append(u_dict)
    return render_template('admin_users_manage.html', users=user_list)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    u, p = request.form.get('username', '').strip(), request.form.get('password', '').strip()
    if create_user(u, p, request.form.get('role', 'user'), request.form.get('can_fetch') == 'on'):
        global users; users = load_users_from_db(); flash(f"User {u} created.", "success")
    return redirect(url_for('admin_users_manage'))

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    if user_id not in users or user_id == 1: flash('Invalid action.', 'danger'); return redirect(url_for('admin_users_manage'))
    role = request.form.get('role'); updates = {'role': role, 'can_fetch': request.form.get('can_fetch') == 'on', 'daily_api_limit': int(request.form.get('daily_api_limit', 0)) if role == 'guest' else 0}
    if request.form.get('password'): updates['password'] = request.form.get('password')
    if update_user(user_id, **updates):
        global users; users = load_users_from_db(); flash('User updated.', 'success')
    return redirect(url_for('admin_users_manage'))

@app.route('/admin/users/delete/<int:user_id>')
@admin_required
def admin_delete_user(user_id):
    if user_id not in users or user_id == 1 or user_id == current_user.id: flash('Cannot delete user.', 'danger'); return redirect(url_for('admin_users_manage'))
    if delete_user(user_id):
        global users; users = load_users_from_db(); flash('User deleted.', 'success')
    return redirect(url_for('admin_users_manage'))

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        f = request.form
        upd = {"MAX_PASTE": f.get("max_paste"), "FRAUD_SCORE_LEVEL": f.get("fraud_score_level"), "MAX_WORKERS": f.get("max_workers"), "SCAMALYTICS_API_KEY": f.get("scamalytics_api_key", "").strip(), "SCAMALYTICS_API_URL": f.get("scamalytics_api_url", "").strip(), "SCAMALYTICS_USERNAME": f.get("scamalytics_username", "").strip(), "ABC_GENERATION_URL": f.get("abc_generation_url", "").strip(), "SX_GENERATION_URL": f.get("sx_generation_url", "").strip(), "PYPROXY_RESET_URL": f.get("pyproxy_reset_url", "").strip(), "PIAPROXY_RESET_URL": f.get("piaproxy_reset_url", "").strip(), "FORCE_FETCH_FOR_USERS": f.get("force_fetch_for_users", "FALSE")}
        for k, v in upd.items(): update_setting(k, str(v))
        flash("Settings updated.", "success")
    return render_template("admin_settings.html", settings=get_app_settings(), buttons=get_all_fetch_buttons())

@app.route("/admin/logs")
@admin_required
def admin_logs(): return render_template("admin_logs.html", logs=get_all_system_logs()[::-1])

@app.route("/admin/pool", methods=["GET", "POST"])
@admin_required
def admin_pool():
    settings = get_app_settings()
    if request.method == 'POST':
        if 'bulk_proxies' in request.form:
            text = request.form.get('bulk_proxies', '')
            lines = [l.strip() for l in text.splitlines() if validate_proxy_format(l)]
            if lines: flash(f"Added {add_bulk_proxies(lines, request.form.get('provider', 'manual'))} proxies.", "success")
        elif 'clear_pool' in request.form:
            if clear_proxy_pool(request.form.get('clear_target', 'all')): flash("Pool cleared.", "success")
        return redirect(url_for('admin_pool'))
    return render_template('admin_pool.html', counts=get_pool_stats(), settings=settings, preview_py=get_pool_preview('pyproxy'), preview_pia=get_pool_preview('piaproxy'))

@app.route("/admin/reset-system", methods=["POST"])
@admin_required
def admin_reset_system():
    update_setting("CONSECUTIVE_FAILS", "0"); update_setting("SYSTEM_PAUSED", "FALSE")
    get_app_settings(force_refresh=True); flash("System reset.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/toggle-maintenance", methods=["POST"])
@admin_required
def admin_toggle_maintenance():
    is_paused = str(get_app_settings().get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_paused else "TRUE"
    if update_setting("SYSTEM_PAUSED", new_state):
        get_app_settings(force_refresh=True); flash(f"Maintenance {'Activated' if new_state=='TRUE' else 'Deactivated'}.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/toggle-force-fetch", methods=["POST"])
@admin_required
def admin_toggle_force_fetch():
    is_forced = str(get_app_settings().get("FORCE_FETCH_FOR_USERS", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_forced else "TRUE"
    if update_setting("FORCE_FETCH_FOR_USERS", new_state):
        get_app_settings(force_refresh=True); flash(f"Force fetch {'Activated' if new_state=='TRUE' else 'Deactivated'}.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    val = request.form.get("announcement_text", "").strip() if "save_announcement" in request.form else ""
    update_setting("ANNOUNCEMENT", val); get_app_settings(force_refresh=True)
    return redirect(url_for("admin"))

@app.route("/delete-used-ip/<ip>")
@admin_required
def delete_used_ip_route(ip):
    delete_used_ip(ip); return redirect(url_for("admin"))

@app.errorhandler(404)
def page_not_found(e): return render_template('error.html', error='Page not found.'), 404
@app.errorhandler(500)
def internal_server_error(e): return render_template('error.html', error='Server Error.'), 500

if __name__ == "__main__":
    init_default_users(); app.run(host="0.0.0.0", port=5000)
else:
    init_default_users()
