from flask import Flask, request, render_template, redirect, url_for, jsonify, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
import os, time, requests, random, logging, sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed, FIRST_COMPLETED, wait
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# --- IMPORT FROM DB_UTIL (SUPABASE) ---
from db_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip, get_all_used_ips,
    log_bad_proxy, get_bad_proxies_list, get_all_system_logs, add_log_entry,
    clear_all_system_logs, add_api_usage_log, get_all_api_usage_logs,
    get_user_stats_summary, add_bulk_proxies, get_random_proxies_from_pool,
    get_pool_counts, clear_proxy_pool
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-super-secret-key")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

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
    return ip.split(',')[0].strip() if ip else (request.remote_addr or "Unknown")

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
        final_settings["MAX_WORKERS"] = int(final_settings["MAX_WORKERS"])
    except: pass
    _SETTINGS_CACHE = final_settings; _SETTINGS_CACHE_TIME = time.time(); return final_settings

USER_AGENTS = [ "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36" ]
REQUEST_TIMEOUT = 5; MIN_DELAY = 0.5; MAX_DELAY = 1.5

def parse_api_credentials(settings):
    keys = [k.strip() for k in settings.get("SCAMALYTICS_API_KEY", "").split(',') if k.strip()]
    users = [u.strip() for u in settings.get("SCAMALYTICS_USERNAME", "").split(',') if u.strip()]
    urls = [u.strip() for u in settings.get("SCAMALYTICS_API_URL", "").split(',') if u.strip()]
    if not keys: return []
    if len(users) == 1: users = users * len(keys)
    if len(urls) == 1: urls = urls * len(keys)
    return [{"key": k, "user": u, "url": url} for k, u, url in zip(keys, users, urls)]

def validate_proxy_format(proxy_line):
    try: return len(proxy_line.strip().split(":")) == 4
    except: return False

def extract_ip_local(proxy_line):
    try: return proxy_line.split(':')[0].strip()
    except: return None

def get_ip_from_proxy(proxy_line):
    if not validate_proxy_format(proxy_line): return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_dict = { "http": f"http://{user}:{pw}@{host}:{port}", "https": f"http://{user}:{pw}@{host}:{port}" }
        session = requests.Session(); retries = Retry(total=1, backoff_factor=0.2); session.mount('http://', HTTPAdapter(max_retries=retries))
        response = session.get("https://ipv4.icanhazip.com", proxies=proxy_dict, timeout=4, headers={"User-Agent": random.choice(USER_AGENTS)})
        return response.text.strip()
    except: return None

def get_fraud_score_detailed(ip, proxy_line, credentials_list):
    if not credentials_list: return None
    for cred in credentials_list:
        try:
            host, port, user, pw = proxy_line.strip().split(":")
            proxies = { "http": f"http://{user}:{pw}@{host}:{port}", "https": f"http://{user}:{pw}@{host}:{port}" }
            url = f"{cred['url'].rstrip('/')}/{cred['user']}/?key={cred['key']}&ip={ip}"
            resp = requests.get(url, proxies=proxies, timeout=5, headers={"User-Agent": random.choice(USER_AGENTS)}) 
            if resp.status_code == 200:
                data = resp.json()
                if data.get("scamalytics", {}).get("error") == "out of credits": continue
                return data
        except: continue
    return None

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, used_ip_set, bad_ip_set, is_strict_mode=False):
    res = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None, "status": "error", "used": False, "cached_bad": False}
    if not validate_proxy_format(proxy_line): return res
    
    # 1. GET IP (Network Call)
    ip = get_ip_from_proxy(proxy_line); res["ip"] = ip
    if not ip: return res

    # 2. MID-CHECK (Cache Check) - SAVES API CREDITS
    if str(ip).strip() in used_ip_set: res["used"] = True; res["status"] = "used_cache"; return res
    if str(ip).strip() in bad_ip_set: res["cached_bad"] = True; res["status"] = "bad_cache"; return res

    # 3. API Call
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)
    if not data: return res
    if data.get("credits"): res["credits"] = data.get("credits")
    
    # Geo
    try: 
        mm = data.get("external_datasources", {}).get("maxmind_geolite2", {})
        if "PREMIUM" not in mm.get("ip_country_code", ""):
             res["geo"] = {"country_code": mm.get("ip_country_code"), "state": mm.get("ip_state_name"), "city": mm.get("ip_city"), "postcode": mm.get("ip_postcode")}
        else: res["geo"] = {"country_code": "N/A", "state": "N/A", "city": "N/A", "postcode": "N/A"}
    except: res["geo"] = {"country_code": "ERR", "state": "ERR", "city": "ERR", "postcode": "ERR"}

    # Score & Filters
    scam = data.get("scamalytics", {})
    score = scam.get("scamalytics_score")
    res["score"] = score
    
    try:
        s_int = int(score)
        passed = s_int <= fraud_score_level
        
        # --- STRICT FILTERS ---
        if passed and is_strict_mode:
            if scam.get("scamalytics_risk") != "low": passed = False
            pf = scam.get("scamalytics_proxy", {})
            if any(pf.get(k) for k in ["is_datacenter", "is_vpn", "is_apple_icloud_private_relay", "is_amazon_aws", "is_google"]): passed = False
            
            ext = data.get("external_datasources", {})
            if ext.get("ip2proxy", {}).get("proxy_type") == "VPN": passed = False
            if ext.get("firehol", {}).get("ip_blacklisted_30") or ext.get("firehol", {}).get("is_proxy"): passed = False
            if ext.get("spamhaus_drop", {}).get("ip_blacklisted"): passed = False
            if ext.get("ipsum", {}).get("num_blacklists", 0) > 0: passed = False
            x4b = ext.get("x4bnet", {})
            if x4b.get("is_vpn") or x4b.get("is_datacenter"): passed = False

        if passed: res["proxy"] = proxy_line; res["status"] = "success"
        elif s_int > fraud_score_level: res["status"] = "bad_score"; log_bad_proxy(proxy_line, ip, s_int)
    except: pass
    
    return res

@app.before_request
def before_request():
    if get_user_ip() in BLOCKED_IPS: abort(404)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = next((u for u in users.values() if u.username == request.form.get('username')), None)
        if user and user.password == request.form.get('password'):
            login_user(user); add_log_entry("INFO", f"User {user.username} logged in", get_user_ip())
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    add_log_entry("INFO", f"User {current_user.username} logged out.", ip=get_user_ip())
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/fetch-abc-proxies')
@login_required
def fetch_abc():
    if not current_user.can_fetch: return jsonify({"status": "error"}), 403
    s = get_app_settings(); url = s.get("ABC_GENERATION_URL", "")
    if not url: return jsonify({"status": "error", "message": "No URL"})
    try:
        p = urlparse(url); q = parse_qs(p.query); q['num'] = [str(s["MAX_PASTE"])]
        final = urlunparse(p._replace(query=urlencode(q, doseq=True)))
        r = requests.get(final, timeout=10)
        lines = [l.strip() for l in r.text.splitlines() if l.strip()][:s["MAX_PASTE"]]
        return jsonify({"status": "success", "proxies": lines})
    except Exception as e: return jsonify({"status": "error", "message": str(e)})

@app.route('/api/fetch-pool-proxies/<provider>')
@login_required
def fetch_pool(provider):
    if not current_user.can_fetch: return jsonify({"status": "error"}), 403
    s = get_app_settings(); limit = int(s["MAX_PASTE"])
    proxies = get_random_proxies_from_pool(limit, provider)
    if not proxies: return jsonify({"status": "error", "message": "Pool empty"})
    return jsonify({"status": "success", "proxies": proxies})

@app.route('/api/trigger-reset/<provider>')
@admin_required
def trigger_reset(provider):
    s = get_app_settings()
    url = s.get("PYPROXY_RESET_URL") if provider == 'pyproxy' else s.get("PIAPROXY_RESET_URL")
    if not url: return jsonify({"status": "error", "message": "No URL"})
    try: requests.get(url, timeout=5); return jsonify({"status": "success", "message": "Reset sent"})
    except: return jsonify({"status": "error", "message": "Failed"})

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    s = get_app_settings()
    if str(s.get("SYSTEM_PAUSED")).upper() == "TRUE" and not current_user.is_admin:
        return render_template("index.html", message="System Paused", settings=s, system_paused=True)

    if request.method == 'POST':
        proxies = request.form.get('proxytext', '').strip().splitlines()[:s["MAX_PASTE"]]
        if not proxies: return render_template("index.html", settings=s)
        
        # CACHE LOAD (IPs)
        used_ip_set = {r['IP'] for r in get_all_used_ips()}
        bad_ip_set = set()
        for r in get_bad_proxies_list():
             if r.get('ip'): bad_ip_set.add(r['ip'])
             elif r.get('proxy'): 
                 ip = extract_ip_local(r['proxy'])
                 if ip: bad_ip_set.add(ip)

        creds = parse_api_credentials(s)
        results = []; stats = {"used": 0, "bad": 0, "api": 0}
        
        with ThreadPoolExecutor(max_workers=s["MAX_WORKERS"]) as ex:
            # Check IP logic in 'single_check_proxy_detailed' handles Mid-Check to save API
            futures = {ex.submit(single_check_proxy_detailed, p, s["FRAUD_SCORE_LEVEL"], creds, used_ip_set, bad_ip_set, True): p for p in proxies if validate_proxy_format(p)}
            for f in as_completed(futures):
                res = f.result()
                if res["status"] == "used_cache": stats["used"] += 1
                elif res["status"] == "bad_cache": stats["bad"] += 1
                elif res["status"] in ["success", "bad_score"]: stats["api"] += 1
                if res.get("proxy"): results.append(res)

        unique = []
        seen = set()
        for r in results:
            if r['ip'] not in seen: seen.add(r['ip']); unique.append(r)
        
        good_count = len([r for r in unique if not r['used']])
        
        if good_count > 0: update_setting("CONSECUTIVE_FAILS", "0")
        else: 
            fails = s.get("CONSECUTIVE_FAILS", 0) + len(proxies)
            update_setting("CONSECUTIVE_FAILS", str(fails))
            if fails > 1000: update_setting("SYSTEM_PAUSED", "TRUE")

        add_api_usage_log(current_user.username, get_user_ip(), len(proxies), stats["api"], good_count)
        
        msg = f"Found {good_count} good proxies. ({stats['used']} cache, {stats['bad']} bad, {stats['api']} live)"
        return render_template("index.html", results=sorted(unique, key=lambda x: x['used']), message=msg, settings=s)

    return render_template("index.html", settings=s)

@app.route("/track-used", methods=["POST"])
@login_required
def track():
    d = request.get_json()
    # SAVES TO DB (Copy Button)
    if add_used_ip(d.get("ip"), d.get("proxy"), current_user.username): return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

# --- ADMIN ROUTES ---
@app.route("/admin")
@admin_required
def admin():
    s = get_app_settings()
    stats = {"total_api_calls_logged": sum([int(l.get("api_calls_count", 0)) for l in get_all_api_usage_logs()]), 
             "api_credits_remaining": s.get("API_CREDITS_REMAINING"), "system_paused": s.get("SYSTEM_PAUSED"), "consecutive_fails": s.get("CONSECUTIVE_FAILS")}
    return render_template("admin.html", stats=stats, used_ips=get_all_used_ips(), announcement=s.get("ANNOUNCEMENT"))

@app.route("/admin/pool", methods=['GET', 'POST'])
@admin_required
def admin_pool():
    if request.method == 'POST':
        if 'bulk_proxies' in request.form:
            add_bulk_proxies(request.form.get('bulk_proxies', '').splitlines(), request.form.get('provider'))
            flash("Added", "success")
        elif 'clear_pool' in request.form:
            clear_proxy_pool(request.form.get('clear_target'))
            flash("Cleared", "success")
        elif 'save_urls' in request.form:
            update_setting("PYPROXY_RESET_URL", request.form.get("pyproxy_url"))
            update_setting("PIAPROXY_RESET_URL", request.form.get("piaproxy_url"))
            flash("Saved", "success")
        return redirect(url_for('admin_pool'))
    return render_template("admin_pool.html", counts=get_pool_counts(), settings=get_app_settings())

@app.route("/admin/reset-system", methods=["POST"])
@admin_required
def admin_reset_system():
    update_setting("CONSECUTIVE_FAILS", "0"); update_setting("SYSTEM_PAUSED", "FALSE"); get_app_settings(force_refresh=True); flash("System reset.", "success"); return redirect(url_for("admin"))

@app.route("/admin/toggle-maintenance", methods=["POST"])
@admin_required
def admin_toggle_maintenance():
    curr = get_app_settings(); is_paused = str(curr.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"; new_state = "FALSE" if is_paused else "TRUE"; update_setting("SYSTEM_PAUSED", new_state); get_app_settings(force_refresh=True); flash(f"Maintenance {'Activated' if new_state=='TRUE' else 'Deactivated'}.", "success"); return redirect(url_for("admin"))

@app.route("/admin/users")
@admin_required
def admin_users(): return render_template("admin_users.html", stats=get_user_stats_summary())

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
            futures = {ex.submit(single_check_proxy_detailed, p, settings["STRICT_FRAUD_SCORE_LEVEL"], parse_api_credentials(settings), set(), set(), True): p for p in proxies_to_check}
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
    update_setting("ANNOUNCEMENT", val); get_app_settings(force_refresh=True); return redirect(url_for("admin"))

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
