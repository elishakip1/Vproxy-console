# --- IMPORTS ---
from flask import (
    Flask, request, render_template, redirect, url_for,
    jsonify, send_from_directory, flash, session
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from functools import wraps
import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed, FIRST_COMPLETED, wait
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys

# Import from db_util (Supabase)
from db_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip,
    get_all_used_ips,
    log_bad_proxy, get_bad_proxies_list,
    get_all_system_logs, add_log_entry,
    clear_all_system_logs,
    add_api_usage_log, get_all_api_usage_logs
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

# --- APP INITIALIZATION ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-super-secret-key-in-production")

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"

class User(UserMixin):
    def __init__(self, id, username, password, role="user"):
        self.id = id; self.username = username; self.password = password; self.role = role
    @property
    def is_admin(self): return self.role == "admin"

users = {
    1: User(id=1, username="Boss", password="ADMIN123", role="admin"),
    2: User(id=2, username="Work", password="password"),
}

@login_manager.user_loader
def load_user(user_id): return users.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def get_user_ip():
    ip = request.headers.get('X-Forwarded-For')
    if ip: return ip.split(',')[0].strip()
    return request.remote_addr or "Unknown"

# Default configuration values
DEFAULT_SETTINGS = {
    "MAX_PASTE": 30, "FRAUD_SCORE_LEVEL": 0, "MAX_WORKERS": 5,
    "SCAMALYTICS_API_KEY": "",
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/",
    "SCAMALYTICS_USERNAME": "",
    "ANNOUNCEMENT": "",
    "API_CREDITS_USED": "N/A",
    "API_CREDITS_REMAINING": "N/A",
    "STRICT_FRAUD_SCORE_LEVEL": 20,
    "CONSECUTIVE_FAILS": 0,
    "SYSTEM_PAUSED": "FALSE",
    "ABC_GENERATION_URL": ""
}

# --- CACHE ---
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
        final_settings["STRICT_FRAUD_SCORE_LEVEL"] = int(final_settings["STRICT_FRAUD_SCORE_LEVEL"])
        final_settings["MAX_WORKERS"] = int(final_settings["MAX_WORKERS"])
        final_settings["CONSECUTIVE_FAILS"] = int(final_settings.get("CONSECUTIVE_FAILS", 0))
    except: pass

    _SETTINGS_CACHE = final_settings
    _SETTINGS_CACHE_TIME = time.time()
    return final_settings

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
]
REQUEST_TIMEOUT = 5; MIN_DELAY = 0.5; MAX_DELAY = 1.5

def parse_api_credentials(settings):
    raw_keys = settings.get("SCAMALYTICS_API_KEY", "")
    raw_users = settings.get("SCAMALYTICS_USERNAME", "")
    raw_urls = settings.get("SCAMALYTICS_API_URL", "")
    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]
    users = [u.strip() for u in raw_users.split(',') if u.strip()]
    urls = [u.strip() for u in raw_urls.split(',') if u.strip()]
    if not keys: return []
    if len(users) == 1 and len(keys) > 1: users = users * len(keys)
    if len(urls) == 1 and len(keys) > 1: urls = urls * len(keys)
    credentials = []
    for k, u, url in zip(keys, users, urls):
        credentials.append({"key": k, "user": u, "url": url})
    return credentials

def validate_proxy_format(proxy_line):
    try:
        parts = proxy_line.strip().split(":")
        if len(parts) == 4 and all(part for part in parts): return True
        return False
    except: return False

def get_ip_from_proxy(proxy_line):
    if not validate_proxy_format(proxy_line): return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_dict = { "http": f"http://{user}:{pw}@{host}:{port}", "https": f"http://{user}:{pw}@{host}:{port}" }
        session = requests.Session()
        retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))
        response = session.get("https://ipv4.icanhazip.com", proxies=proxy_dict, timeout=REQUEST_TIMEOUT-1, headers={"User-Agent": random.choice(USER_AGENTS)})
        response.raise_for_status()
        ip = response.text.strip()
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
                data = resp.json()
                scam = data.get("scamalytics", {})
                if scam.get("status") == "error" and scam.get("error") == "out of credits":
                    add_log_entry("WARNING", f"Out of credits: {cred['user']}", ip="System")
                    continue
                return data
        except: continue
    return None

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, is_strict_mode=False):
    """
    RESTORED FULL STRICT LOGIC.
    Checks every single external blacklist provided by the API.
    """
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    res = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None}
    if not validate_proxy_format(proxy_line): return res
    
    ip = get_ip_from_proxy(proxy_line)
    res["ip"] = ip
    if not ip: return res

    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)
    if data and data.get("credits"): res["credits"] = data.get("credits")
    
    # Geo extraction
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
        scam = data.get("scamalytics", {})
        score = scam.get("scamalytics_score")
        res["score"] = score
        if scam.get("status") != "ok": return res
        
        try:
            score_int = int(score)
            res["score"] = score_int
            passed = True
            
            # 1. Basic Score Check
            if score_int > fraud_score_level: passed = False
            
            # 2. FULL STRICT CHECKS (Restored)
            if passed and is_strict_mode:
                # A. Scamalytics Risk
                if scam.get("scamalytics_risk") != "low": passed = False
                # B. Scamalytics Blacklist
                if scam.get("is_blacklisted_external") is True: passed = False
                # C. Scamalytics Flags
                pf = scam.get("scamalytics_proxy", {})
                for f in ["is_datacenter", "is_vpn", "is_apple_icloud_private_relay", "is_amazon_aws", "is_google"]:
                    if pf.get(f) is True: passed = False
                
                # D. External Data Sources (The missing part)
                ext_data = data.get("external_datasources", {})
                
                # ip2proxy
                if ext_data.get("ip2proxy", {}).get("proxy_type") == "VPN": passed = False
                if ext_data.get("ip2proxy_lite", {}).get("ip_blacklisted") is True: passed = False

                # Firehol
                firehol = ext_data.get("firehol", {})
                if firehol.get("ip_blacklisted_30") is True: passed = False
                if firehol.get("ip_blacklisted_1day") is True: passed = False
                if firehol.get("is_proxy") is True: passed = False

                # Ipsum
                ipsum = ext_data.get("ipsum", {})
                if ipsum.get("ip_blacklisted") is True: passed = False
                if ipsum.get("num_blacklists", 0) != 0: passed = False

                # Spamhaus Drop
                if ext_data.get("spamhaus_drop", {}).get("ip_blacklisted") is True: passed = False

                # x4bnet
                x4b = ext_data.get("x4bnet", {})
                for f in ["is_vpn", "is_datacenter", "is_tor", "is_blacklisted_spambot", "is_bot_operamini", "is_bot_semrush"]:
                    if x4b.get(f) is True: passed = False

                # Google external
                goog = ext_data.get("google", {})
                for f in ["is_google_general", "is_googlebot", "is_special_crawler", "is_user_triggered_fetcher"]:
                    if goog.get(f) is True: passed = False

            if passed: res["proxy"] = proxy_line
            elif score_int > fraud_score_level:
                try: log_bad_proxy(proxy_line, ip, score_int)
                except: pass
        except: pass
    return res

@app.before_request
def before_request_func():
    if request.path.startswith(('/static', '/login', '/logout')) or request.path.endswith(('.ico', '.png')): return

# --- Routes ---

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
    settings = get_app_settings()
    generation_url = settings.get("ABC_GENERATION_URL", "").strip()
    if not generation_url: return jsonify({"status": "error", "message": "ABC Generation URL not set."})
    try:
        response = requests.get(generation_url, timeout=10)
        if response.status_code == 200:
            content = response.text.strip()
            if not content or "{" in content:
                 try:
                     json_data = response.json()
                     if json_data.get("code") != 0: return jsonify({"status": "error", "message": f"API Error: {json_data}"})
                 except: pass
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            return jsonify({"status": "success", "proxies": lines})
        return jsonify({"status": "error", "message": f"HTTP Error: {response.status_code}"})
    except Exception as e: return jsonify({"status": "error", "message": f"Server Error: {str(e)}"})

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    settings = get_app_settings()
    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    api_credentials = parse_api_credentials(settings)
    system_paused = str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    
    admin_bypass = False
    if system_paused:
        if current_user.is_admin:
            admin_bypass = True
        else:
            return render_template("index.html", results=None, message="⚠️ System Under Maintenance. Please try again later.", max_paste=MAX_PASTE, settings=settings, system_paused=True, announcement=settings.get("ANNOUNCEMENT"))

    if request.method == "POST":
        if system_paused and not admin_bypass:
             return render_template("index.html", results=None, message="System Paused.", max_paste=MAX_PASTE, settings=settings, system_paused=True)

        proxies_input = []
        if 'proxytext' in request.form:
            all_lines = request.form.get("proxytext", "").strip().splitlines()
            proxies_input = all_lines[:MAX_PASTE]
        
        if not proxies_input:
             return render_template("index.html", results=[], message="No proxies submitted.", max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"))

        used_ips_list = set(); used_proxy_cache = set(); bad_proxy_cache = set()
        try:
            u_recs = get_all_used_ips()
            used_ips_list = {str(r.get('IP')).strip() for r in u_recs if r.get('IP')}
            used_proxy_cache = {r.get('Proxy') for r in u_recs if r.get('Proxy')}
            bad_proxy_cache = set(get_bad_proxies_list())
        except: pass

        proxies_to_check = []
        for p in {px.strip() for px in proxies_input if px.strip()}:
            if validate_proxy_format(p) and p not in used_proxy_cache and p not in bad_proxy_cache:
                proxies_to_check.append(p)

        good_proxy_results = []; futures = set()
        if proxies_to_check:
            with ThreadPoolExecutor(max_workers=min(settings["MAX_WORKERS"], len(proxies_to_check))) as executor:
                for p in proxies_to_check:
                    futures.add(executor.submit(single_check_proxy_detailed, p, FRAUD_SCORE_LEVEL, api_credentials, is_strict_mode=True))
                while futures:
                    done, futures = wait(futures, return_when=FIRST_COMPLETED)
                    for f in done:
                        try:
                            res = f.result()
                            if res and res.get("proxy"):
                                res['used'] = str(res.get('ip')).strip() in used_ips_list
                                good_proxy_results.append(res)
                                if len([r for r in good_proxy_results if not r['used']]) >= 2:
                                    for x in futures: x.cancel()
                                    futures = set(); break
                        except: pass
                    if not futures: break

        unique_results = []
        seen = set()
        for r in good_proxy_results:
            if r['ip'] not in seen: seen.add(r['ip']); unique_results.append(r)
        results = sorted(unique_results, key=lambda x: x['used'])

        good_count = len([r for r in results if not r['used']])
        fails = settings.get("CONSECUTIVE_FAILS", 0)
        
        if good_count > 0 and fails > 0:
            update_setting("CONSECUTIVE_FAILS", "0")
            if _SETTINGS_CACHE: _SETTINGS_CACHE["CONSECUTIVE_FAILS"] = 0
        elif not good_count and proxies_to_check:
            new_fails = fails + len(proxies_to_check)
            update_setting("CONSECUTIVE_FAILS", str(new_fails))
            if new_fails > 1000:
                update_setting("SYSTEM_PAUSED", "TRUE")
                add_log_entry("CRITICAL", "Auto-paused system due to failures.", ip="System")
        
        try: add_api_usage_log(current_user.username, get_user_ip(), len(proxies_input), len(proxies_to_check))
        except: pass
        
        msg_prefix = "⚠️ MAINTENANCE MODE ACTIVE (Admin Access) - " if admin_bypass else ""
        message = f"{msg_prefix}Found {good_count} new usable proxies."

        return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False)

    msg_prefix = "⚠️ MAINTENANCE MODE ACTIVE (Admin Access)" if admin_bypass else ""
    return render_template("index.html", results=None, message=msg_prefix, max_paste=MAX_PASTE, settings=settings, announcement=settings.get("ANNOUNCEMENT"), system_paused=False)

@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    data = request.get_json()
    proxy = data.get("proxy"); ip = data.get("ip")
    if not proxy or not ip or not validate_proxy_format(proxy): return jsonify({"status": "error"}), 400
    if add_used_ip(ip, proxy):
        add_log_entry("INFO", f"Marked used: {ip}", ip=get_user_ip())
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 500

@app.route("/admin")
@admin_required
def admin():
    settings = get_app_settings()
    total_api_calls = 0
    try:
        for log in get_all_api_usage_logs(): total_api_calls += int(log.get("API Calls Made") or 0)
    except: total_api_calls = "Error"
    
    stats = {
        "max_paste": settings["MAX_PASTE"],
        "fraud_score_level": settings["FRAUD_SCORE_LEVEL"],
        "strict_fraud_score_level": settings["STRICT_FRAUD_SCORE_LEVEL"],
        "max_workers": settings["MAX_WORKERS"],
        "scamalytics_username": settings["SCAMALYTICS_USERNAME"],
        "api_credits_remaining": settings.get("API_CREDITS_REMAINING"),
        "api_credits_used": settings.get("API_CREDITS_USED"),
        "consecutive_fails": settings.get("CONSECUTIVE_FAILS"),
        "system_paused": settings.get("SYSTEM_PAUSED"),
        "total_api_calls_logged": total_api_calls,
        "abc_generation_url": settings.get("ABC_GENERATION_URL")
    }
    return render_template("admin.html", stats=stats, used_ips=get_all_used_ips(), announcement=settings.get("ANNOUNCEMENT"))

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
    current_settings = get_app_settings()
    is_paused = str(current_settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_paused else "TRUE"
    if update_setting("SYSTEM_PAUSED", new_state):
        get_app_settings(force_refresh=True)
        status_msg = "ACTIVATED" if new_state == "TRUE" else "DEACTIVATED"
        flash(f"Maintenance Mode {status_msg}.", "success" if new_state == "FALSE" else "warning")
        add_log_entry("WARNING", f"Maintenance Mode {status_msg} by {current_user.username}", ip=get_user_ip())
    else:
        flash("Failed to toggle maintenance mode.", "danger")
    return redirect(url_for("admin"))

@app.route("/admin/logs")
@admin_required
def admin_logs():
    return render_template("admin_logs.html", logs=get_all_system_logs()[::-1])

@app.route("/admin/clear-logs", methods=["POST"])
@admin_required
def admin_clear_logs():
    clear_all_system_logs()
    return redirect(url_for("admin_logs"))

@app.route("/admin/test", methods=["GET", "POST"])
@admin_required
def admin_test():
    settings = get_app_settings()
    MAX_PASTE = settings["MAX_PASTE"]
    results = None; message = None
    if request.method == "POST":
        proxies_input = request.form.get("proxytext", "").strip().splitlines()[:MAX_PASTE]
        proxies_to_check = [p.strip() for p in proxies_input if validate_proxy_format(p.strip())]
        good = []
        with ThreadPoolExecutor(max_workers=min(settings["MAX_WORKERS"], len(proxies_to_check))) as ex:
            futures = {ex.submit(single_check_proxy_detailed, p, settings["STRICT_FRAUD_SCORE_LEVEL"], parse_api_credentials(settings), True): p for p in proxies_to_check}
            for f in as_completed(futures):
                res = f.result()
                if res.get("proxy"): good.append(res)
        results = good
        message = f"Strict check found {len(results)} proxies."
    return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    current_settings = get_app_settings()
    if request.method == "POST":
        form = request.form
        updates = {
            "MAX_PASTE": form.get("max_paste"),
            "FRAUD_SCORE_LEVEL": form.get("fraud_score_level"),
            "STRICT_FRAUD_SCORE_LEVEL": form.get("strict_fraud_score_level"),
            "MAX_WORKERS": form.get("max_workers"),
            "SCAMALYTICS_API_KEY": form.get("scamalytics_api_key", "").strip(),
            "SCAMALYTICS_API_URL": form.get("scamalytics_api_url", "").strip(),
            "SCAMALYTICS_USERNAME": form.get("scamalytics_username", "").strip(),
            "ABC_GENERATION_URL": form.get("abc_generation_url", "").strip()
        }
        success = True
        for k, v in updates.items():
            if not update_setting(k, str(v)): success = False
            time.sleep(0.5)
        if success:
            flash("Settings updated.", "success")
            current_settings = get_app_settings(force_refresh=True)
        else:
            flash("Some settings failed to save.", "danger")
            current_settings.update(updates)
    return render_template("admin_settings.html", settings=current_settings)

@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    val = request.form.get("announcement_text", "").strip() if "save_announcement" in request.form else ""
    if update_setting("ANNOUNCEMENT", val):
        flash("Announcement updated.", "success")
        get_app_settings(force_refresh=True)
    else: flash("Failed to update announcement.", "danger")
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
