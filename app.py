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
from urllib3.util.retry import Retry  # Updated import
import logging
import sys
import re
import json

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
    get_active_fetch_buttons, get_all_fetch_buttons, add_fetch_button, delete_fetch_button, delete_user_activity_logs,
    get_user_by_id  # Added
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
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.can_fetch = can_fetch
        self.daily_api_limit = daily_api_limit
    
    @property
    def is_admin(self):
        return self.role == "admin"
    
    @property 
    def is_guest(self):
        return self.role == "guest"
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,
            'role': self.role,
            'can_fetch': self.can_fetch,
            'daily_api_limit': daily_api_limit
        }

def load_users_from_db():
    try:
        users_data = get_all_users()
        users_map = {}
        for user_data in users_data:
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                password=user_data['password'],
                role=user_data.get('role', 'user'),
                can_fetch=user_data.get('can_fetch', False),
                daily_api_limit=user_data.get('daily_api_limit', 0)
            )
            users_map[user.id] = user
        
        if not users_map:
            init_default_users()
            users_data = get_all_users()
            for user_data in users_data:
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    password=user_data['password'],
                    role=user_data.get('role', 'user'),
                    can_fetch=user_data.get('can_fetch', False),
                    daily_api_limit=user_data.get('daily_api_limit', 0)
                )
                users_map[user.id] = user
        return users_map
    except Exception as e:
        logger.error(f"Error loading users from DB: {e}")
        return {1: User(id=1, username="EL", password="ADMIN123", role="admin", can_fetch=True, daily_api_limit=0)}

users = load_users_from_db()

@login_manager.user_loader
def load_user(user_id):
    try:
        user_data = get_user_by_id(user_id)  # Use DB function
        if user_data:
            return User(
                id=user_data['id'],
                username=user_data['username'],
                password=user_data['password'],
                role=user_data.get('role', 'user'),
                can_fetch=user_data.get('can_fetch', False),
                daily_api_limit=user_data.get('daily_api_limit', 0)
            )
        return None
    except Exception as e:
        logger.error(f"Error loading user {user_id}: {e}")
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def get_user_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
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
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        db_settings = {}
    
    final_settings = DEFAULT_SETTINGS.copy()
    final_settings.update(db_settings)
    
    try:
        final_settings["MAX_PASTE"] = int(final_settings["MAX_PASTE"])
        final_settings["FRAUD_SCORE_LEVEL"] = int(final_settings["FRAUD_SCORE_LEVEL"])
        final_settings["MAX_WORKERS"] = int(final_settings["MAX_WORKERS"])
        final_settings["CONSECUTIVE_FAILS"] = int(final_settings.get("CONSECUTIVE_FAILS", 0))
    except ValueError:
        logger.error("Error converting settings to integers")
    
    _SETTINGS_CACHE = final_settings
    _SETTINGS_CACHE_TIME = time.time()
    return final_settings

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15"
]

REQUEST_TIMEOUT = 10
MIN_DELAY = 0.5
MAX_DELAY = 1.5

def parse_api_credentials(settings):
    raw_keys = settings.get("SCAMALYTICS_API_KEY", "")
    raw_users = settings.get("SCAMALYTICS_USERNAME", "")
    raw_urls = settings.get("SCAMALYTICS_API_URL", "")
    
    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]
    user_list = [u.strip() for u in raw_users.split(',') if u.strip()]
    urls = [u.strip() for u in raw_urls.split(',') if u.strip()]
    
    if not keys:
        return []
    
    if len(user_list) == 1 and len(keys) > 1:
        user_list = user_list * len(keys)
    if len(urls) == 1 and len(keys) > 1:
        urls = urls * len(keys)
    
    credentials = []
    for k, u, url in zip(keys, user_list, urls):
        credentials.append({"key": k, "user": u, "url": url})
    return credentials

def validate_proxy_format(proxy_line):
    try:
        if not proxy_line or not isinstance(proxy_line, str):
            return False
        parts = proxy_line.strip().split(":")
        return len(parts) == 4 and all(part for part in parts)
    except Exception:
        return False

def extract_ip_local(proxy_line):
    try:
        return proxy_line.split(':')[0].strip()
    except Exception:
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
        
        session_req = requests.Session()
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        session_req.mount('http://', HTTPAdapter(max_retries=retries))
        session_req.mount('https://', HTTPAdapter(max_retries=retries))
        
        response = session_req.get(
            "https://ipv4.icanhazip.com",
            proxies=proxy_dict,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        response.raise_for_status()
        ip = response.text.strip()
        return ip if (ip and '.' in ip) else None
    except Exception as e:
        logger.debug(f"Failed to get IP from proxy {proxy_line[:20]}...: {e}")
        return None

def verify_ip_stability(proxy_line, required_stable_checks=3, max_attempts=5):
    if not validate_proxy_format(proxy_line):
        return None
    
    seen_ips = set()
    for attempt in range(max_attempts):
        ip = get_ip_from_proxy(proxy_line)
        if not ip:
            time.sleep(random.uniform(0.1, 0.3))
            continue
        
        seen_ips.add(ip)
        if len(seen_ips) == 1 and (attempt + 1) >= required_stable_checks:
            return ip
        if len(seen_ips) > 1:
            return None
        if attempt < max_attempts - 1:
            time.sleep(random.uniform(0.1, 0.3))
    
    return None

def get_fraud_score_detailed(ip, proxy_line, credentials_list):
    if not validate_proxy_format(proxy_line) or not ip or not credentials_list:
        return None
    
    for cred in credentials_list:
        try:
            host, port, user, pw = proxy_line.strip().split(":")
            proxy_url = f"http://{user}:{pw}@{host}:{port}"
            proxies = {"http": proxy_url, "https": proxy_url}
            
            url = f"{cred['url'].rstrip('/')}/{cred['user']}/?key={cred['key']}&ip={ip}"
            
            resp = requests.get(
                url,
                headers={"User-Agent": random.choice(USER_AGENTS)},
                proxies=proxies,
                timeout=REQUEST_TIMEOUT
            )
            
            if resp.status_code == 200:
                data = resp.json()
                scam = data.get("scamalytics", {})
                
                if scam.get("status") == "error" and scam.get("error") == "out of credits":
                    add_log_entry("WARNING", f"Out of credits: {cred['user']}", ip="System")
                    update_setting("API_CREDITS_REMAINING", "0")
                    continue
                
                if scam.get("status") == "ok" and scam.get("credits"):
                    update_setting("API_CREDITS_USED", str(scam.get("credits", {}).get("used", 0)))
                    update_setting("API_CREDITS_REMAINING", str(scam.get("credits", {}).get("remaining", 0)))
                
                return data
        except Exception as e:
            logger.debug(f"Failed to get fraud score: {e}")
            continue
    
    return None

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, used_ip_set, bad_ip_set, is_strict_mode=False):
    res = {
        "proxy": None,
        "ip": None,
        "credits": {},
        "geo": {},
        "score": None,
        "status": "error",
        "used": False,
        "cached_bad": False,
        "unstable": False
    }
    
    if not validate_proxy_format(proxy_line):
        return res
    
    # Check stability
    ip = verify_ip_stability(proxy_line, required_stable_checks=2, max_attempts=3)
    if not ip:
        res["status"] = "unstable_ip"
        res["unstable"] = True
        return res
    
    res["ip"] = ip
    
    # Check used cache
    if str(ip).strip() in used_ip_set:
        res["used"] = True
        res["status"] = "used_cache"
        return res
    
    # Check bad cache
    if str(ip).strip() in bad_ip_set:
        res["cached_bad"] = True
        res["status"] = "bad_cache"
        return res
    
    # Delay before API call
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    
    # Get fraud score
    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)
    if data and data.get("scamalytics", {}).get("credits"):
        res["credits"] = data.get("scamalytics", {}).get("credits", {})
    
    # Extract geo information
    try:
        ext_src = data.get("external_datasources", {}) if data else {}
        geo = {}
        
        # Try MaxMind first
        mm = ext_src.get("maxmind_geolite2", {})
        if mm and "PREMIUM" not in mm.get("ip_country_code", ""):
            geo = {
                "country_code": mm.get("ip_country_code"),
                "state": mm.get("ip_state_name"),
                "city": mm.get("ip_city"),
                "postcode": mm.get("ip_postcode")
            }
        
        # Fallback to DBIP
        if not geo:
            db = ext_src.get("dbip", {})
            if db and "PREMIUM" not in db.get("ip_country_code", ""):
                geo = {
                    "country_code": db.get("ip_country_code"),
                    "state": db.get("ip_state_name"),
                    "city": db.get("ip_city"),
                    "postcode": db.get("ip_postcode")
                }
        
        res["geo"] = geo if geo else {
            "country_code": "N/A",
            "state": "N/A",
            "city": "N/A",
            "postcode": "N/A"
        }
    except Exception:
        res["geo"] = {
            "country_code": "ERR",
            "state": "ERR",
            "city": "ERR",
            "postcode": "ERR"
        }
    
    # Process fraud score result
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
            
            # Basic score check
            if score_int > fraud_score_level:
                passed = False
            
            # Strict mode checks
            if passed and is_strict_mode:
                if scam.get("scamalytics_risk") != "low":
                    passed = False
                
                if scam.get("is_blacklisted_external") is True:
                    passed = False
                
                pf = scam.get("scamalytics_proxy", {})
                strict_checks = [
                    "is_datacenter",
                    "is_vpn",
                    "is_apple_icloud_private_relay",
                    "is_amazon_aws",
                    "is_google"
                ]
                for check in strict_checks:
                    if pf.get(check) is True:
                        passed = False
            
            if passed:
                res["proxy"] = proxy_line
                res["status"] = "success"
            elif score_int > fraud_score_level:
                # Log bad proxy
                try:
                    log_bad_proxy(proxy_line, ip, score_int)
                except Exception:
                    pass
                res["status"] = "bad_score"
                
        except (ValueError, TypeError) as e:
            logger.debug(f"Error processing score: {e}")
    
    return res

# --- ROUTES ---

@app.before_request
def before_request_func():
    user_ip = get_user_ip()
    if user_ip in BLOCKED_IPS:
        abort(404)
    
    # Skip auth for static files and login/logout
    if request.path.startswith(('/static', '/login', '/logout')) or \
       request.path.endswith(('.ico', '.png', '.jpg', '.css', '.js')):
        return

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin'))
        return redirect(url_for('index'))
    
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # Find user in database
        user_data = get_user_by_username(username)
        if user_data and user_data['password'] == password:
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                password=user_data['password'],
                role=user_data.get('role', 'user'),
                can_fetch=user_data.get('can_fetch', False),
                daily_api_limit=user_data.get('daily_api_limit', 0)
            )
            login_user(user, remember=(request.form.get('remember') == 'on'))
            
            # Update global users cache
            global users
            users = load_users_from_db()
            
            next_page = request.args.get('next')
            if next_page and not current_user.is_admin and '/admin' in next_page:
                next_page = url_for('index')
            if current_user.is_admin and next_page == url_for('index'):
                next_page = url_for('admin')
            
            add_log_entry("INFO", f"User {user.username} logged in.", ip=get_user_ip())
            return redirect(next_page or (url_for('admin') if current_user.is_admin else url_for('index')))
        
        error = 'Invalid Credentials.'
        add_log_entry("WARNING", f"Failed login attempt: {username}", ip=get_user_ip())
    
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    add_log_entry("INFO", f"User {username} logged out.", ip=get_user_ip())
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/fetch-abc-proxies')
@login_required
def fetch_abc_proxies():
    if not current_user.can_fetch:
        return jsonify({"status": "error", "message": "Permission denied."}), 403
    
    settings = get_app_settings()
    gen_url = settings.get("ABC_GENERATION_URL", "").strip()
    limit = int(settings.get("MAX_PASTE", 30))
    state = request.args.get('state', '').lower()
    
    if not gen_url:
        return jsonify({"status": "error", "message": "ABC Generation URL not set."}), 400
    
    try:
        parsed = urlparse(gen_url)
        params = parse_qs(parsed.query)
        
        if state:
            user_val = params.get('username', [''])[0]
            new_user = re.sub(r'st-[a-zA-Z0-9]+', f'st-{state}', user_val) if 'st-' in user_val else user_val + f"-st-{state}"
            params['username'] = [new_user]
        
        params['num'] = [str(limit)]
        final_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
        
        resp = requests.get(final_url, timeout=15)
        if resp.status_code == 200:
            lines = [l.strip() for l in resp.text.strip().splitlines() if l.strip()]
            lines = lines[:limit]
            return jsonify({"status": "success", "proxies": lines})
        
        return jsonify({"status": "error", "message": f"HTTP Error: {resp.status_code}"}), resp.status_code
    
    except Exception as e:
        logger.error(f"Error fetching ABC proxies: {e}")
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500

@app.route('/api/fetch-sx-proxies')
@login_required
def fetch_sx_proxies():
    if not current_user.can_fetch:
        return jsonify({"status": "error", "message": "Permission denied."}), 403
    
    settings = get_app_settings()
    gen_url = settings.get("SX_GENERATION_URL", "").strip()
    limit = int(settings.get("MAX_PASTE", 30))
    
    if not gen_url:
        return jsonify({"status": "error", "message": "SX Generation URL not set."}), 400
    
    try:
        resp = requests.get(gen_url, timeout=15)
        if resp.status_code == 200:
            lines = [l.strip() for l in resp.text.strip().splitlines() if l.strip()]
            lines = lines[:limit]
            return jsonify({"status": "success", "proxies": lines})
        
        return jsonify({"status": "error", "message": f"HTTP Error: {resp.status_code}"}), resp.status_code
    
    except Exception as e:
        logger.error(f"Error fetching SX proxies: {e}")
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"}), 500

@app.route('/api/fetch-pool-provider/<provider>')
@login_required
def fetch_pool_provider(provider):
    if not current_user.can_fetch:
        return jsonify({"status": "error", "message": "Permission denied"}), 403
    
    limit = int(get_app_settings().get("MAX_PASTE", 30))
    
    try:
        proxies = get_random_proxies_from_pool(limit)
        return jsonify({"status": "success", "proxies": proxies})
    except Exception as e:
        logger.error(f"Error fetching pool proxies: {e}")
        return jsonify({"status": "error", "message": "Database error"}), 500

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    settings = get_app_settings()
    MAX_PASTE = settings["MAX_PASTE"]
    api_credentials = parse_api_credentials(settings)
    system_paused = str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    dynamic_buttons = get_active_fetch_buttons() if current_user.can_fetch else []
    admin_bypass = current_user.is_admin and system_paused
    
    # Check guest user daily limit
    if current_user.is_guest and current_user.daily_api_limit > 0:
        daily_usage = get_daily_api_usage_for_user(current_user.username)
        if daily_usage >= current_user.daily_api_limit:
            return render_template(
                "index.html",
                results=None,
                message=f"Daily API limit reached ({current_user.daily_api_limit} calls).",
                max_paste=MAX_PASTE,
                settings=settings,
                dynamic_buttons=dynamic_buttons,
                announcement=settings.get("ANNOUNCEMENT"),
                system_paused=False,
                paste_disabled_for_user=False
            )
    
    # Check if paste is disabled for regular users
    paste_disabled = (current_user.role == "user" and 
                     str(settings.get("FORCE_FETCH_FOR_USERS", "FALSE")).upper() == "TRUE")
    
    # Handle system pause
    if system_paused and not current_user.is_admin:
        return render_template(
            "index.html",
            results=None,
            message="⚠️ System Under Maintenance.",
            max_paste=MAX_PASTE,
            settings=settings,
            system_paused=True,
            dynamic_buttons=dynamic_buttons,
            announcement=settings.get("ANNOUNCEMENT"),
            paste_disabled_for_user=paste_disabled
        )
    
    # Handle POST request (proxy check)
    if request.method == "POST":
        if system_paused and not current_user.is_admin:
            return render_template(
                "index.html",
                results=None,
                message="System Paused.",
                max_paste=MAX_PASTE,
                settings=settings,
                dynamic_buttons=dynamic_buttons,
                system_paused=True,
                announcement=settings.get("ANNOUNCEMENT"),
                paste_disabled_for_user=paste_disabled
            )
        
        origin = request.form.get('proxy_origin', 'paste')
        
        # Validate paste permission
        if paste_disabled and origin != 'fetch' and 'proxytext' in request.form:
            return render_template(
                "index.html",
                results=[],
                message="Manual pasting disabled. Please use fetch buttons.",
                max_paste=MAX_PASTE,
                settings=settings,
                dynamic_buttons=dynamic_buttons,
                announcement=settings.get("ANNOUNCEMENT"),
                system_paused=False,
                paste_disabled_for_user=paste_disabled
            )
        
        # Get proxies from form
        proxies_input = request.form.get("proxytext", "").strip().splitlines()
        proxies_input = proxies_input[:MAX_PASTE]
        
        if not proxies_input:
            return render_template(
                "index.html",
                results=[],
                message="No proxies submitted.",
                max_paste=MAX_PASTE,
                settings=settings,
                dynamic_buttons=dynamic_buttons,
                announcement=settings.get("ANNOUNCEMENT"),
                paste_disabled_for_user=paste_disabled
            )
        
        # Get cached IPs
        used_ip_set = {str(r['IP']).strip() for r in get_all_used_ips() if r.get('IP')}
        bad_ip_set = set()
        
        for r in get_bad_proxies_list():
            if r.get('ip'):
                bad_ip_set.add(str(r['ip']).strip())
            elif r.get('proxy'):
                lip = extract_ip_local(r['proxy'])
                if lip:
                    bad_ip_set.add(lip)
        
        # Validate proxy format
        proxies_raw = [p.strip() for p in proxies_input if validate_proxy_format(p.strip())]
        
        if not proxies_raw:
            return render_template(
                "index.html",
                results=[],
                message="No valid proxies found. Format: host:port:user:pass",
                max_paste=MAX_PASTE,
                settings=settings,
                dynamic_buttons=dynamic_buttons,
                announcement=settings.get("ANNOUNCEMENT"),
                paste_disabled_for_user=paste_disabled
            )
        
        good_proxy_results = []
        stats = {"used": 0, "bad": 0, "api": 0, "unstable": 0}
        
        # Check proxies in parallel
        with ThreadPoolExecutor(max_workers=settings["MAX_WORKERS"]) as executor:
            batch_size = min(settings["MAX_WORKERS"] * 2, len(proxies_raw))
            
            for i in range(0, len(proxies_raw), batch_size):
                batch = proxies_raw[i:i + batch_size]
                
                # Stop if we already found enough good proxies
                good_count = len([r for r in good_proxy_results if r.get('proxy')])
                if good_count >= 2 and len(batch) > 5:
                    break
                
                futures = {
                    executor.submit(
                        single_check_proxy_detailed,
                        p,
                        settings["FRAUD_SCORE_LEVEL"],
                        api_credentials,
                        used_ip_set,
                        bad_ip_set,
                        is_strict_mode=True
                    ): p for p in batch
                }
                
                for future in as_completed(futures):
                    res = future.result()
                    
                    # Update stats
                    if res["status"] == "used_cache":
                        stats["used"] += 1
                    elif res["status"] == "bad_cache":
                        stats["bad"] += 1
                    elif res["status"] == "unstable_ip":
                        stats["unstable"] += 1
                    elif res["status"] in ["success", "bad_score"]:
                        stats["api"] += 1
                    
                    if res.get("proxy"):
                        good_proxy_results.append(res)
        
        # Remove duplicates
        unique_results = []
        seen_ips = set()
        for r in good_proxy_results:
            if r['ip'] and r['ip'] not in seen_ips:
                seen_ips.add(r['ip'])
                unique_results.append(r)
        
        # Sort results (good proxies first)
        results = sorted(unique_results, key=lambda x: (x.get('used', False), x.get('score', 100)))
        good_final = len([r for r in results if r.get('proxy')])
        
        # Update consecutive fails counter
        if good_final > 0:
            update_setting("CONSECUTIVE_FAILS", "0")
        elif proxies_raw:
            new_fails = settings.get("CONSECUTIVE_FAILS", 0) + len(proxies_raw)
            update_setting("CONSECUTIVE_FAILS", str(new_fails))
            if new_fails > 1000:
                update_setting("SYSTEM_PAUSED", "TRUE")
        
        # Log API usage
        try:
            add_api_usage_log(
                current_user.username,
                get_user_ip(),
                len(proxies_input),
                stats["api"],
                good_final
            )
        except Exception as e:
            logger.error(f"Error logging API usage: {e}")
        
        message = f"Processed {len(proxies_input)} proxies. Found {good_final} good proxies. "
        message += f"(Used: {stats['used']}, Bad: {stats['bad']}, Unstable: {stats['unstable']})"
        
        return render_template(
            "index.html",
            results=results,
            message=message,
            max_paste=MAX_PASTE,
            settings=settings,
            dynamic_buttons=dynamic_buttons,
            announcement=settings.get("ANNOUNCEMENT"),
            system_paused=False,
            paste_disabled_for_user=paste_disabled
        )
    
    # GET request - show form
    return render_template(
        "index.html",
        results=None,
        message="⚠️ MAINTENANCE (Admin)" if admin_bypass else "",
        max_paste=MAX_PASTE,
        settings=settings,
        dynamic_buttons=dynamic_buttons,
        announcement=settings.get("ANNOUNCEMENT"),
        system_paused=False,
        paste_disabled_for_user=paste_disabled
    )

@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400
        
        proxy = data.get("proxy")
        ip = data.get("ip")
        
        if not proxy or not ip:
            return jsonify({"status": "error", "message": "Missing proxy or IP"}), 400
        
        if not validate_proxy_format(proxy):
            return jsonify({"status": "error", "message": "Invalid proxy format"}), 400
        
        # Add to used IPs
        success = add_used_ip(ip, proxy, username=current_user.username)
        
        if success:
            add_log_entry("INFO", f"Used IP tracked: {ip}", ip=get_user_ip())
            return jsonify({"status": "success"})
        
        return jsonify({"status": "error", "message": "Database error"}), 500
    
    except Exception as e:
        logger.error(f"Error tracking used IP: {e}")
        return jsonify({"status": "error", "message": "Server error"}), 500

# --- ADMIN ROUTES ---

@app.route("/admin")
@admin_required
def admin():
    settings = get_app_settings()
    
    # Calculate total API calls
    try:
        logs = get_all_api_usage_logs()
        total_api = sum(int(log.get("api_calls_count", 0)) for log in logs if log)
    except Exception:
        total_api = "Error"
    
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
    
    return render_template(
        "admin.html",
        stats=stats,
        used_ips=get_all_used_ips(),
        announcement=settings.get("ANNOUNCEMENT"),
        settings=settings
    )

@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        try:
            updates = {
                "MAX_PASTE": request.form.get("max_paste", "").strip(),
                "FRAUD_SCORE_LEVEL": request.form.get("fraud_score_level", "").strip(),
                "MAX_WORKERS": request.form.get("max_workers", "").strip(),
                "SCAMALYTICS_API_KEY": request.form.get("scamalytics_api_key", "").strip(),
                "SCAMALYTICS_API_URL": request.form.get("scamalytics_api_url", "").strip(),
                "SCAMALYTICS_USERNAME": request.form.get("scamalytics_username", "").strip(),
                "ABC_GENERATION_URL": request.form.get("abc_generation_url", "").strip(),
                "SX_GENERATION_URL": request.form.get("sx_generation_url", "").strip(),
                "PYPROXY_RESET_URL": request.form.get("pyproxy_reset_url", "").strip(),
                "PIAPROXY_RESET_URL": request.form.get("piaproxy_reset_url", "").strip(),
                "FORCE_FETCH_FOR_USERS": request.form.get("force_fetch_for_users", "FALSE")
            }
            
            for key, value in updates.items():
                if value is not None:
                    update_setting(key, str(value))
            
            flash("Settings updated successfully.", "success")
            get_app_settings(force_refresh=True)
            
        except Exception as e:
            logger.error(f"Error updating settings: {e}")
            flash("Error updating settings.", "danger")
    
    return render_template(
        "admin_settings.html",
        settings=get_app_settings(),
        buttons=get_all_fetch_buttons()
    )

@app.route("/admin/add-button", methods=["POST"])
@admin_required
def admin_add_button():
    name = request.form.get("name", "").strip()
    b_type = request.form.get("type", "").strip()
    target = request.form.get("target", "").strip()
    
    if not name or not b_type or not target:
        flash("All fields are required.", "danger")
        return redirect(url_for('admin_settings'))
    
    if add_fetch_button(name, b_type, target):
        flash(f"Button '{name}' created successfully!", "success")
    else:
        flash("Error creating button.", "danger")
    
    return redirect(url_for('admin_settings'))

@app.route("/admin/delete-button/<int:btn_id>")
@admin_required
def admin_del_button(btn_id):
    if delete_fetch_button(btn_id):
        flash("Button removed successfully.", "success")
    else:
        flash("Error removing button.", "danger")
    
    return redirect(url_for('admin_settings'))

@app.route("/admin/users")
@admin_required
def admin_users():
    stats = get_user_stats_summary()
    
    # Calculate user status
    for s in stats:
        try:
            if s.get('last_active'):
                last_active = datetime.datetime.fromisoformat(
                    s['last_active'].replace('Z', '+00:00')
                )
                now = datetime.datetime.now(datetime.timezone.utc)
                diff = now - last_active
                
                if diff.days > 7:
                    s['status'] = 'Inactive'
                elif diff.total_seconds() > 86400:  # 24 hours
                    s['status'] = 'Offline'
                else:
                    s['status'] = 'Active'
            else:
                s['status'] = 'Unknown'
        except Exception:
            s['status'] = 'Unknown'
    
    return render_template("admin_users.html", stats=stats)

@app.route("/admin/delete-user-activity/<username>")
@admin_required
def admin_delete_user_activity(username):
    if delete_user_activity_logs(username):
        flash(f"Activity for {username} cleared.", "success")
    else:
        flash("Error clearing activity.", "danger")
    
    return redirect(url_for('admin_users'))

@app.route('/admin/users/manage', methods=['GET'])
@admin_required
def admin_users_manage():
    global users
    users = load_users_from_db()
    
    user_list = []
    for user in users.values():
        u_dict = user.to_dict()
        u_dict['daily_api_usage'] = get_daily_api_usage_for_user(user.username)
        user_list.append(u_dict)
    
    return render_template('admin_users_manage.html', users=user_list)

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    global users
    
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    role = request.form.get('role', 'user')
    can_fetch = request.form.get('can_fetch') == 'on'
    
    # Set daily limit for guests
    if role == 'guest':
        daily_api_limit = int(request.form.get('daily_api_limit', 150))
    else:
        daily_api_limit = 0
    
    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for('admin_users_manage'))
    
    if create_user(username, password, role, can_fetch, daily_api_limit):
        users = load_users_from_db()
        flash(f'User {username} created successfully.', 'success')
    else:
        flash('Error creating user. Username may already exist.', 'danger')
    
    return redirect(url_for('admin_users_manage'))

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@admin_required
def admin_edit_user(user_id):
    global users
    
    if user_id not in users or user_id == 1:
        flash('Invalid action.', 'danger')
        return redirect(url_for('admin_users_manage'))
    
    role = request.form.get('role')
    updates = {
        'role': role,
        'can_fetch': request.form.get('can_fetch') == 'on'
    }
    
    # Set daily limit for guests
    if role == 'guest':
        updates['daily_api_limit'] = int(request.form.get('daily_api_limit', 0))
    else:
        updates['daily_api_limit'] = 0
    
    # Update password if provided
    new_password = request.form.get('password', '').strip()
    if new_password:
        updates['password'] = new_password
    
    if update_user(user_id, **updates):
        users = load_users_from_db()
        flash('User updated successfully.', 'success')
    else:
        flash('Error updating user.', 'danger')
    
    return redirect(url_for('admin_users_manage'))

@app.route('/admin/users/delete/<int:user_id>')
@admin_required
def admin_delete_user(user_id):
    global users
    
    if user_id not in users or user_id == 1 or user_id == current_user.id:
        flash('Cannot delete this user.', 'danger')
        return redirect(url_for('admin_users_manage'))
    
    if delete_user(user_id):
        users = load_users_from_db()
        flash('User deleted successfully.', 'success')
    else:
        flash('Error deleting user.', 'danger')
    
    return redirect(url_for('admin_users_manage'))

@app.route("/admin/logs")
@admin_required
def admin_logs():
    logs = get_all_system_logs()
    return render_template("admin_logs.html", logs=logs[::-1])

@app.route("/admin/logs/clear", methods=["POST"])
@admin_required
def admin_clear_logs():
    if clear_all_system_logs():
        flash("All logs cleared.", "success")
    else:
        flash("Error clearing logs.", "danger")
    
    return redirect(url_for('admin_logs'))

@app.route("/admin/pool", methods=["GET", "POST"])
@admin_required
def admin_pool():
    settings = get_app_settings()
    
    if request.method == 'POST':
        if 'bulk_proxies' in request.form:
            text = request.form.get('bulk_proxies', '')
            provider = request.form.get('provider', 'manual')
            
            lines = [l.strip() for l in text.splitlines() if validate_proxy_format(l)]
            if lines:
                added = add_bulk_proxies(lines, provider)
                flash(f"Added {added} proxies to pool.", "success")
            else:
                flash("No valid proxies found.", "warning")
        
        elif 'clear_pool' in request.form:
            clear_target = request.form.get('clear_target', 'all')
            if clear_proxy_pool(clear_target):
                flash(f"Pool cleared: {clear_target}.", "success")
            else:
                flash("Error clearing pool.", "danger")
        
        return redirect(url_for('admin_pool'))
    
    return render_template(
        'admin_pool.html',
        counts=get_pool_stats(),
        settings=settings,
        preview_py=get_pool_preview('pyproxy', 20),
        preview_pia=get_pool_preview('piaproxy', 20)
    )

@app.route("/admin/reset-system", methods=["POST"])
@admin_required
def admin_reset_system():
    update_setting("CONSECUTIVE_FAILS", "0")
    update_setting("SYSTEM_PAUSED", "FALSE")
    get_app_settings(force_refresh=True)
    flash("System reset successfully.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/toggle-maintenance", methods=["POST"])
@admin_required
def admin_toggle_maintenance():
    is_paused = str(get_app_settings().get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_paused else "TRUE"
    
    if update_setting("SYSTEM_PAUSED", new_state):
        get_app_settings(force_refresh=True)
        flash(f"Maintenance {'Activated' if new_state == 'TRUE' else 'Deactivated'}.", "success")
    else:
        flash("Error updating maintenance mode.", "danger")
    
    return redirect(url_for("admin"))

@app.route("/admin/toggle-force-fetch", methods=["POST"])
@admin_required
def admin_toggle_force_fetch():
    is_forced = str(get_app_settings().get("FORCE_FETCH_FOR_USERS", "FALSE")).upper() == "TRUE"
    new_state = "FALSE" if is_forced else "TRUE"
    
    if update_setting("FORCE_FETCH_FOR_USERS", new_state):
        get_app_settings(force_refresh=True)
        flash(f"Force fetch {'Activated' if new_state == 'TRUE' else 'Deactivated'}.", "success")
    else:
        flash("Error updating force fetch setting.", "danger")
    
    return redirect(url_for("admin"))

@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    if "save_announcement" in request.form:
        val = request.form.get("announcement_text", "").strip()
        update_setting("ANNOUNCEMENT", val)
        get_app_settings(force_refresh=True)
        flash("Announcement updated.", "success")
    
    return redirect(url_for("admin"))

@app.route("/delete-used-ip/<ip>")
@admin_required
def delete_used_ip_route(ip):
    if delete_used_ip(ip):
        flash("IP record deleted.", "success")
    else:
        flash("Error deleting IP record.", "danger")
    
    return redirect(url_for("admin"))

# --- ERROR HANDLERS ---

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='Page not found.'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error='Access forbidden.'), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {e}")
    return render_template('error.html', error='Server Error.'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {e}")
    return render_template('error.html', error='An unexpected error occurred.'), 500

# --- APPLICATION INITIALIZATION ---

if __name__ == "__main__":
    # Initialize default users
    init_default_users()
    
    # Load users into cache
    global users
    users = load_users_from_db()
    
    # Run Flask app
    app.run(host="0.0.0.0", port=5000, debug=False)
else:
    # For Vercel/WSGI deployment
    init_default_users()
    users = load_users_from_db()
