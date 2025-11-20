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
# --- Import FIRST_COMPLETED ---
from concurrent.futures import ThreadPoolExecutor, as_completed, FIRST_COMPLETED, wait
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys
from sheets_util import (
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
# MUST be defined before routes and login_manager
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-super-secret-key-in-production")
# --- END APP INITIALIZATION ---


# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app) # <-- Must be after app = Flask()
login_manager.login_view = 'login'
login_manager.login_message_category = "warning"

class User(UserMixin):
    def __init__(self, id, username, password, role="user"):
        self.id = id; self.username = username; self.password = password; self.role = role
    @property
    def is_admin(self): return self.role == "admin"

# TODO: Replace with a secure user store in a real application
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
# --- End Flask-Login Setup ---


def get_user_ip():
    """Get the user's real IP address from Vercel's request headers."""
    # Vercel uses 'X-Forwarded-For'
    ip = request.headers.get('X-Forwarded-For')
    if ip:
        # The header can contain a list, the first one is the client
        return ip.split(',')[0].strip()
    # Fallback for local development or other environments
    return request.remote_addr or "Unknown"


# Default configuration values
DEFAULT_SETTINGS = {
    "MAX_PASTE": 30, "FRAUD_SCORE_LEVEL": 0, "MAX_WORKERS": 5,
    "SCAMALYTICS_API_KEY": "YOUR_API_KEY_HERE",
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/",
    "SCAMALYTICS_USERNAME": "YOUR_USERNAME_HERE",
    "ANNOUNCEMENT": "",
    "API_CREDITS_USED": "N/A",
    "API_CREDITS_REMAINING": "N/A",
    "STRICT_FRAUD_SCORE_LEVEL": 20,
    "CONSECUTIVE_FAILS": 0,
    "SYSTEM_PAUSED": "FALSE",
    "ABC_GENERATION_URL": "" # <-- NEW SETTING
}

# --- CACHING SYSTEM FOR SETTINGS ---
# This prevents hitting Google Sheets for settings on every single request
# Fixes the "0/30" and "Admin URL not set" errors.
_SETTINGS_CACHE = None
_SETTINGS_CACHE_TIME = 0
CACHE_DURATION = 300 # 5 Minutes

def get_app_settings(force_refresh=False):
    """Fetches settings with in-memory caching."""
    global _SETTINGS_CACHE, _SETTINGS_CACHE_TIME
    
    # Use cache if available, fresh, and not forced to refresh
    if not force_refresh and _SETTINGS_CACHE and (time.time() - _SETTINGS_CACHE_TIME < CACHE_DURATION):
        return _SETTINGS_CACHE

    # If we need to fetch
    try:
        sheet_settings = get_settings() # Fetch from sheets
    except:
        sheet_settings = {}
    
    # Merge with defaults to ensure no missing keys
    final_settings = DEFAULT_SETTINGS.copy()
    final_settings.update(sheet_settings)
    
    # Ensure correct data types for numbers
    try:
        final_settings["MAX_PASTE"] = int(final_settings["MAX_PASTE"])
        final_settings["FRAUD_SCORE_LEVEL"] = int(final_settings["FRAUD_SCORE_LEVEL"])
        final_settings["STRICT_FRAUD_SCORE_LEVEL"] = int(final_settings["STRICT_FRAUD_SCORE_LEVEL"])
        final_settings["MAX_WORKERS"] = int(final_settings["MAX_WORKERS"])
        final_settings["CONSECUTIVE_FAILS"] = int(final_settings.get("CONSECUTIVE_FAILS", 0))
    except: pass

    # Update Cache
    _SETTINGS_CACHE = final_settings
    _SETTINGS_CACHE_TIME = time.time()
    
    return final_settings


# User agents for requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
]

# Request settings
REQUEST_TIMEOUT = 5; MIN_DELAY = 0.5; MAX_DELAY = 1.5

def parse_api_credentials(settings):
    """
    Parses comma-separated keys, usernames, and URLs from settings into a list of dicts.
    """
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
    """Validate proxy format: host:port:username:password"""
    try:
        parts = proxy_line.strip().split(":")
        if len(parts) == 4 and all(part for part in parts):
            return True
        return False
    except Exception as e:
        logger.error(f"Error validating proxy format '{proxy_line}': {e}")
        return False

def get_ip_from_proxy(proxy_line):
    """Extract public IP address using the provided proxy via ipv4.icanhazip.com."""
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

        ip_check_url = "https://ipv4.icanhazip.com"

        response = session.get(
            ip_check_url,
            proxies=proxy_dict,
            timeout=REQUEST_TIMEOUT - 1,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        response.raise_for_status()
        ip = response.text.strip()

        if ip and '.' in ip and len(ip.split('.')) == 4:
            return ip
        else:
            logger.warning(f"Invalid IP format received from {ip_check_url} for {proxy_line}: {ip}")
            return None
    except Exception as e:
        logger.error(f"❌ Unexpected error getting IP from proxy {proxy_line}: {e}", exc_info=False)
        return None

def get_fraud_score_detailed(ip, proxy_line, credentials_list):
    """
    Get detailed fraud score report via Scamalytics v3 API.
    """
    if not validate_proxy_format(proxy_line): return None
    if not ip: return None
    
    if not credentials_list:
        logger.error("No API credentials available to check score.")
        return None

    for idx, cred in enumerate(credentials_list):
        api_key = cred['key']
        api_user = cred['user']
        api_url = cred['url']

        try:
            host, port, user, pw = proxy_line.strip().split(":")
            proxy_url = f"http://{user}:{pw}@{host}:{port}"
            proxies = { "http": proxy_url, "https": proxy_url }
            session = requests.Session()
            retries = Retry(total=1, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
            session.mount('http://', HTTPAdapter(max_retries=retries))
            session.mount('https://', HTTPAdapter(max_retries=retries))

            url = f"{api_url.rstrip('/')}/{api_user}/?key={api_key}&ip={ip}"
            headers = { "User-Agent": random.choice(USER_AGENTS), "Accept": "application/json", }

            response = session.get(url, headers=headers, proxies=proxies, timeout=REQUEST_TIMEOUT)

            if response.status_code == 200:
                try:
                    data = response.json()
                    scam_block = data.get("scamalytics", {})
                    if scam_block.get("status") == "error" and scam_block.get("error") == "out of credits":
                        msg = f"⚠️ API Key for user '{api_user}' is OUT OF CREDITS. Rotating to next key."
                        logger.warning(msg)
                        add_log_entry("WARNING", msg, ip="System") 
                        continue 
                    return data 
                except requests.exceptions.JSONDecodeError:
                    logger.error(f"JSON decode error checking IP {ip}")
                    continue 
            else:
                logger.error(f"API request failed (HTTP {response.status_code})")
        except Exception as e:
             logger.error(f"⚠️ Unexpected error checking API for IP {ip}: {e}")
             continue 
    
    return None

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, is_strict_mode=False):
    """
    Checks a single proxy with detailed criteria, extracts geo info + score.
    """
    mode_prefix = "[Strict] " if is_strict_mode else ""
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    base_result = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None}

    if not validate_proxy_format(proxy_line):
        return base_result

    ip = get_ip_from_proxy(proxy_line)
    base_result["ip"] = ip
    if not ip:
        return base_result

    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)

    if data and data.get("credits"):
        base_result["credits"] = data.get("credits")

    try:
        ext_sources = data.get("external_datasources", {}) if data else {}
        geo_data = {}

        if ext_sources.get("maxmind_geolite2"):
            mm_data = ext_sources["maxmind_geolite2"]
            if "PREMIUM" not in mm_data.get("ip_country_code", ""):
                geo_data = {
                    "country_code": mm_data.get("ip_country_code", "N/A"),
                    "state": mm_data.get("ip_state_name", "N/A"),
                    "city": mm_data.get("ip_city", "N/A"),
                    "postcode": mm_data.get("ip_postcode", "N/A")
                }

        if not geo_data and ext_sources.get("dbip"):
            dbip_data = ext_sources["dbip"]
            if "PREMIUM" not in dbip_data.get("ip_country_code", ""):
                geo_data = {
                    "country_code": dbip_data.get("ip_country_code", "N/A"),
                    "state": dbip_data.get("ip_state_name", "N/A"),
                    "city": dbip_data.get("ip_city", "N/A"),
                    "postcode": dbip_data.get("ip_postcode", "N/A")
                }

        if not geo_data:
             base_result["geo"] = {"country_code": "N/A", "state": "N/A", "city": "N/A", "postcode": "N/A"}
        else:
             base_result["geo"] = geo_data

    except Exception as e:
        base_result["geo"] = {"country_code": "ERR", "state": "ERR", "city": "ERR", "postcode": "ERR"}

    score_val = None
    score_int = None
    if data and data.get("scamalytics"):
        scam_data = data.get("scamalytics", {})
        score_val = scam_data.get("scamalytics_score")
        base_result["score"] = score_val 

        if scam_data.get("status") != "ok":
            return base_result 

        try:
            passed = True
            if score_val is None:
                passed = False
            else:
                try:
                    score_int = int(score_val)
                    base_result["score"] = score_int 
                except (ValueError, TypeError):
                    passed = False

            if passed and not (score_int <= fraud_score_level):
                passed = False

            if passed and is_strict_mode:
                if passed and not (scam_data.get("scamalytics_risk") == "low"):
                    passed = False

                if passed:
                    proxy_flags = scam_data.get("scamalytics_proxy", {})
                    scam_flags_to_check = ["is_datacenter", "is_vpn", "is_apple_icloud_private_relay", "is_amazon_aws", "is_google"]
                    for flag in scam_flags_to_check:
                        if proxy_flags.get(flag) is True:
                            passed = False
                            break

                if passed and scam_data.get("is_blacklisted_external") is True:
                     passed = False

            if passed:
                base_result["proxy"] = proxy_line 
                return base_result
            else:
                if score_int is not None and score_int > fraud_score_level:
                    try: log_bad_proxy(proxy_line, ip, score_int)
                    except Exception: pass
                return base_result

        except Exception as e:
            return base_result 

    else:
        return base_result


@app.before_request
def before_request_func():
    if request.path.startswith(('/static', '/login', '/logout')) or \
       request.path.endswith(('.ico', '.png')) or \
       request.path == url_for('admin_test'):
        return
    pass 


# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin') if current_user.is_admin else url_for('index'))
    
    user_ip = get_user_ip()
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        user_to_login = next((user for uid, user in users.items() if user.username == username), None)

        if user_to_login and user_to_login.password == password:
            login_user(user_to_login, remember=remember)
            next_page = request.args.get('next')
            if next_page and not current_user.is_admin and ('/admin' in next_page or '/delete-used-ip' in next_page):
                 flash("Redirecting to user dashboard.", "info")
                 next_page = url_for('index')
            if current_user.is_admin and next_page == url_for('index'):
                 next_page = url_for('admin')
            add_log_entry("INFO", f"User '{username}' logged in successfully.", ip=user_ip)
            return redirect(next_page or (url_for('admin') if current_user.is_admin else url_for('index')))
        else:
            add_log_entry("WARNING", f"Failed login attempt for username: '{username}'", ip=user_ip)
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    user_ip = get_user_ip() 
    username = current_user.username 
    logout_user()
    flash('You have been logged out successfully.', 'info')
    add_log_entry("INFO", f"User '{username}' logged out.", ip=user_ip)
    return redirect(url_for('login'))


# --- NEW ROUTE: Fetch ABC Proxies ---
@app.route('/api/fetch-abc-proxies')
@login_required
def fetch_abc_proxies():
    """Fetches proxies from the URL saved in settings."""
    # Use cached settings to avoid rate limiting
    settings = get_app_settings()
    generation_url = settings.get("ABC_GENERATION_URL", "").strip()

    if not generation_url:
        return jsonify({"status": "error", "message": "ABC Generation URL not set in Admin Settings."})

    try:
        # Request the proxies from the URL
        response = requests.get(generation_url, timeout=10)
        
        if response.status_code == 200:
            content = response.text.strip()
            
            # Check if content looks like an error or empty
            if not content or "{" in content: # Simple check if it returned JSON error instead of text list
                 try:
                     json_data = response.json()
                     if json_data.get("code") != 0 and json_data.get("code") != "success":
                          return jsonify({"status": "error", "message": f"ABC API Error: {json_data}"})
                 except:
                     pass 

            lines = [line.strip() for line in content.splitlines() if line.strip()]
            
            if not lines:
                 return jsonify({"status": "error", "message": "ABC Proxy API returned empty result."})

            return jsonify({"status": "success", "proxies": lines})
        else:
            return jsonify({"status": "error", "message": f"ABC API HTTP Error: {response.status_code}"})
            
    except Exception as e:
        logger.error(f"Error fetching ABC proxies: {e}")
        return jsonify({"status": "error", "message": f"Server Error: {str(e)}"})
# --- END NEW ROUTE ---


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    try:
        # Use cached settings
        settings = get_app_settings()
    except Exception as e:
        logger.critical(f"CRITICAL ERROR getting app settings on index page: {e}", exc_info=True)
        add_log_entry("CRITICAL", f"Failed to load settings on index: {str(e)[:50]}", ip=get_user_ip())
        return render_template("error.html", error="Could not load critical application settings."), 500

    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    api_credentials = parse_api_credentials(settings)
    
    announcement = settings.get("ANNOUNCEMENT")
    system_paused = str(settings.get("SYSTEM_PAUSED", "FALSE")).upper() == "TRUE"
    
    results = None 
    message = None
    user_ip = get_user_ip() 

    if system_paused:
        message = "⚠️ System Paused: Too many consecutive failures. Please contact admin."

    if request.method == "POST":
        if system_paused:
             flash("System is currently paused for maintenance. Please contact admin.", "danger")
             return render_template("index.html", results=None, message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement, system_paused=True)

        start_time = time.time()
        proxies_input = []
        input_count = 0
        truncation_warning = ""
        results = [] 

        if 'proxytext' in request.form and request.form.get("proxytext", "").strip():
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            input_count = len(all_lines)
            
            if input_count > MAX_PASTE:
                truncation_warning = f" Input text truncated to first {MAX_PASTE} lines."
                proxies_input = all_lines[:MAX_PASTE]
            else:
                proxies_input = all_lines

            logger.info(f"Received {input_count} proxies via text area.")
        else:
            message = "No proxies submitted. Please paste proxies."
            return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement, system_paused=system_paused)

        # Load Caches
        used_ips_list = set()
        used_proxy_cache = set()
        bad_proxy_cache = set()
        cache_load_warnings = []
        try:
            used_ips_records = get_all_used_ips()
            used_ips_list = {str(r.get('IP')).strip() for r in used_ips_records if r.get('IP')}
            used_proxy_cache = {r.get('Proxy') for r in used_ips_records if r.get('Proxy')}
            logger.info(f"Loaded {len(used_ips_list)} used IPs and {len(used_proxy_cache)} used proxies from cache.")
        except Exception as e:
            logger.error(f"Error loading used proxy cache: {e}")
            cache_load_warnings.append("Could not load used proxy cache.")
        try:
            bad_proxy_cache = set(get_bad_proxies_list())
            logger.info(f"Loaded {len(bad_proxy_cache)} bad proxies from cache.")
        except Exception as e:
            logger.error(f"Error loading bad proxy cache: {e}")
            cache_load_warnings.append("Could not load bad proxy cache.")
        if cache_load_warnings:
             message = "Warning: " + " ".join(cache_load_warnings)

        proxies_to_check = []
        invalid_format_proxies = []
        used_count_prefilter = 0
        bad_count_prefilter = 0
        unique_proxies_input = {p.strip() for p in proxies_input if p.strip()}
        logger.info(f"Processing {len(unique_proxies_input)} unique non-empty input lines.")

        for proxy in unique_proxies_input:
            if not validate_proxy_format(proxy):
                invalid_format_proxies.append(proxy)
                continue
            if proxy in used_proxy_cache:
                used_count_prefilter += 1
                continue
            if proxy in bad_proxy_cache:
                bad_count_prefilter += 1
                continue
            proxies_to_check.append(proxy)

        processed_count = len(proxies_to_check)
        logger.info(f"Prefiltering complete. {processed_count} proxies remaining.")

        good_proxy_results = []
        target_good_proxies = 2 
        futures = set()
        cancelled_count = 0
        last_credits = {} 

        if proxies_to_check:
            actual_workers = min(MAX_WORKERS, processed_count)
            logger.info(f"Starting detailed check for {processed_count} proxies using {actual_workers} workers...")
            with ThreadPoolExecutor(max_workers=actual_workers) as executor:
                for proxy in proxies_to_check:
                    futures.add(executor.submit(single_check_proxy_detailed, proxy, FRAUD_SCORE_LEVEL, api_credentials, is_strict_mode=True)) 

                while futures:
                    done, futures = wait(futures, return_when=FIRST_COMPLETED)
                    for future in done:
                        try:
                            result = future.result() 
                            if result:
                                if result.get("credits"):
                                    last_credits = result.get("credits")

                                if result.get("proxy"):
                                    ip_clean = str(result.get('ip')).strip()
                                    result['used'] = ip_clean in used_ips_list
                                    
                                    good_proxy_results.append(result)

                                    if len([r for r in good_proxy_results if not r['used']]) >= target_good_proxies:
                                        logger.info(f"Target of {target_good_proxies} usable proxies reached. Cancelling remaining tasks.")
                                        for f in futures:
                                            if f.cancel(): cancelled_count += 1
                                        futures = set() 
                                        break 

                        except Exception as exc:
                            logger.error(f'A proxy check task generated an exception: {exc}', exc_info=False)

                    if not futures: 
                        break

            logger.info(f"Finished checking. Found {len(good_proxy_results)} potential good proxies.")
        else:
            logger.info("No valid proxies left to check after prefiltering.")


        unique_results = []
        seen_ips = set()
        for res in good_proxy_results:
            if res.get('ip') and res.get('ip') not in seen_ips:
                seen_ips.add(res['ip'])
                unique_results.append(res)
        
        final_results_display = sorted(unique_results, key=lambda x: x['used'])

        good_count_final = len([r for r in final_results_display if not r['used']])
        used_count_final = len([r for r in final_results_display if r['used']])
        invalid_format_count = len(invalid_format_proxies)
        checks_attempted = processed_count - cancelled_count

        try:
            current_fails = settings.get("CONSECUTIVE_FAILS", 0)
            
            if good_count_final > 0:
                if current_fails > 0:
                    update_setting("CONSECUTIVE_FAILS", "0")
                    # Update cache immediately
                    if _SETTINGS_CACHE: _SETTINGS_CACHE["CONSECUTIVE_FAILS"] = 0
                    logger.info("Good proxies found. Resetting consecutive failure counter to 0.")
            
            elif checks_attempted > 0:
                new_fails = current_fails + checks_attempted
                update_setting("CONSECUTIVE_FAILS", str(new_fails))
                logger.warning(f"Batch failed. Consecutive failures updated: {current_fails} -> {new_fails}")
                
                if new_fails > 1000:
                    logger.critical(f"CRITICAL: Consecutive failures ({new_fails}) exceeded 1000. PAUSING SYSTEM.")
                    update_setting("SYSTEM_PAUSED", "TRUE")
                    add_log_entry("CRITICAL", f"System PAUSED due to {new_fails} consecutive failed checks.", ip=user_ip)
                    system_paused = True
                    message = "⚠️ System Paused: Too many consecutive failures. Please contact admin."

        except Exception as e:
            logger.error(f"Error updating consecutive failure logic: {e}")

        try:
            add_api_usage_log(
                username=current_user.username,
                ip=user_ip,
                submitted_count=input_count,
                api_calls_count=checks_attempted
            )
        except Exception as e:
            logger.error(f"Failed to log API usage for user {current_user.username}: {e}")

        format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
        prefilter_msg = ""
        if used_count_prefilter > 0 or bad_count_prefilter > 0:
             prefilter_msg = f" (Skipped {used_count_prefilter} from used cache, {bad_count_prefilter} from bad cache)."
        cancel_msg = ""
        if cancelled_count > 0:
            cancel_msg = f" Stopped early after finding {good_count_final} usable proxies (checked {checks_attempted})."

        if good_count_final > 0 or used_count_final > 0:
            base_message = f"✅ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). Found {good_count_final} unique usable proxies ({used_count_final} previously used IPs found)."
            add_log_entry("INFO", f"Checker run by {current_user.username}. Found {good_count_final} usable proxies.", ip=user_ip)
        else:
             base_message = f"⚠️ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). No new usable proxies found."
             add_log_entry("WARNING", f"Checker run by {current_user.username}. Found no usable proxies in batch.", ip=user_ip)

        full_message = base_message + truncation_warning + prefilter_msg + cancel_msg
        message = (message + " " + full_message) if message else full_message

        results = final_results_display
        end_time = time.time()
        logger.info(f"Request processing took {end_time - start_time:.2f} seconds.")

    return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement, system_paused=system_paused)


@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    data = request.get_json()
    proxy_line = data.get("proxy") if data else None
    ip = data.get("ip") if data else None 
    user_ip = get_user_ip()

    if not proxy_line or not ip or ip in ('N/A', 'ERR'): 
        logger.warning(f"Track-used request received without proxy or a valid IP. Proxy: {proxy_line}, IP: {ip}")
        return jsonify({"status": "error", "message": "Invalid request data (missing or invalid IP)"}), 400

    if not validate_proxy_format(proxy_line):
        logger.warning(f"Track-used request received with invalid proxy format: {proxy_line}")
        return jsonify({"status": "error", "message": "Invalid proxy format"}), 400

    try:
        if add_used_ip(ip, proxy_line):
            logger.info(f"Successfully marked IP {ip} as used for proxy: {proxy_line}")
            add_log_entry("INFO", f"Proxy marked as used by {current_user.username}: {ip}", ip=user_ip)
            return jsonify({"status": "success"})
        else:
            logger.error(f"Failed to add used IP/Proxy to Google Sheet: {proxy_line} (IP: {ip})")
            add_log_entry("ERROR", f"Failed to log used proxy {ip} for {current_user.username}.", ip=user_ip)
            return jsonify({"status": "error", "message": "Failed to update usage status"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in /track-used for proxy '{proxy_line}': {e}", exc_info=True)
        add_log_entry("ERROR", f"Exception in track-used for {proxy_line}: {str(e)[:50]}", ip=user_ip)
        return jsonify({"status": "error", "message": "Internal server error during usage tracking"}), 500


@app.route("/admin")
@admin_required
def admin():
    user_ip = get_user_ip()
    try:
        # Use Cached Settings
        settings = get_app_settings()

        total_api_calls = 0
        try:
            usage_logs = get_all_api_usage_logs()
            for log in usage_logs:
                total_api_calls += int(log.get("API Calls Made") or 0)
        except Exception as e:
            logger.error(f"Failed to calculate total API calls: {e}")
            total_api_calls = "Error"
        
        stats = {
            "max_paste": settings["MAX_PASTE"],
            "fraud_score_level": settings["FRAUD_SCORE_LEVEL"],
            "strict_fraud_score_level": settings.get("STRICT_FRAUD_SCORE_LEVEL", "N/A"),
            "max_workers": settings["MAX_WORKERS"],
            "scamalytics_api_key": settings["SCAMALYTICS_API_KEY"],
            "scamalytics_api_url": settings["SCAMALYTICS_API_URL"],
            "scamalytics_username": settings["SCAMALYTICS_USERNAME"],
            "api_credits_used": settings.get("API_CREDITS_USED", "N/A"),
            "api_credits_remaining": settings.get("API_CREDITS_REMAINING", "N/A"),
            "total_api_calls_logged": total_api_calls,
            "consecutive_fails": settings.get("CONSECUTIVE_FAILS", 0),
            "system_paused": settings.get("SYSTEM_PAUSED", "FALSE"),
            "abc_generation_url": settings.get("ABC_GENERATION_URL", "Not Set")
        }
        used_ips = get_all_used_ips() 
        announcement = settings.get("ANNOUNCEMENT")
        return render_template(
            "admin.html",
            stats=stats,
            used_ips=used_ips,
            announcement=announcement
            )
    except Exception as e:
        logger.error(f"Error loading admin panel: {e}", exc_info=True)
        add_log_entry("ERROR", f"Failed to load admin panel: {str(e)[:50]}", ip=user_ip)
        flash("Error loading admin panel data. Please check logs.", "danger")
        stats_error = { 
            "api_credits_used": "Error", 
            "api_credits_remaining": "Error",
            "total_api_calls_logged": "Error",
            "consecutive_fails": "Error",
            "system_paused": "Error",
             "abc_generation_url": "Error"
        }
        return render_template("admin.html", stats=stats_error, used_ips=[], announcement="")


@app.route("/admin/reset-system", methods=["POST"])
@admin_required
def admin_reset_system():
    user_ip = get_user_ip()
    try:
        update_setting("CONSECUTIVE_FAILS", "0")
        update_setting("SYSTEM_PAUSED", "FALSE")
        
        # Force refresh cache so UI updates immediately
        get_app_settings(force_refresh=True)
        
        flash("System successfully reset and unpaused.", "success")
        logger.info(f"Admin '{current_user.username}' reset and unpaused the system.")
        add_log_entry("INFO", f"System Unpaused by {current_user.username}.", ip=user_ip)
    except Exception as e:
        logger.error(f"Error resetting system: {e}")
        flash("Failed to reset system settings.", "danger")
    
    return redirect(url_for("admin"))


@app.route("/admin/logs")
@admin_required
def admin_logs():
    user_ip = get_user_ip()
    try:
        logs = get_all_system_logs()
        add_log_entry("INFO", f"Admin '{current_user.username}' viewed system logs.", ip=user_ip)
        return render_template("admin_logs.html", logs=logs[::-1])
    except Exception as e:
        logger.error(f"Error loading admin logs page: {e}", exc_info=True)
        add_log_entry("CRITICAL", f"Failed to load system logs: {str(e)[:50]}", ip=user_ip)
        flash("Error loading system logs. Check logs for details.", "danger")
        return render_template("admin_logs.html", logs=[])


@app.route("/admin/clear-logs", methods=["POST"])
@admin_required
def admin_clear_logs():
    user_ip = get_user_ip() 
    try:
        if clear_all_system_logs(): 
            flash("Successfully cleared all system logs.", "success")
            logger.info(f"Admin '{current_user.username}' cleared all system logs.")
            add_log_entry("WARNING", f"All system logs cleared by {current_user.username}", ip=user_ip)
        else:
            flash("Failed to clear system logs. Check server logs.", "danger")
            add_log_entry("ERROR", f"Failed attempt to clear logs by {current_user.username}", ip=user_ip)
    except Exception as e:
        logger.error(f"Error in admin_clear_logs route: {e}", exc_info=True)
        flash("An unexpected error occurred while clearing logs.", "danger")
        add_log_entry("CRITICAL", f"Exception in admin_clear_logs: {str(e)[:50]}", ip=user_ip)
    return redirect(url_for("admin_logs"))


@app.route("/admin/test", methods=["GET", "POST"])
@admin_required
def admin_test():
    try:
        settings = get_app_settings()
    except Exception as e:
        logger.critical(f"CRITICAL ERROR getting app settings for admin test: {e}", exc_info=True)
        add_log_entry("CRITICAL", f"Failed to load settings on admin/test: {str(e)[:50]}", ip=get_user_ip())
        return render_template("error.html", error="Could not load critical application settings."), 500

    MAX_PASTE = settings["MAX_PASTE"] 
    STRICT_FRAUD_SCORE_LEVEL = settings["STRICT_FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    api_credentials = parse_api_credentials(settings)

    results = None
    message = None
    user_ip = get_user_ip() 

    if request.method == "GET":
         return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)

    start_time = time.time()
    proxies_input = []
    input_count = 0
    truncation_warning = ""
    results = []

    if 'proxytext' in request.form and request.form.get("proxytext", "").strip():
        proxytext = request.form.get("proxytext", "")
        all_lines = proxytext.strip().splitlines()
        input_count = len(all_lines)
        
        if input_count > MAX_PASTE:
            truncation_warning = f" Input text truncated to first {MAX_PASTE} lines."
            proxies_input = all_lines[:MAX_PASTE]
        else:
            proxies_input = all_lines
        
        logger.info(f"[Strict] Received {input_count} proxies via text area.")
    else: message = "No proxies submitted."; return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)


    used_ips_list = set(); used_proxy_cache = set(); bad_proxy_cache = set(); cache_load_warnings = []
    try: used_ips_records = get_all_used_ips(); used_ips_list = {str(r.get('IP')).strip() for r in used_ips_records if r.get('IP')}; used_proxy_cache = {r.get('Proxy') for r in used_ips_records if r.get('Proxy')}; logger.info(f"[Strict] Loaded {len(used_ips_list)} used IPs and {len(used_proxy_cache)} used proxies.")
    except Exception as e: logger.error(f"[Strict] Error loading used proxy cache: {e}"); cache_load_warnings.append("Could not load used proxy cache.")
    try: bad_proxy_cache = set(get_bad_proxies_list()); logger.info(f"[Strict] Loaded {len(bad_proxy_cache)} bad proxies.")
    except Exception as e: logger.error(f"[Strict] Error loading bad proxy cache: {e}"); cache_load_warnings.append("Could not load bad proxy cache.")
    if cache_load_warnings: message = "Warning: " + " ".join(cache_load_warnings)

    proxies_to_check = []; invalid_format_proxies = []; used_count_prefilter = 0; bad_count_prefilter = 0
    unique_proxies_input = {p.strip() for p in proxies_input if p.strip()}
    logger.info(f"[Strict] Processing {len(unique_proxies_input)} unique non-empty input lines.")
    for proxy in unique_proxies_input:
        if not validate_proxy_format(proxy): invalid_format_proxies.append(proxy); continue
        if proxy in used_proxy_cache: used_count_prefilter += 1; continue
        if proxy in bad_proxy_cache: bad_count_prefilter += 1; continue
        proxies_to_check.append(proxy)
    processed_count = len(proxies_to_check)
    logger.info(f"[Strict] Prefiltering complete. {processed_count} proxies remaining.")

    good_proxy_results = []
    target_good_proxies = 2 
    futures = set()
    cancelled_count = 0 
    last_credits = {}
    
    if proxies_to_check:
        actual_workers = min(MAX_WORKERS, processed_count)
        logger.info(f"[Strict] Starting check for {processed_count} proxies using {actual_workers} workers...")
        add_log_entry("INFO", f"Strict test started by {current_user.username} for {processed_count} proxies.", ip=user_ip)
        
        with ThreadPoolExecutor(max_workers=actual_workers) as executor:
            for proxy in proxies_to_check:
                futures.add(executor.submit(single_check_proxy_detailed, proxy, STRICT_FRAUD_SCORE_LEVEL, api_credentials, is_strict_mode=True))
            
            while futures:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        result = future.result()
                        if result:
                            if result.get("credits"): 
                                last_credits = result.get("credits")
                            if result.get("proxy"):
                                ip_clean = str(result.get('ip')).strip()
                                result['used'] = ip_clean in used_ips_list
                                good_proxy_results.append(result)

                                if len([r for r in good_proxy_results if not r['used']]) >= target_good_proxies:
                                    logger.info(f"[Strict] Target of {target_good_proxies} usable proxies reached. Cancelling remaining tasks.")
                                    for f in futures:
                                        if f.cancel(): cancelled_count += 1
                                    futures = set() 
                                    break # Exit inner loop
                                    
                    except Exception as exc: 
                        logger.error(f'[Strict] A proxy check task generated an exception: {exc}', exc_info=False)
                
                if not futures: 
                    break

        logger.info(f"[Strict] Finished checking. Found {len(good_proxy_results)} proxies passing strict filter.")
    else: 
        logger.info("[Strict] No valid proxies left to check after prefiltering.")


    credit_msg = ""
    if last_credits:
        try:
            used = last_credits.get("used", "N/A"); remaining = last_credits.get("remaining", "N/A")
            if used != "N/A" and remaining != "N/A":
                update_used_ok = update_setting("API_CREDITS_USED", str(used))
                update_remaining_ok = update_setting("API_CREDITS_REMAINING", str(remaining))
                if update_used_ok and update_remaining_ok: logger.info(f"Successfully updated API credits: Used={used}, Remaining={remaining}"); credit_msg = f" (API Credits Updated: {remaining} left)"
                else: logger.error("Failed to update API credit settings in Google Sheet."); credit_msg = " (Failed to update API credits in Sheet)"
            else: logger.warning("Credits block found, but 'used' or 'remaining' keys missing."); credit_msg = " (Could not parse API credits)"
        except Exception as e: logger.error(f"Error during API credit update process: {e}"); credit_msg = " (Error updating API credits)"
    elif processed_count > 0: logger.warning("No credit information returned from API."); credit_msg = " (Could not get API credit info)"

    unique_results = []
    seen_ips = set()
    for res in good_proxy_results:
        if res.get('ip') and res.get('ip') not in seen_ips:
            seen_ips.add(res['ip'])
            unique_results.append(res)
    
    final_results_display = sorted(unique_results, key=lambda x: x['used'])
    
    good_count_final = len([r for r in final_results_display if not r['used']])
    used_count_final = len([r for r in final_results_display if r['used']])
    invalid_format_count = len(invalid_format_proxies)
    
    checks_attempted = processed_count - cancelled_count 
    
    try:
        add_api_usage_log(
            username=current_user.username,
            ip=user_ip,
            submitted_count=input_count,
            api_calls_count=checks_attempted
        )
    except Exception as e:
        logger.error(f"Failed to log API usage for user {current_user.username}: {e}")

    format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
    prefilter_msg = f" (Skipped {used_count_prefilter} used, {bad_count_prefilter} bad cache)." if used_count_prefilter > 0 or bad_count_prefilter > 0 else ""

    cancel_msg = ""
    if cancelled_count > 0:
        cancel_msg = f" Stopped early after finding {good_count_final} usable proxies (checked {checks_attempted})."

    if good_count_final > 0 or used_count_final > 0: main_message = f"✅ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). Found {good_count_final} unique usable proxies passing strict filter ({used_count_final} used IPs found)."
    else: main_message = f"⚠️ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). No new usable proxies found passing strict filter."
    
    add_log_entry("INFO", f"Strict test finished by {current_user.username}. Found {good_count_final} good proxies. {credit_msg}", ip=user_ip)

    message = main_message + truncation_warning + prefilter_msg + credit_msg + cancel_msg
    message = ("Warning: " + " ".join(cache_load_warnings) + " " + message) if cache_load_warnings else message
    results = final_results_display
    end_time = time.time()
    logger.info(f"[Strict] Request processing took {end_time - start_time:.2f} seconds.")

    return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    """Admin settings page."""
    user_ip = get_user_ip()
    
    # Always start with current cached settings
    current_settings = get_app_settings()

    if request.method == "POST":
        form_settings = {}; error_msg = None
        try:
            # Validate form inputs
            form_settings["MAX_PASTE"] = int(request.form.get("max_paste", DEFAULT_SETTINGS["MAX_PASTE"]))
            form_settings["FRAUD_SCORE_LEVEL"] = int(request.form.get("fraud_score_level", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]))
            form_settings["STRICT_FRAUD_SCORE_LEVEL"] = int(request.form.get("strict_fraud_score_level", DEFAULT_SETTINGS["STRICT_FRAUD_SCORE_LEVEL"]))
            form_settings["MAX_WORKERS"] = int(request.form.get("max_workers", DEFAULT_SETTINGS["MAX_WORKERS"]))
            form_settings["SCAMALYTICS_API_KEY"] = request.form.get("scamalytics_api_key", "").strip()
            form_settings["SCAMALYTICS_API_URL"] = request.form.get("scamalytics_api_url", "").strip()
            form_settings["SCAMALYTICS_USERNAME"] = request.form.get("scamalytics_username", "").strip()
            form_settings["ABC_GENERATION_URL"] = request.form.get("abc_generation_url", "").strip()

            if not (5 <= form_settings["MAX_PASTE"] <= 100): error_msg = "Max proxies must be between 5 and 100."
            elif not (0 <= form_settings["FRAUD_SCORE_LEVEL"] <= 100): error_msg = "User Fraud score must be between 0 and 100."
            elif not (0 <= form_settings["STRICT_FRAUD_SCORE_LEVEL"] <= 100): error_msg = "Strict Fraud score must be between 0 and 100."
            elif not (1 <= form_settings["MAX_WORKERS"] <= 100): error_msg = "Max workers must be between 1 and 100."
            
            keys_check = [k.strip() for k in form_settings["SCAMALYTICS_API_KEY"].split(',') if k.strip()]
            for k in keys_check:
                 if len(k) < 5: error_msg = f"API Key '{k}' seems too short."

        except ValueError: error_msg = "Invalid input: Score levels, Max Proxies, and Max Workers must be whole numbers."

        if not error_msg:
            logger.info("Attempting settings update via admin panel..."); success_count = 0
            settings_to_update = list(form_settings.items()) 
            
            for key, value in settings_to_update:
                # Slow down updates slightly to help rate limits, even with retry logic
                time.sleep(0.5) 
                if update_setting(key, str(value)): 
                    success_count += 1
                else: 
                    logger.error(f"Failed to update setting '{key}' in Google Sheet.")
            
            if success_count == len(settings_to_update): 
                logger.info("All settings updated successfully."); 
                flash("Settings updated successfully", "success"); 
                add_log_entry("INFO", f"Admin '{current_user.username}' updated settings.", ip=user_ip)
                
                # FORCE CACHE REFRESH so new settings appear immediately
                current_settings = get_app_settings(force_refresh=True) 
            else: 
                error_msg = f"Error saving settings: {len(settings_to_update) - success_count} update(s) failed. Check logs."; 
                flash(error_msg, "danger"); 
                add_log_entry("ERROR", f"Admin '{current_user.username}' failed to update settings.", ip=user_ip)
                current_settings.update(form_settings) 
        else: 
            flash(error_msg, "danger"); 
            current_settings.update(form_settings) 

    return render_template("admin_settings.html", settings=current_settings, message=None)


@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    user_ip = get_user_ip()
    try:
        if "save_announcement" in request.form:
            text = request.form.get("announcement_text", "").strip()
            if update_setting("ANNOUNCEMENT", text): 
                flash("Announcement updated successfully.", "success"); 
                logger.info(f"Admin '{current_user.username}' updated announcement.")
                add_log_entry("INFO", f"Admin '{current_user.username}' updated announcement.", ip=user_ip)
                get_app_settings(force_refresh=True) # Refresh cache
            else: 
                flash("Error saving announcement to Google Sheet. Check logs.", "danger"); 
                logger.error("Failed to save announcement to GSheet.")
                add_log_entry("ERROR", f"Admin '{current_user.username}' failed to save announcement.", ip=user_ip)
        elif "delete_announcement" in request.form:
            if update_setting("ANNOUNCEMENT", ""): 
                flash("Announcement cleared successfully.", "success"); 
                logger.info(f"Admin '{current_user.username}' cleared announcement.")
                add_log_entry("INFO", f"Admin '{current_user.username}' cleared announcement.", ip=user_ip)
                get_app_settings(force_refresh=True) # Refresh cache
            else: 
                flash("Error clearing announcement in Google Sheet. Check logs.", "danger"); 
                logger.error("Failed to clear announcement in GSheet.")
                add_log_entry("ERROR", f"Admin '{current_user.username}' failed to clear announcement.", ip=user_ip)
    except Exception as e: 
        logger.error(f"Error in admin_announcement route: {e}", exc_info=True); 
        add_log_entry("ERROR", f"Exception in admin_announcement: {str(e)[:50]}", ip=user_ip)
        flash("An unexpected error occurred while managing the announcement.", "danger")
    return redirect(url_for("admin"))


@app.route("/delete-used-ip/<ip>")
@admin_required
def delete_used_ip_route(ip):
    user_ip = get_user_ip()
    if not ip: flash("Invalid IP provided for deletion.", "warning"); return redirect(url_for("admin"))
    try:
        if delete_used_ip(ip): 
            flash(f"Successfully removed record for IP {ip}.", "success"); 
            logger.info(f"Admin '{current_user.username}' deleted used IP record: {ip}")
            add_log_entry("INFO", f"Admin '{current_user.username}' deleted used IP: {ip}", ip=user_ip)
        else: 
            flash(f"Could not delete record for IP {ip}. It might not exist or an error occurred.", "warning") 
            add_log_entry("WARNING", f"Admin '{current_user.username}' failed to delete IP: {ip}", ip=user_ip)
    except Exception as e: 
        logger.error(f"Unexpected error in delete_used_ip_route for IP {ip}: {e}", exc_info=True); 
        add_log_entry("ERROR", f"Exception deleting used IP {ip}: {str(e)[:50]}", ip=user_ip)
        flash("An server error occurred while trying to delete the record.", "danger")
    return redirect(url_for("admin"))


@app.errorhandler(404)
def page_not_found(e):
    user_ip = get_user_ip()
    logger.warning(f"404 Not Found access attempt: {request.path}")
    add_log_entry("WARNING", f"404 Not Found access at {request.path}", ip=user_ip)
    if current_user.is_authenticated:
        if request.path.endswith(('.ico', '.png', '.css', '.js')): return '', 404 
        return render_template('error.html', error=f'The requested page ({request.path}) was not found.'), 404
    else: flash("Page not found or access denied. Please log in.", "warning"); return redirect(url_for('login'))


@app.errorhandler(500)
def internal_server_error(e):
    user_ip = get_user_ip()
    logger.error(f"500 Internal Server Error processing request {request.path}: {e}", exc_info=True)
    add_log_entry("CRITICAL", f"500 Server Error at {request.path}: {str(e)[:50]}", ip=user_ip)
    return render_template('error.html', error='An internal server error occurred. The administrator has been notified.'), 500

# --- Main Execution ---
if __name__ == "__main__":
    add_log_entry("INFO", "Application server starting up.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
