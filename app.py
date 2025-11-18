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
    # --- NEW IMPORTS ---
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


# --- NEW: IP Helper Function ---
def get_user_ip():
    """Get the user's real IP address from Vercel's request headers."""
    # Vercel uses 'X-Forwarded-For'
    ip = request.headers.get('X-Forwarded-For')
    if ip:
        # The header can contain a list, the first one is the client
        return ip.split(',')[0].strip()
    # Fallback for local development or other environments
    return request.remote_addr or "Unknown"
# --- END NEW FUNCTION ---


# Default configuration values
DEFAULT_SETTINGS = {
    "MAX_PASTE": 30, "FRAUD_SCORE_LEVEL": 0, "MAX_WORKERS": 5,
    "SCAMALYTICS_API_KEY": "YOUR_API_KEY_HERE",
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/",
    "SCAMALYTICS_USERNAME": "YOUR_USERNAME_HERE",
    "ANNOUNCEMENT": "",
    "API_CREDITS_USED": "N/A",
    "API_CREDITS_REMAINING": "N/A",
    "STRICT_FRAUD_SCORE_LEVEL": 20 # <-- Default strict score
}

# User agents for requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
]

# Request settings
REQUEST_TIMEOUT = 5; MIN_DELAY = 0.5; MAX_DELAY = 1.5


# --- HELPER FUNCTIONS ---

def get_app_settings():
    """Fetches settings from Google Sheet, providing defaults."""
    settings = get_settings() # Fetch from sheets_util
    # Apply defaults if settings are missing from the sheet
    return {
        "MAX_PASTE": int(settings.get("MAX_PASTE", DEFAULT_SETTINGS["MAX_PASTE"])),
        "FRAUD_SCORE_LEVEL": int(settings.get("FRAUD_SCORE_LEVEL", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"])),
        "STRICT_FRAUD_SCORE_LEVEL": int(settings.get("STRICT_FRAUD_SCORE_LEVEL", DEFAULT_SETTINGS["STRICT_FRAUD_SCORE_LEVEL"])),
        "MAX_WORKERS": int(settings.get("MAX_WORKERS", DEFAULT_SETTINGS["MAX_WORKERS"])),
        "SCAMALYTICS_API_KEY": settings.get("SCAMALYTICS_API_KEY", DEFAULT_SETTINGS["SCAMALYTICS_API_KEY"]),
        "SCAMALYTICS_API_URL": settings.get("SCAMALYTICS_API_URL", DEFAULT_SETTINGS["SCAMALYTICS_API_URL"]),
        "SCAMALYTICS_USERNAME": settings.get("SCAMALYTICS_USERNAME", DEFAULT_SETTINGS["SCAMALYTICS_USERNAME"]),
        "ANNOUNCEMENT": settings.get("ANNOUNCEMENT", DEFAULT_SETTINGS["ANNOUNCEMENT"]),
        "API_CREDITS_USED": settings.get("API_CREDITS_USED", DEFAULT_SETTINGS["API_CREDITS_USED"]),
        "API_CREDITS_REMAINING": settings.get("API_CREDITS_REMAINING", DEFAULT_SETTINGS["API_CREDITS_REMAINING"])
    }

def parse_api_credentials(settings):
    """
    Parses comma-separated keys, usernames, and URLs from settings into a list of dicts.
    Handles cases where one URL might be used for multiple keys.
    """
    raw_keys = settings.get("SCAMALYTICS_API_KEY", "")
    raw_users = settings.get("SCAMALYTICS_USERNAME", "")
    raw_urls = settings.get("SCAMALYTICS_API_URL", "")

    keys = [k.strip() for k in raw_keys.split(',') if k.strip()]
    users = [u.strip() for u in raw_users.split(',') if u.strip()]
    urls = [u.strip() for u in raw_urls.split(',') if u.strip()]

    if not keys: return []

    # If only one user/url provided but multiple keys, use it for all
    if len(users) == 1 and len(keys) > 1: users = users * len(keys)
    if len(urls) == 1 and len(keys) > 1: urls = urls * len(keys)

    credentials = []
    # Zip stops at the shortest list, so ensure you provide enough for all keys
    for k, u, url in zip(keys, users, urls):
        credentials.append({"key": k, "user": u, "url": url})
    
    return credentials

def validate_proxy_format(proxy_line):
    """Validate proxy format: host:port:username:password"""
    try:
        parts = proxy_line.strip().split(":")
        # Ensure exactly 4 non-empty parts
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
            "https": f"http://{user}:{pw}@{host}:{port}" # Use http tunnel for https
        }
        # Use a session with retries for robustness
        session = requests.Session()
        retries = Retry(total=1, backoff_factor=0.2, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        # --- UPDATED URL ---
        ip_check_url = "https://ipv4.icanhazip.com"
        # --- END UPDATE ---

        response = session.get(
            ip_check_url,
            proxies=proxy_dict,
            timeout=REQUEST_TIMEOUT - 1, # Slightly less than worker timeout
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        ip = response.text.strip()

        # Basic IP format validation
        if ip and '.' in ip and len(ip.split('.')) == 4:
            return ip
        else:
            logger.warning(f"Invalid IP format received from {ip_check_url} for {proxy_line}: {ip}")
            return None
    except requests.exceptions.Timeout:
        logger.error(f"❌ Timeout getting IP from proxy {proxy_line} using {ip_check_url}")
        return None
    except requests.exceptions.ProxyError as pe:
         logger.error(f"❌ Proxy error getting IP from proxy {proxy_line} using {ip_check_url}: {pe}")
         return None
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Network error getting IP from proxy {proxy_line} using {ip_check_url}: {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Unexpected error getting IP from proxy {proxy_line} using {ip_check_url}: {e}", exc_info=False)
        return None

def get_fraud_score_detailed(ip, proxy_line, credentials_list):
    """
    Get detailed fraud score report via Scamalytics v3 API. 
    Iterates through the provided credentials list if 'out of credits' occurs.
    Returns full response dict or None.
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
                    
                    # --- CHECK FOR OUT OF CREDITS ---
                    scam_block = data.get("scamalytics", {})
                    if scam_block.get("status") == "error" and scam_block.get("error") == "out of credits":
                        logger.warning(f"⚠️ Credential Set #{idx+1} ({api_user}) is out of credits. Rotating...")
                        continue # Try next credential in loop
                    
                    return data # Success or other error
                except requests.exceptions.JSONDecodeError:
                    logger.error(f"JSON decode error checking IP {ip} with user {api_user}. Response: {response.text[:100]}")
                    continue # Try next credential just in case? Or fail?
            else:
                logger.error(f"API request failed (HTTP {response.status_code}) with user {api_user}: {response.text[:100]}")
                # If 401/403, maybe rotate? For now, we only rotate on explicit "out of credits".
        
        except Exception as e:
             logger.error(f"⚠️ Unexpected error checking API for IP {ip} with user {api_user}: {e}")
             continue # Try next credential
    
    logger.error(f"❌ All API credentials failed or out of credits for IP {ip}")
    return None

def single_check_proxy_detailed(proxy_line, fraud_score_level, credentials_list, is_strict_mode=False):
    """
    Checks a single proxy with detailed criteria, extracts geo info + score.
    Applies extensive checks if is_strict_mode is True.
    Always returns a dict: {'proxy': str|None, 'ip': str|None, 'credits': dict, 'geo': dict, 'score': int|None}
    'proxy' is only non-None if checks pass (score for normal, extensive for strict).
    """
    mode_prefix = "[Strict] " if is_strict_mode else ""
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    base_result = {"proxy": None, "ip": None, "credits": {}, "geo": {}, "score": None}

    if not validate_proxy_format(proxy_line):
        logger.warning(f"❌ {mode_prefix}Format fail: {proxy_line}")
        return base_result

    ip = get_ip_from_proxy(proxy_line)
    base_result["ip"] = ip
    if not ip:
        return base_result # get_ip_from_proxy logs error

    # --- Fetch Detailed Data Always (With Key Rotation) ---
    data = get_fraud_score_detailed(ip, proxy_line, credentials_list)

    # Always try to extract credits if the response exists
    if data and data.get("credits"):
        base_result["credits"] = data.get("credits")

    # --- MODIFIED: Smart Geo Extraction (Prioritize MaxMind, Fallback to DBIP) ---
    try:
        ext_sources = data.get("external_datasources", {}) if data else {}
        geo_data = {}

        # 1. Try MaxMind first (It works on free tier)
        if ext_sources.get("maxmind_geolite2"):
            mm_data = ext_sources["maxmind_geolite2"]
            # Check if it has real data (not "PREMIUM FIELD...")
            if "PREMIUM" not in mm_data.get("ip_country_code", ""):
                geo_data = {
                    "country_code": mm_data.get("ip_country_code", "N/A"),
                    "state": mm_data.get("ip_state_name", "N/A"),
                    "city": mm_data.get("ip_city", "N/A"),
                    "postcode": mm_data.get("ip_postcode", "N/A")
                }

        # 2. If MaxMind failed or was empty, try DBIP (Old default)
        if not geo_data and ext_sources.get("dbip"):
            dbip_data = ext_sources["dbip"]
            # Only use if it doesn't say PREMIUM
            if "PREMIUM" not in dbip_data.get("ip_country_code", ""):
                geo_data = {
                    "country_code": dbip_data.get("ip_country_code", "N/A"),
                    "state": dbip_data.get("ip_state_name", "N/A"),
                    "city": dbip_data.get("ip_city", "N/A"),
                    "postcode": dbip_data.get("ip_postcode", "N/A")
                }

        # 3. Final Fallback
        if not geo_data:
             base_result["geo"] = {"country_code": "N/A", "state": "N/A", "city": "N/A", "postcode": "N/A"}
        else:
             base_result["geo"] = geo_data

    except Exception as e:
        logger.warning(f"Could not extract geo data for {ip}: {e}")
        base_result["geo"] = {"country_code": "ERR", "state": "ERR", "city": "ERR", "postcode": "ERR"}

    score_val = None
    score_int = None
    # Process Scamalytics data if available
    if data and data.get("scamalytics"):
        scam_data = data.get("scamalytics", {})
        score_val = scam_data.get("scamalytics_score")
        base_result["score"] = score_val # Store original score value

        # Check API status first
        if scam_data.get("status") != "ok":
            logger.warning(f"❓ {mode_prefix}API Error: {scam_data.get('status')} for {proxy_line}")
            return base_result # Return with available info

        # --- Apply Checks ---
        try:
            passed = True
            fail_reason = ""

            # 0. Convert Score safely
            if score_val is None:
                passed = False
                fail_reason = "Score is missing"
            else:
                try:
                    score_int = int(score_val)
                    base_result["score"] = score_int # Update result with integer score
                except (ValueError, TypeError):
                    logger.warning(f"❓ {mode_prefix}Non-integer score received: {score_val} for {proxy_line}")
                    passed = False
                    fail_reason = f"Non-integer score ({score_val})"

            # 1. Score check (<= fraud_score_level) - ALWAYS PERFORMED
            if passed and not (score_int <= fraud_score_level):
                passed = False
                fail_reason = f"Score ({score_int} > {fraud_score_level})"

            # --- Apply STRICT MODE checks only if is_strict_mode is True ---
            if passed and is_strict_mode:
                # 2. Risk check (must be "low")
                if passed and not (scam_data.get("scamalytics_risk") == "low"):
                    passed = False
                    fail_reason = f"Strict: Risk is not low ({scam_data.get('scamalytics_risk')})"

                # 3. Scamalytics Proxy Flags (all must be false)
                if passed:
                    proxy_flags = scam_data.get("scamalytics_proxy", {})
                    scam_flags_to_check = ["is_datacenter", "is_vpn", "is_apple_icloud_private_relay", "is_amazon_aws", "is_google"]
                    for flag in scam_flags_to_check:
                        # Explicitly check for True, as False or None should pass
                        if proxy_flags.get(flag) is True:
                            passed = False
                            fail_reason = f"Strict: Scamalytics flag '{flag}' is true"
                            break

                # 4. Scamalytics External Blacklist (must be false)
                if passed and scam_data.get("is_blacklisted_external") is True:
                     passed = False
                     fail_reason = "Strict: Scamalytics flag 'is_blacklisted_external' is true"

                # --- External Datasource Checks (Safely access nested dicts) ---
                ext_data = data.get("external_datasources", {})

                # 4.5. ip2proxy Proxy Type (must not be VPN) <-- NEW CHECK
                # Note: On free tier, this often returns "PREMIUM FIELD", so this check may be ineffective but harmless.
                if passed and ext_data.get("ip2proxy", {}).get("proxy_type") == "VPN":
                    passed = False
                    fail_reason = "Strict: ip2proxy proxy_type is 'VPN'"

                # 5. ip2proxy_lite Blacklist (must be false)
                if passed and ext_data.get("ip2proxy_lite", {}).get("ip_blacklisted") is True:
                    passed = False
                    fail_reason = "Strict: ip2proxy_lite flag 'ip_blacklisted' is true"

                # 6. Firehol Blacklists & Proxy flag (all must be false)
                if passed:
                    firehol_data = ext_data.get("firehol", {})
                    firehol_flags = ["ip_blacklisted_30", "ip_blacklisted_1day", "is_proxy"]
                    for flag in firehol_flags:
                         if firehol_data.get(flag) is True:
                              passed = False
                              fail_reason = f"Strict: Firehol flag '{flag}' is true"
                              break

                # 7. Ipsum Blacklist (must be false) and num_blacklists (must be 0)
                if passed:
                     ipsum_data = ext_data.get("ipsum", {})
                     if ipsum_data.get("ip_blacklisted") is True:
                          passed = False
                          fail_reason = "Strict: Ipsum flag 'ip_blacklisted' is true"
                     # Ensure num_blacklists exists and is exactly 0
                     elif ipsum_data.get("num_blacklists") != 0:
                          passed = False
                          fail_reason = f"Strict: Ipsum num_blacklists is not 0 ({ipsum_data.get('num_blacklists', 'N/A')})"

                # 8. Spamhaus Drop Blacklist (must be false)
                if passed and ext_data.get("spamhaus_drop", {}).get("ip_blacklisted") is True:
                     passed = False
                     fail_reason = "Strict: Spamhaus Drop flag 'ip_blacklisted' is true"

                # 9. x4bnet Flags (all must be false)
                if passed:
                     x4b_data = ext_data.get("x4bnet", {})
                     x4b_flags = ["is_vpn", "is_datacenter", "is_tor", "is_blacklisted_spambot", "is_bot_operamini", "is_bot_semrush"]
                     for flag in x4b_flags:
                          if x4b_data.get(flag) is True:
                               passed = False
                               fail_reason = f"Strict: x4bnet flag '{flag}' is true"
                               break

                # 10. Google Flags (all must be false)
                if passed:
                     google_data = ext_data.get("google", {})
                     google_flags = ["is_google_general", "is_googlebot", "is_special_crawler", "is_user_triggered_fetcher"]
                     for flag in google_flags:
                          if google_data.get(flag) is True:
                               passed = False
                               fail_reason = f"Strict: Google flag '{flag}' is true"
                               break
            # --- End of Strict Mode Checks ---

            # --- Final Decision ---
            if passed:
                logger.info(f"✅ {mode_prefix}Good: {proxy_line} (IP: {ip}, Score: {score_int})")
                base_result["proxy"] = proxy_line # Set proxy only if all checks passed
                return base_result
            else:
                logger.info(f"❌ {mode_prefix}Fail: {proxy_line} (Reason: {fail_reason})")
                # Log to bad proxies if score was the *primary* failure reason
                if score_int is not None and score_int > fraud_score_level and fail_reason.startswith("Score"):
                    try: log_bad_proxy(proxy_line, ip, score_int)
                    except Exception as e: logger.error(f"Error logging bad proxy '{proxy_line}': {e}")
                # Return result without proxy set
                return base_result

        except Exception as e:
            logger.error(f"Error during check logic evaluation for {proxy_line}: {e}", exc_info=False)
            return base_result # Return with available info

    else:
        # Handle case where Scamalytics API call failed completely or returned invalid structure
        logger.warning(f"❓ {mode_prefix}No valid Scamalytics data block for: {proxy_line} (IP: {ip})")
        return base_result # Return with available info
# --- END HELPER FUNCTIONS ---


# --- BEFORE REQUEST HANDLER ---
@app.before_request
def before_request_func():
    """Skip checks for static/asset routes and admin test page."""
    if request.path.startswith(('/static', '/login', '/logout')) or \
       request.path.endswith(('.ico', '.png')) or \
       request.path == url_for('admin_test'): # Check specifically for the test route
        return
    pass # No specific action needed for other routes here
# --- END BEFORE REQUEST HANDLER ---


# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        return redirect(url_for('admin') if current_user.is_admin else url_for('index'))
    
    # Get IP for logging *before* the post check
    user_ip = get_user_ip()
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        # Find user (replace with DB lookup in real app)
        user_to_login = next((user for uid, user in users.items() if user.username == username), None)

        # !! Use password hashing in production !!
        if user_to_login and user_to_login.password == password:
            login_user(user_to_login, remember=remember)
            next_page = request.args.get('next')
            # Security: Prevent redirecting non-admins trying to access admin pages
            if next_page and not current_user.is_admin and ('/admin' in next_page or '/delete-used-ip' in next_page):
                 flash("Redirecting to user dashboard.", "info")
                 next_page = url_for('index')
            # Redirect admins from index to admin if that was the 'next' page
            if current_user.is_admin and next_page == url_for('index'):
                 next_page = url_for('admin')
            logger.info(f"User '{username}' logged in successfully.")
            # --- MODIFIED: Added IP ---
            add_log_entry("INFO", f"User '{username}' logged in successfully.", ip=user_ip)
            return redirect(next_page or (url_for('admin') if current_user.is_admin else url_for('index')))
        else:
            logger.warning(f"Failed login attempt for username: '{username}'")
            # --- MODIFIED: Added IP ---
            add_log_entry("WARNING", f"Failed login attempt for username: '{username}'", ip=user_ip)
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    user_ip = get_user_ip() # Get IP before logging out
    username = current_user.username # Get username before logging out
    logout_user()
    flash('You have been logged out successfully.', 'info')
    logger.info(f"User '{username}' logged out.")
    # --- MODIFIED: Added IP ---
    add_log_entry("INFO", f"User '{username}' logged out.", ip=user_ip)
    return redirect(url_for('login'))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Main proxy checker page. Now uses detailed check with strict mode (silently)."""
    try:
        settings = get_app_settings()
    except Exception as e:
        logger.critical(f"CRITICAL ERROR getting app settings on index page: {e}", exc_info=True)
        # --- MODIFIED: Added IP ---
        add_log_entry("CRITICAL", f"Failed to load settings on index: {str(e)[:50]}", ip=get_user_ip())
        return render_template("error.html", error="Could not load critical application settings."), 500

    # Extract settings for clarity
    MAX_PASTE = settings["MAX_PASTE"]
    # Use the standard user fraud score level for this page
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    # --- Parse Credentials List ---
    api_credentials = parse_api_credentials(settings)
    
    announcement = settings.get("ANNOUNCEMENT")

    results = None # Use None for GET to distinguish from empty POST results
    message = None
    user_ip = get_user_ip() # Get IP for POST logic

    if request.method == "POST":
        start_time = time.time()
        proxies_input = []
        input_count = 0
        truncation_warning = ""
        results = [] # Initialize as empty list for POST

        # --- Handle Input (Text) ---
        if 'proxytext' in request.form and request.form.get("proxytext", "").strip():
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            input_count = len(all_lines)
            
            # --- MODIFICATION: Re-added limit ---
            if input_count > MAX_PASTE:
                truncation_warning = f" Input text truncated to first {MAX_PASTE} lines."
                proxies_input = all_lines[:MAX_PASTE]
            else:
                proxies_input = all_lines
            # --- END MODIFICATION ---

            logger.info(f"Received {input_count} proxies via text area.")
        else:
            message = "No proxies submitted. Please paste proxies."
            return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement)

        # --- Load Caches (Used IPs and Bad Proxies) ---
        used_ips_list = set()
        used_proxy_cache = set()
        bad_proxy_cache = set()
        cache_load_warnings = []
        try:
            used_ips_records = get_all_used_ips()
            used_ips_list = {r.get('IP') for r in used_ips_records if r.get('IP')}
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

        # --- Filter Proxies (Unique, Format, Cache) ---
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
        logger.info(f"Prefiltering complete: {len(unique_proxies_input)} unique -> {len(invalid_format_proxies)} invalid, {used_count_prefilter} skipped (used cache), {bad_count_prefilter} skipped (bad cache). {processed_count} proxies remaining.")

        # --- Execute Checks Concurrently with Early Exit (Using Detailed Check) ---
        good_proxy_results = []
        target_good_proxies = 2 # Early exit target
        futures = set()
        cancelled_count = 0
        last_credits = {} # Store credits from last API call on this page too

        if proxies_to_check:
            actual_workers = min(MAX_WORKERS, processed_count)
            logger.info(f"Starting detailed check for {processed_count} proxies using {actual_workers} workers (target: {target_good_proxies} usable good proxies)...")
            with ThreadPoolExecutor(max_workers=actual_workers) as executor:
                # MODIFIED: Pass list of credentials
                for proxy in proxies_to_check:
                    futures.add(executor.submit(single_check_proxy_detailed, proxy, FRAUD_SCORE_LEVEL, api_credentials, is_strict_mode=True)) 

                # Process results as they complete, implement early exit
                while futures:
                    done, futures = wait(futures, return_when=FIRST_COMPLETED)
                    for future in done:
                        try:
                            result = future.result() # result is always a dict
                            if result:
                                # Store latest credit info
                                if result.get("credits"):
                                    last_credits = result.get("credits")

                                # Check if the 'proxy' key is set (meaning score check passed)
                                if result.get("proxy"):
                                    result['used'] = result.get('ip') in used_ips_list # Check against live used IP list
                                    good_proxy_results.append(result)

                                    # Check if target is met (counting only non-used proxies)
                                    if len([r for r in good_proxy_results if not r['used']]) >= target_good_proxies:
                                        logger.info(f"Target of {target_good_proxies} usable proxies reached. Cancelling remaining tasks.")
                                        for f in futures:
                                            if f.cancel(): cancelled_count += 1
                                        futures = set() # Clear the set to stop the loop
                                        break # Exit inner loop

                        except Exception as exc:
                            logger.error(f'A proxy check task generated an exception: {exc}', exc_info=False)

                    if not futures: # Break outer loop if futures set is empty
                        break

            logger.info(f"Finished checking. Found {len(good_proxy_results)} potential good proxies (score <= {FRAUD_SCORE_LEVEL}). Cancelled {cancelled_count} tasks.")
        else:
            logger.info("No valid proxies left to check after prefiltering.")


        # --- Final Processing and Message Construction ---
        # --- MODIFIED: Deduplicate Results by IP (keep first occurrence) ---
        unique_results = []
        seen_ips = set()
        for res in good_proxy_results:
            if res.get('ip') and res.get('ip') not in seen_ips:
                seen_ips.add(res['ip'])
                unique_results.append(res)
        
        final_results_display = sorted(unique_results, key=lambda x: x['used'])
        # --- END MODIFIED ---

        good_count_final = len([r for r in final_results_display if not r['used']])
        used_count_final = len([r for r in final_results_display if r['used']])
        invalid_format_count = len(invalid_format_proxies)
        checks_attempted = processed_count - cancelled_count

        # --- NEW: Log API Usage ---
        try:
            add_api_usage_log(
                username=current_user.username,
                ip=user_ip,
                submitted_count=input_count,
                api_calls_count=checks_attempted
            )
        except Exception as e:
            logger.error(f"Failed to log API usage for user {current_user.username}: {e}")
        # --- END NEW ---

        format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
        prefilter_msg = ""
        if used_count_prefilter > 0 or bad_count_prefilter > 0:
             prefilter_msg = f" (Skipped {used_count_prefilter} from used cache, {bad_count_prefilter} from bad cache)."
        cancel_msg = ""
        if cancelled_count > 0:
            cancel_msg = f" Stopped early after finding {good_count_final} usable proxies (checked {checks_attempted})."

        if good_count_final > 0 or used_count_final > 0:
            base_message = f"✅ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). Found {good_count_final} unique usable proxies ({used_count_final} previously used IPs found)."
            # --- MODIFIED: Added IP ---
            add_log_entry("INFO", f"Checker run by {current_user.username}. Found {good_count_final} usable proxies.", ip=user_ip)
        else:
             base_message = f"⚠️ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). No new usable proxies found."
             # --- MODIFIED: Added IP ---
             add_log_entry("WARNING", f"Checker run by {current_user.username}. Found no usable proxies in batch.", ip=user_ip)

        full_message = base_message + truncation_warning + prefilter_msg + cancel_msg
        message = (message + " " + full_message) if message else full_message

        results = final_results_display
        end_time = time.time()
        logger.info(f"Request processing took {end_time - start_time:.2f} seconds.")

    # Render template for both GET and POST
    return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement)


@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    """Endpoint called by JS to mark a proxy's IP as used. OPTIMIZED: Accepts IP from client."""
    data = request.get_json()
    proxy_line = data.get("proxy") if data else None
    ip = data.get("ip") if data else None  # <-- MODIFIED: Get IP from request data
    user_ip = get_user_ip() # Get IP for logging

    # Validate both proxy and IP presence and format
    if not proxy_line or not ip or ip in ('N/A', 'ERR'): # MODIFIED: Check for proxy, ip, and invalid ip placeholders
        logger.warning(f"Track-used request received without proxy or a valid IP. Proxy: {proxy_line}, IP: {ip}")
        return jsonify({"status": "error", "message": "Invalid request data (missing or invalid IP)"}), 400

    if not validate_proxy_format(proxy_line):
        logger.warning(f"Track-used request received with invalid proxy format: {proxy_line}")
        return jsonify({"status": "error", "message": "Invalid proxy format"}), 400

    try:
        # Direct call using the passed IP, eliminating the slow get_ip_from_proxy call.
        if add_used_ip(ip, proxy_line):
            logger.info(f"Successfully marked IP {ip} as used for proxy: {proxy_line}")
            # --- MODIFIED: Added IP ---
            add_log_entry("INFO", f"Proxy marked as used by {current_user.username}: {ip}", ip=user_ip)
            return jsonify({"status": "success"})
        else:
            # add_used_ip logs its own errors
            logger.error(f"Failed to add used IP/Proxy to Google Sheet: {proxy_line} (IP: {ip})")
            # --- MODIFIED: Added IP ---
            add_log_entry("ERROR", f"Failed to log used proxy {ip} for {current_user.username}.", ip=user_ip)
            return jsonify({"status": "error", "message": "Failed to update usage status"}), 500
    except Exception as e:
        logger.error(f"Unexpected error in /track-used for proxy '{proxy_line}': {e}", exc_info=True)
        # --- MODIFIED: Added IP ---
        add_log_entry("ERROR", f"Exception in track-used for {proxy_line}: {str(e)[:50]}", ip=user_ip)
        return jsonify({"status": "error", "message": "Internal server error during usage tracking"}), 500


# --- Admin Routes (Protected) ---

@app.route("/admin")
@admin_required
def admin():
    """Admin dashboard page."""
    user_ip = get_user_ip()
    try:
        settings = get_app_settings()

        # --- NEW: Calculate Total API Calls ---
        total_api_calls = 0
        try:
            usage_logs = get_all_api_usage_logs()
            for log in usage_logs:
                # get_all_records() can return strings, ensure conversion
                total_api_calls += int(log.get("API Calls Made") or 0)
        except Exception as e:
            logger.error(f"Failed to calculate total API calls: {e}")
            total_api_calls = "Error"
        # --- END NEW ---
        
        # Consolidate stats for template
        stats = {
            # Basic stats (currently placeholders)
            "total_checks": "N/A (Vercel)",
            "total_good": "N/A",
            # Current settings display
            "max_paste": settings["MAX_PASTE"],
            "fraud_score_level": settings["FRAUD_SCORE_LEVEL"],
            "strict_fraud_score_level": settings.get("STRICT_FRAUD_SCORE_LEVEL", "N/A"),
            "max_workers": settings["MAX_WORKERS"],
            "scamalytics_api_key": settings["SCAMALYTICS_API_KEY"],
            "scamalytics_api_url": settings["SCAMALYTICS_API_URL"],
            "scamalytics_username": settings["SCAMALYTICS_USERNAME"],
            # API Credits
            "api_credits_used": settings.get("API_CREDITS_USED", "N/A"),
            "api_credits_remaining": settings.get("API_CREDITS_REMAINING", "N/A"),
            # --- NEW STAT ---
            "total_api_calls_logged": total_api_calls
        }
        # Fetch used IPs list
        used_ips = get_all_used_ips() # Assuming this returns a list of dicts
        announcement = settings.get("ANNOUNCEMENT")
        return render_template(
            "admin.html",
            stats=stats,
            used_ips=used_ips,
            announcement=announcement
            )
    except Exception as e:
        logger.error(f"Error loading admin panel: {e}", exc_info=True)
        # --- MODIFIED: Added IP ---
        add_log_entry("ERROR", f"Failed to load admin panel: {str(e)[:50]}", ip=user_ip)
        flash("Error loading admin panel data. Please check logs.", "danger")
        # Provide safe defaults on error
        stats_error = { 
            "api_credits_used": "Error", 
            "api_credits_remaining": "Error",
            "total_api_calls_logged": "Error" # <-- NEW
        }
        return render_template("admin.html", stats=stats_error, used_ips=[], announcement="")


# --- NEW ADMIN LOGS ROUTE ---
@app.route("/admin/logs")
@admin_required
def admin_logs():
    """Admin-only page to view application system logs."""
    user_ip = get_user_ip()
    try:
        # Fetch logs from Google Sheet (new function)
        logs = get_all_system_logs()
        # --- MODIFIED: Added IP ---
        add_log_entry("INFO", f"Admin '{current_user.username}' viewed system logs.", ip=user_ip)
        # Reversing logs so newest is on top for display
        return render_template("admin_logs.html", logs=logs[::-1])
    except Exception as e:
        logger.error(f"Error loading admin logs page: {e}", exc_info=True)
        # --- MODIFIED: Added IP ---
        add_log_entry("CRITICAL", f"Failed to load system logs: {str(e)[:50]}", ip=user_ip)
        flash("Error loading system logs. Check logs for details.", "danger")
        return render_template("admin_logs.html", logs=[])
# --- END NEW ADMIN LOGS ROUTE ---


# --- NEW: ROUTE TO CLEAR LOGS ---
@app.route("/admin/clear-logs", methods=["POST"])
@admin_required
def admin_clear_logs():
    """Clears all system logs from the Google Sheet."""
    user_ip = get_user_ip() # Get IP before logging
    try:
        if clear_all_system_logs(): # This is the new function
            flash("Successfully cleared all system logs.", "success")
            logger.info(f"Admin '{current_user.username}' cleared all system logs.")
            # Log the clearing event *after* it's done (it will be the only log)
            add_log_entry("WARNING", f"All system logs cleared by {current_user.username}", ip=user_ip)
        else:
            flash("Failed to clear system logs. Check server logs.", "danger")
            add_log_entry("ERROR", f"Failed attempt to clear logs by {current_user.username}", ip=user_ip)
    except Exception as e:
        logger.error(f"Error in admin_clear_logs route: {e}", exc_info=True)
        flash("An unexpected error occurred while clearing logs.", "danger")
        add_log_entry("CRITICAL", f"Exception in admin_clear_logs: {str(e)[:50]}", ip=user_ip)
    return redirect(url_for("admin_logs"))
# --- END NEW ROUTE ---


@app.route("/admin/test", methods=["GET", "POST"])
@admin_required
def admin_test():
    """Admin-only strict proxy checker page."""
    try:
        settings = get_app_settings()
    except Exception as e:
        logger.critical(f"CRITICAL ERROR getting app settings for admin test: {e}", exc_info=True)
        # --- MODIFIED: Added IP ---
        add_log_entry("CRITICAL", f"Failed to load settings on admin/test: {str(e)[:50]}", ip=get_user_ip())
        return render_template("error.html", error="Could not load critical application settings."), 500

    MAX_PASTE = settings["MAX_PASTE"] # Still needed for render_template
    STRICT_FRAUD_SCORE_LEVEL = settings["STRICT_FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    # --- Parse Credentials List ---
    api_credentials = parse_api_credentials(settings)

    results = None
    message = None
    user_ip = get_user_ip() # Get IP for POST logic

    if request.method == "GET":
         return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)

    # --- POST Request Logic ---
    start_time = time.time()
    proxies_input = []
    input_count = 0
    truncation_warning = ""
    results = []

    # --- Handle Input ---
    if 'proxytext' in request.form and request.form.get("proxytext", "").strip():
        proxytext = request.form.get("proxytext", "")
        all_lines = proxytext.strip().splitlines()
        input_count = len(all_lines)
        
        # --- MODIFICATION: Re-added limit ---
        if input_count > MAX_PASTE:
            truncation_warning = f" Input text truncated to first {MAX_PASTE} lines."
            proxies_input = all_lines[:MAX_PASTE]
        else:
            proxies_input = all_lines
        # --- END MODIFICATION ---
        
        logger.info(f"[Strict] Received {input_count} proxies via text area.")
    else: message = "No proxies submitted."; return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)


    # --- Load Caches ---
    used_ips_list = set(); used_proxy_cache = set(); bad_proxy_cache = set(); cache_load_warnings = []
    try: used_ips_records = get_all_used_ips(); used_ips_list = {r.get('IP') for r in used_ips_records if r.get('IP')}; used_proxy_cache = {r.get('Proxy') for r in used_ips_records if r.get('Proxy')}; logger.info(f"[Strict] Loaded {len(used_ips_list)} used IPs and {len(used_proxy_cache)} used proxies.")
    except Exception as e: logger.error(f"[Strict] Error loading used proxy cache: {e}"); cache_load_warnings.append("Could not load used proxy cache.")
    try: bad_proxy_cache = set(get_bad_proxies_list()); logger.info(f"[Strict] Loaded {len(bad_proxy_cache)} bad proxies.")
    except Exception as e: logger.error(f"[Strict] Error loading bad proxy cache: {e}"); cache_load_warnings.append("Could not load bad proxy cache.")
    if cache_load_warnings: message = "Warning: " + " ".join(cache_load_warnings)

    # --- Filter Proxies ---
    proxies_to_check = []; invalid_format_proxies = []; used_count_prefilter = 0; bad_count_prefilter = 0
    unique_proxies_input = {p.strip() for p in proxies_input if p.strip()}
    logger.info(f"[Strict] Processing {len(unique_proxies_input)} unique non-empty input lines.")
    for proxy in unique_proxies_input:
        if not validate_proxy_format(proxy): invalid_format_proxies.append(proxy); continue
        if proxy in used_proxy_cache: used_count_prefilter += 1; continue
        if proxy in bad_proxy_cache: bad_count_prefilter += 1; continue
        proxies_to_check.append(proxy)
    processed_count = len(proxies_to_check)
    logger.info(f"[Strict] Prefiltering complete: {len(unique_proxies_input)} unique -> {len(invalid_format_proxies)} invalid, {used_count_prefilter} skipped (used cache), {bad_count_prefilter} skipped (bad cache). {processed_count} proxies remaining.")

    # --- Execute Checks Concurrently ---
    good_proxy_results = []
    target_good_proxies = 2 # <--- MODIFICATION: Set target
    futures = set()
    cancelled_count = 0 # <--- MODIFICATION: Add counter
    last_credits = {}
    
    if proxies_to_check:
        actual_workers = min(MAX_WORKERS, processed_count)
        # MODIFIED Log
        logger.info(f"[Strict] Starting check for {processed_count} proxies using {actual_workers} workers (target: {target_good_proxies} usable good proxies)...")
        # --- MODIFIED: Added IP ---
        add_log_entry("INFO", f"Strict test started by {current_user.username} for {processed_count} proxies.", ip=user_ip)
        
        with ThreadPoolExecutor(max_workers=actual_workers) as executor:
            # MODIFIED: Pass credentials list
            for proxy in proxies_to_check:
                 # Use detailed check with is_strict_mode=True
                futures.add(executor.submit(single_check_proxy_detailed, proxy, STRICT_FRAUD_SCORE_LEVEL, api_credentials, is_strict_mode=True))
            
            # --- MODIFICATION: Replaced as_completed with while/wait logic ---
            while futures:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        result = future.result()
                        if result:
                            if result.get("credits"): 
                                last_credits = result.get("credits")
                            if result.get("proxy"):
                                result['used'] = result.get('ip') in used_ips_list
                                good_proxy_results.append(result)

                                # Check if target is met (counting only non-used proxies)
                                if len([r for r in good_proxy_results if not r['used']]) >= target_good_proxies:
                                    logger.info(f"[Strict] Target of {target_good_proxies} usable proxies reached. Cancelling remaining tasks.")
                                    for f in futures:
                                        if f.cancel(): cancelled_count += 1
                                    futures = set() # Clear the set to stop the loop
                                    break # Exit inner loop
                                    
                    except Exception as exc: 
                        logger.error(f'[Strict] A proxy check task generated an exception: {exc}', exc_info=False)
                
                if not futures: # Break outer loop if futures set is empty
                    break
            # --- END MODIFICATION ---

        # MODIFIED Log
        logger.info(f"[Strict] Finished checking. Found {len(good_proxy_results)} proxies passing strict filter. Cancelled {cancelled_count} tasks.")
    else: 
        logger.info("[Strict] No valid proxies left to check after prefiltering.")


    # --- Update API Credits ---
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

    # --- Final Processing and Message ---
    # --- MODIFIED: Deduplicate Results by IP (keep first occurrence) ---
    unique_results = []
    seen_ips = set()
    for res in good_proxy_results:
        if res.get('ip') and res.get('ip') not in seen_ips:
            seen_ips.add(res['ip'])
            unique_results.append(res)
    
    final_results_display = sorted(unique_results, key=lambda x: x['used'])
    # --- END MODIFIED ---
    
    good_count_final = len([r for r in final_results_display if not r['used']])
    used_count_final = len([r for r in final_results_display if r['used']])
    invalid_format_count = len(invalid_format_proxies)
    
    checks_attempted = processed_count - cancelled_count # <--- MODIFICATION
    
    # --- NEW: Log API Usage ---
    try:
        add_api_usage_log(
            username=current_user.username,
            ip=user_ip,
            submitted_count=input_count,
            api_calls_count=checks_attempted
        )
    except Exception as e:
        logger.error(f"Failed to log API usage for user {current_user.username}: {e}")
    # --- END NEW ---

    format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
    prefilter_msg = f" (Skipped {used_count_prefilter} used, {bad_count_prefilter} bad cache)." if used_count_prefilter > 0 or bad_count_prefilter > 0 else ""

    # --- MODIFICATION: Add cancel message ---
    cancel_msg = ""
    if cancelled_count > 0:
        cancel_msg = f" Stopped early after finding {good_count_final} usable proxies (checked {checks_attempted})."
    # --- END MODIFICATION ---

    if good_count_final > 0 or used_count_final > 0: main_message = f"✅ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). Found {good_count_final} unique usable proxies passing strict filter ({used_count_final} used IPs found)."
    else: main_message = f"⚠️ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). No new usable proxies found passing strict filter."
    
    # --- MODIFIED: Added IP ---
    add_log_entry("INFO", f"Strict test finished by {current_user.username}. Found {good_count_final} good proxies. {credit_msg}", ip=user_ip)

    # MODIFICATION: Add cancel_msg
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
    try: current_settings = get_app_settings()
    except Exception as e: logger.critical(f"CRITICAL ERROR getting settings for admin settings page: {e}", exc_info=True); flash("Could not load current settings.", "danger"); add_log_entry("CRITICAL", f"Failed to load settings page: {str(e)[:50]}", ip=user_ip); return render_template("admin_settings.html", settings=DEFAULT_SETTINGS, message=None)

    if request.method == "POST":
        form_settings = {}; error_msg = None
        try:
            # Validate and convert form inputs
            form_settings["MAX_PASTE"] = int(request.form.get("max_paste", DEFAULT_SETTINGS["MAX_PASTE"]))
            form_settings["FRAUD_SCORE_LEVEL"] = int(request.form.get("fraud_score_level", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]))
            form_settings["STRICT_FRAUD_SCORE_LEVEL"] = int(request.form.get("strict_fraud_score_level", DEFAULT_SETTINGS["STRICT_FRAUD_SCORE_LEVEL"]))
            form_settings["MAX_WORKERS"] = int(request.form.get("max_workers", DEFAULT_SETTINGS["MAX_WORKERS"]))
            form_settings["SCAMALYTICS_API_KEY"] = request.form.get("scamalytics_api_key", "").strip()
            form_settings["SCAMALYTICS_API_URL"] = request.form.get("scamalytics_api_url", "").strip()
            form_settings["SCAMALYTICS_USERNAME"] = request.form.get("scamalytics_username", "").strip()

            # Input constraints validation
            if not (5 <= form_settings["MAX_PASTE"] <= 100): error_msg = "Max proxies must be between 5 and 100."
            elif not (0 <= form_settings["FRAUD_SCORE_LEVEL"] <= 100): error_msg = "User Fraud score must be between 0 and 100."
            elif not (0 <= form_settings["STRICT_FRAUD_SCORE_LEVEL"] <= 100): error_msg = "Strict Fraud score must be between 0 and 100."
            elif not (1 <= form_settings["MAX_WORKERS"] <= 100): error_msg = "Max workers must be between 1 and 100."
            
            # MODIFIED Validation: Check all comma-separated keys
            keys_check = [k.strip() for k in form_settings["SCAMALYTICS_API_KEY"].split(',') if k.strip()]
            for k in keys_check:
                 if len(k) < 5: error_msg = f"API Key '{k}' seems too short."
            
            # MODIFIED Validation: Check all URLs
            urls_check = [u.strip() for u in form_settings["SCAMALYTICS_API_URL"].split(',') if u.strip()]
            for u in urls_check:
                 if not u.startswith("http"): error_msg = f"API URL '{u}' must start with http or https."

            # MODIFIED Validation: Check all Usernames
            users_check = [u.strip() for u in form_settings["SCAMALYTICS_USERNAME"].split(',') if u.strip()]
            for u in users_check:
                 if len(u) < 3: error_msg = f"Username '{u}' seems too short."

        except ValueError: error_msg = "Invalid input: Score levels, Max Proxies, and Max Workers must be whole numbers."

        if not error_msg:
            logger.info("Attempting settings update via admin panel..."); success_count = 0
            settings_to_update = list(form_settings.items()) # Get items from validated form data
            for key, value in settings_to_update:
                if update_setting(key, str(value)): success_count += 1
                else: logger.error(f"Failed to update setting '{key}' in Google Sheet.")
            if success_count == len(settings_to_update): 
                logger.info("All settings updated successfully."); 
                flash("Settings updated successfully", "success"); 
                # --- MODIFIED: Added IP ---
                add_log_entry("INFO", f"Admin '{current_user.username}' updated settings.", ip=user_ip)
                current_settings = get_app_settings() # Refresh
            else: 
                error_msg = f"Error saving settings: {len(settings_to_update) - success_count} update(s) failed. Check logs."; 
                flash(error_msg, "danger"); 
                # --- MODIFIED: Added IP ---
                add_log_entry("ERROR", f"Admin '{current_user.username}' failed to update {len(settings_to_update) - success_count} settings.", ip=user_ip)
                current_settings.update(form_settings) # Show submitted values on partial failure
        else: 
            flash(error_msg, "danger"); 
            current_settings.update(form_settings) # Show submitted values on validation failure

    # Render template with current (or submitted-on-error) settings
    return render_template("admin_settings.html", settings=current_settings, message=None)


@app.route("/admin/announcement", methods=["POST"])
@admin_required
def admin_announcement():
    """Handles saving or deleting the announcement."""
    user_ip = get_user_ip()
    try:
        if "save_announcement" in request.form:
            text = request.form.get("announcement_text", "").strip()
            if update_setting("ANNOUNCEMENT", text): 
                flash("Announcement updated successfully.", "success"); 
                logger.info(f"Admin '{current_user.username}' updated announcement.")
                # --- MODIFIED: Added IP ---
                add_log_entry("INFO", f"Admin '{current_user.username}' updated announcement.", ip=user_ip)
            else: 
                flash("Error saving announcement to Google Sheet. Check logs.", "danger"); 
                logger.error("Failed to save announcement to GSheet.")
                # --- MODIFIED: Added IP ---
                add_log_entry("ERROR", f"Admin '{current_user.username}' failed to save announcement.", ip=user_ip)
        elif "delete_announcement" in request.form:
            if update_setting("ANNOUNCEMENT", ""): 
                flash("Announcement cleared successfully.", "success"); 
                logger.info(f"Admin '{current_user.username}' cleared announcement.")
                # --- MODIFIED: Added IP ---
                add_log_entry("INFO", f"Admin '{current_user.username}' cleared announcement.", ip=user_ip)
            else: 
                flash("Error clearing announcement in Google Sheet. Check logs.", "danger"); 
                logger.error("Failed to clear announcement in GSheet.")
                # --- MODIFIED: Added IP ---
                add_log_entry("ERROR", f"Admin '{current_user.username}' failed to clear announcement.", ip=user_ip)
    except Exception as e: 
        logger.error(f"Error in admin_announcement route: {e}", exc_info=True); 
        # --- MODIFIED: Added IP ---
        add_log_entry("ERROR", f"Exception in admin_announcement: {str(e)[:50]}", ip=user_ip)
        flash("An unexpected error occurred while managing the announcement.", "danger")
    return redirect(url_for("admin"))


@app.route("/delete-used-ip/<ip>")
@admin_required
def delete_used_ip_route(ip):
    """Deletes a used IP record from the Google Sheet."""
    user_ip = get_user_ip()
    if not ip: flash("Invalid IP provided for deletion.", "warning"); return redirect(url_for("admin"))
    try:
        if delete_used_ip(ip): 
            flash(f"Successfully removed record for IP {ip}.", "success"); 
            logger.info(f"Admin '{current_user.username}' deleted used IP record: {ip}")
            # --- MODIFIED: Added IP ---
            add_log_entry("INFO", f"Admin '{current_user.username}' deleted used IP: {ip}", ip=user_ip)
        else: 
            flash(f"Could not delete record for IP {ip}. It might not exist or an error occurred.", "warning") # delete_used_ip logs specifics
            # --- MODIFIED: Added IP ---
            add_log_entry("WARNING", f"Admin '{current_user.username}' failed to delete IP: {ip}", ip=user_ip)
    except Exception as e: 
        logger.error(f"Unexpected error in delete_used_ip_route for IP {ip}: {e}", exc_info=True); 
        # --- MODIFIED: Added IP ---
        add_log_entry("ERROR", f"Exception deleting used IP {ip}: {str(e)[:50]}", ip=user_ip)
        flash("An server error occurred while trying to delete the record.", "danger")
    return redirect(url_for("admin"))


# --- THIS SECTION IS NOW REMOVED ---
# @app.route('/static/<path:path>')
# def send_static(path):
#    """Serves static files (if any)."""
#    return send_from_directory('static', path)


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    """Handles 404 Not Found errors."""
    user_ip = get_user_ip()
    logger.warning(f"404 Not Found access attempt: {request.path}")
    # --- MODIFIED: Added IP ---
    add_log_entry("WARNING", f"404 Not Found access at {request.path}", ip=user_ip)
    if current_user.is_authenticated:
        if request.path.endswith(('.ico', '.png', '.css', '.js')): return '', 404 # Return empty 404 for assets
        return render_template('error.html', error=f'The requested page ({request.path}) was not found.'), 404
    else: flash("Page not found or access denied. Please log in.", "warning"); return redirect(url_for('login'))


@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Errors."""
    user_ip = get_user_ip()
    logger.error(f"500 Internal Server Error processing request {request.path}: {e}", exc_info=True)
    # --- MODIFIED: Added IP ---
    add_log_entry("CRITICAL", f"500 Server Error at {request.path}: {str(e)[:50]}", ip=user_ip)
    return render_template('error.html', error='An internal server error occurred. The administrator has been notified.'), 500

# --- Main Execution ---
if __name__ == "__main__":
    # Log the application startup for visibility
    add_log_entry("INFO", "Application server starting up.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False) # Use PORT env var if available
