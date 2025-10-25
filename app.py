# --- IMPORTS ---
from flask import (
    Flask, request, render_template, redirect, url_for,
    jsonify, send_from_directory, flash, session
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user
)
from functools import wraps # Needed for admin_required decorator
import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys
# --- sheets_util Imports (Removed unused functions) ---
from sheets_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip,
    get_all_used_ips,
    log_bad_proxy, get_bad_proxies_list
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# --- SECRET KEY (Required for sessions/Flask-Login) ---
# IMPORTANT: Change this to a real, random secret key in production!
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-super-secret-key-in-production")


# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to /login if user tries to access protected page
login_manager.login_message_category = "warning" # Use bootstrap category for flash messages

# --- Simple User Model (Add Role) ---
class User(UserMixin):
    def __init__(self, id, username, password, role="user"): # Default role is 'user'
        self.id = id
        self.username = username
        self.password = password
        self.role = role # Added role attribute

    # --- Add is_admin property ---
    @property
    def is_admin(self):
        return self.role == "admin"

# Hardcoded users for simplicity. Store securely in production!
# Add more users as needed.
# REMEMBER TO CHANGE THESE PASSWORDS
users = {
    1: User(id=1, username="Boss", password="ADMIN123", role="admin"), # Admin user
    2: User(id=2, username="Work", password="password"),            # Regular user
    # 3: User(id=3, username="user2", password="password2"),
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# --- Decorator to require admin role ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
# --- End Flask-Login Setup ---


# Default configuration values
DEFAULT_SETTINGS = {
    "MAX_PASTE": 30,
    "FRAUD_SCORE_LEVEL": 0,
    "MAX_WORKERS": 5,
    "SCAMALYTICS_API_KEY": "YOUR_API_KEY_HERE",
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/",
    "SCAMALYTICS_USERNAME": "YOUR_USERNAME_HERE"
}

# User agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
]

# Request timeout
REQUEST_TIMEOUT = 5
MIN_DELAY = 0.5
MAX_DELAY = 2.5


def get_app_settings():
    """Fetches settings from Google Sheet, providing defaults."""
    settings = get_settings()
    # No longer need password logic here
    return {
        "MAX_PASTE": int(settings.get("MAX_PASTE", DEFAULT_SETTINGS["MAX_PASTE"])),
        "FRAUD_SCORE_LEVEL": int(settings.get("FRAUD_SCORE_LEVEL", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"])),
        "MAX_WORKERS": int(settings.get("MAX_WORKERS", DEFAULT_SETTINGS["MAX_WORKERS"])),
        "SCAMALYTICS_API_KEY": settings.get("SCAMALYTICS_API_KEY", DEFAULT_SETTINGS["SCAMALYTICS_API_KEY"]),
        "SCAMALYTICS_API_URL": settings.get("SCAMALYTICS_API_URL", DEFAULT_SETTINGS["SCAMALYTICS_API_URL"]),
        "SCAMALYTICS_USERNAME": settings.get("SCAMALYTICS_USERNAME", DEFAULT_SETTINGS["SCAMALYTICS_USERNAME"])
    }

def validate_proxy_format(proxy_line):
    """Validate that proxy has complete format: host:port:username:password"""
    try:
        parts = proxy_line.strip().split(":")
        if len(parts) == 4:
            host, port, user, password = parts
            # Basic check: ensure all parts have some content
            if host and port and user and password:
                return True
        return False
    except Exception as e:
        logger.error(f"Error validating proxy format '{proxy_line}': {e}")
        return False


def get_ip_from_proxy(proxy_line):
    """Extract IP using the proxy. Returns IP string or None."""
    if not validate_proxy_format(proxy_line):
        return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}", # Use http for https requests via proxy
        }
        session = requests.Session()
        # Configure retries for robustness
        retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        response = session.get(
            "https://api.ipify.org", # Simple service to get public IP
            proxies=proxies,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        response.raise_for_status() # Raise exception for bad status codes
        ip = response.text.strip()
        # Basic IP format validation (optional but good)
        if ip and '.' in ip and len(ip.split('.')) == 4:
            return ip
        else:
            logger.warning(f"Invalid IP format received from ipify for {proxy_line}: {ip}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"❌ Failed to get IP from proxy {proxy_line}: {e}")
        return None
    except Exception as e: # Catch any other unexpected errors
        logger.error(f"❌ Unexpected error getting IP from proxy {proxy_line}: {e}", exc_info=True)
        return None


def get_fraud_score(ip, proxy_line, api_key, api_url, api_user):
    """Get fraud score via Scamalytics v3 API. Returns score (int) or None."""
    if not validate_proxy_format(proxy_line):
        return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_url = f"http://{user}:{pw}@{host}:{port}"
        proxies = { "http": proxy_url, "https": proxy_url } # Need https proxy for https API call

        session = requests.Session()
        # Configure retries for robustness
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        # Construct the correct API URL
        url = f"{api_url.rstrip('/')}/{api_user}/?key={api_key}&ip={ip}"

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json", # Expecting JSON response
        }

        response = session.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            try:
                data = response.json()
                if data.get("scamalytics", {}).get("status") == "ok":
                    score = data.get("scamalytics", {}).get("scamalytics_score")
                    if score is not None:
                        return int(score)
                    else:
                        logger.warning(f"Scamalytics API OK but no score returned for IP {ip} via proxy {proxy_line}")
                else:
                    api_status = data.get('scamalytics', {}).get('status', 'N/A')
                    logger.error(f"Scamalytics API returned error status '{api_status}' for IP {ip} via proxy {proxy_line}")
            except requests.exceptions.JSONDecodeError:
                logger.error(f"Failed to decode JSON response from Scamalytics for IP {ip} via proxy {proxy_line}. Response text: {response.text[:200]}")
        else:
            logger.error(f"Scamalytics API request failed for IP {ip} via proxy {proxy_line}: HTTP {response.status_code} {response.text[:200]}") # Log only beginning of error page

    except requests.exceptions.RequestException as e:
        logger.error(f"⚠️ Network error checking Scamalytics API for IP {ip} via proxy {proxy_line}: {e}")
    except Exception as e: # Catch any other unexpected errors
        logger.error(f"⚠️ Unexpected error checking Scamalytics API for IP {ip} via proxy {proxy_line}: {e}", exc_info=True)
    return None


def single_check_proxy(proxy_line, fraud_score_level, api_key, api_url, api_user):
    """Checks a single proxy: gets its public IP and checks its fraud score."""
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY)) # Be polite to APIs

    if not validate_proxy_format(proxy_line):
        logger.warning(f"❌ Format validation failed for: {proxy_line}")
        return None # Skip invalid format

    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        logger.warning(f"❌ Could not get public IP for: {proxy_line}")
        return None # Skip if IP retrieval fails

    score = get_fraud_score(ip, proxy_line, api_key, api_url, api_user)
    if score is not None:
        if score <= fraud_score_level:
            logger.info(f"✅ Good proxy found: {proxy_line} (IP: {ip}, Score: {score})")
            return {"proxy": proxy_line, "ip": ip} # Return good proxy info
        else:
            logger.info(f"❌ Bad proxy score: {proxy_line} (IP: {ip}, Score: {score})")
            # Log bad proxy to Google Sheet cache
            try:
                log_bad_proxy(proxy_line, ip, score)
            except Exception as e:
                logger.error(f"Error logging bad proxy '{proxy_line}' to sheet: {e}")
            return None # Not a good proxy
    else:
        logger.warning(f"❓ Could not get fraud score for: {proxy_line} (IP: {ip})")
        return None # Skip if score check fails


@app.before_request
def before_request_func():
    """Skip checks for static files, favicons, login/logout routes."""
    if request.path.startswith(('/static', '/login', '/logout')) or request.path.endswith(('.ico', '.png')):
        return
    pass # No other actions needed here now


# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if current_user.is_authenticated:
        # Redirect based on role if already logged in
        return redirect(url_for('admin') if current_user.is_admin else url_for('index'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'

        # --- Basic User Lookup (Replace with DB in production) ---
        user_to_login = None
        for uid, user_obj in users.items():
            if user_obj.username == username:
                user_to_login = user_obj
                break
        # --- Basic Password Check (Replace with hashing in production) ---
        if user_to_login and user_to_login.password == password:
            login_user(user_to_login, remember=remember)
            next_page = request.args.get('next')

            # Security: Prevent redirecting non-admins to admin areas via 'next'
            if next_page and not current_user.is_admin and ('/admin' in next_page or '/delete-used-ip' in next_page):
                 flash("Redirecting to user dashboard.", "info")
                 next_page = url_for('index') # Force redirect to index

            # Convenience: Redirect admin users trying to access index back to admin
            if current_user.is_admin and next_page == url_for('index'):
                 next_page = url_for('admin')

            logger.info(f"User '{username}' logged in successfully.")
            return redirect(next_page or (url_for('admin') if current_user.is_admin else url_for('index')))
        else:
            logger.warning(f"Failed login attempt for username: '{username}'")
            error = 'Invalid Credentials. Please try again.'

    return render_template('login.html', error=error)


@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    username = current_user.username
    logout_user()
    flash('You have been logged out.', 'info')
    logger.info(f"User '{username}' logged out.")
    return redirect(url_for('login')) # Redirect to login page after logout


@app.route("/", methods=["GET", "POST"])
@login_required # Requires any logged-in user
def index():
    """Main proxy checker page."""
    try:
        settings = get_app_settings()
    except Exception as e:
        logger.critical(f"CRITICAL ERROR getting app settings: {e}", exc_info=True)
        return render_template("error.html", error="Could not load critical application settings. Please check configuration."), 500

    # Extract settings for clarity
    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    API_KEY = settings["SCAMALYTICS_API_KEY"]
    API_URL = settings["SCAMALYTICS_API_URL"]
    API_USER = settings["SCAMALYTICS_USERNAME"]

    results = []
    message = None # Use None for no message initially

    if request.method == "POST":
        start_time = time.time()
        proxies_input = []
        input_count = 0
        truncation_warning = ""

        # --- Handle File Upload or Text Input ---
        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            try:
                file = request.files['proxyfile']
                # Limit read size for safety? Maybe not needed for simple text files.
                all_lines = file.read().decode("utf-8", errors='ignore').strip().splitlines()
                input_count = len(all_lines)
                if input_count > MAX_PASTE:
                    truncation_warning = f" Input truncated to the first {MAX_PASTE} proxies."
                    proxies_input = all_lines[:MAX_PASTE]
                else:
                    proxies_input = all_lines
                logger.info(f"Received {input_count} proxies via file upload.")
            except Exception as e:
                logger.error(f"Error reading proxy file: {e}", exc_info=True)
                message = "Error reading uploaded file. Please ensure it's a valid text file."
                # Return early if file read fails
                return render_template("index.html", results=[], message=message, max_paste=MAX_PASTE, settings=settings)

        elif 'proxytext' in request.form and request.form.get("proxytext", "").strip():
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            input_count = len(all_lines)
            if input_count > MAX_PASTE:
                truncation_warning = f" Input truncated to the first {MAX_PASTE} proxies."
                proxies_input = all_lines[:MAX_PASTE]
            else:
                proxies_input = all_lines
            logger.info(f"Received {input_count} proxies via text input.")
        else:
             message = "Please paste proxies or upload a file."
             # Return early if no input provided
             return render_template("index.html", results=[], message=message, max_paste=MAX_PASTE, settings=settings)


        # --- Load Caches ---
        try:
            used_ips_records = get_all_used_ips()
            # Extract IPs and Proxies into sets for efficient lookup
            used_ips_list = {r.get('IP') for r in used_ips_records if r.get('IP')}
            used_proxy_cache = {r.get('Proxy') for r in used_ips_records if r.get('Proxy')}
            logger.info(f"Loaded {len(used_proxy_cache)} used proxies from cache.")
        except Exception as e:
            logger.error(f"Error loading used proxy cache: {e}", exc_info=True)
            used_ips_list = set()
            used_proxy_cache = set()
            message = "Warning: Could not load used proxy cache." # Inform user

        try:
            bad_proxy_cache = set(get_bad_proxies_list())
            logger.info(f"Loaded {len(bad_proxy_cache)} bad proxies from cache.")
        except Exception as e:
            logger.error(f"Error loading bad proxy cache: {e}", exc_info=True)
            bad_proxy_cache = set()
            # If message isn't set yet, add this warning
            if not message: message = "Warning: Could not load bad proxy cache."
            else: message += " Could not load bad proxy cache."


        # --- Filter and Prepare Proxies for Checking ---
        proxies_to_check = []
        invalid_format_proxies = []
        used_count_prefilter = 0
        bad_count_prefilter = 0

        unique_proxies_input = set(p.strip() for p in proxies_input if p.strip()) # Deduplicate input

        for proxy in unique_proxies_input:
            if not validate_proxy_format(proxy):
                invalid_format_proxies.append(proxy)
                continue # Skip invalid format

            if proxy in used_proxy_cache:
                used_count_prefilter += 1
                continue # Skip already used proxy string

            if proxy in bad_proxy_cache:
                bad_count_prefilter += 1
                continue # Skip known bad proxy string

            proxies_to_check.append(proxy)

        processed_count = len(proxies_to_check)
        logger.info(f"Prefiltering complete: "
                    f"{len(unique_proxies_input)} unique inputs -> "
                    f"{len(invalid_format_proxies)} invalid format, "
                    f"{used_count_prefilter} used (by proxy string), "
                    f"{bad_count_prefilter} bad cache. "
                    f"{processed_count} proxies remaining to check.")

        # --- Execute Checks Concurrently ---
        good_proxy_results = [] # Store results from successful checks
        if proxies_to_check:
            actual_workers = min(MAX_WORKERS, processed_count) # Don't start more workers than needed
            logger.info(f"Starting check for {processed_count} proxies using {actual_workers} workers...")
            with ThreadPoolExecutor(max_workers=actual_workers) as executor:
                # Submit tasks
                futures = {executor.submit(single_check_proxy, proxy, FRAUD_SCORE_LEVEL, API_KEY, API_URL, API_USER): proxy for proxy in proxies_to_check}

                # Process completed tasks
                for future in as_completed(futures):
                    proxy_line = futures[future]
                    try:
                        result = future.result()
                        if result:
                            # Check if the *result IP* is in the used IP list
                            result['used'] = result.get('ip') in used_ips_list
                            good_proxy_results.append(result)
                    except Exception as exc:
                        logger.error(f'Proxy {proxy_line} generated an exception during check: {exc}', exc_info=True)

            logger.info(f"Finished checking. Found {len(good_proxy_results)} potential good proxies.")

        # --- Final Processing and Message Construction ---
        final_results_display = sorted(good_proxy_results, key=lambda x: x['used']) # Show non-used first

        good_count_final = len([r for r in final_results_display if not r['used']])
        used_count_final = len([r for r in final_results_display if r['used']])
        invalid_format_count = len(invalid_format_proxies)

        format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
        prefilter_msg = f" (Skipped {used_count_prefilter} used cache, {bad_count_prefilter} bad cache)." if used_count_prefilter > 0 or bad_count_prefilter > 0 else ""

        if good_count_final > 0 or used_count_final > 0:
            message_prefix = f"✅ Processed {processed_count} proxies ({input_count} submitted{format_warning})."
            message_suffix = f" Found {good_count_final} good proxies ({used_count_final} previously used IPs found).{truncation_warning}{prefilter_msg}"
            message = message_prefix + message_suffix
        else:
             message = f"⚠️ Processed {processed_count} proxies ({input_count} submitted{format_warning}). No new good proxies found.{truncation_warning}{prefilter_msg}"

        results = final_results_display # Assign sorted results for display
        end_time = time.time()
        logger.info(f"Request processing took {end_time - start_time:.2f} seconds.")

    # Always pass settings to the template
    return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)


@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    """Endpoint called by JS when 'Copy' is clicked."""
    data = request.get_json()
    proxy_line = data.get("proxy") if data else None

    if not proxy_line:
        return jsonify({"status": "error", "message": "Invalid request data"}), 400

    # Basic format check before proceeding
    if not validate_proxy_format(proxy_line):
         logger.warning(f"Track-used attempt with invalid format: {proxy_line}")
         return jsonify({"status": "error", "message": "Invalid proxy format"}), 400

    try:
        # Get the IP associated with this proxy to add to the used list
        ip = get_ip_from_proxy(proxy_line)
        if ip:
            if add_used_ip(ip, proxy_line):
                 logger.info(f"Marked proxy as used: {proxy_line} (IP: {ip})")
                 return jsonify({"status": "success"})
            else:
                 logger.error(f"Failed to add used IP/Proxy to sheet: {proxy_line} (IP: {ip})")
                 return jsonify({"status": "error", "message": "Failed to update usage status"}), 500
        else:
            logger.warning(f"Could not get IP for proxy to mark as used: {proxy_line}")
            return jsonify({"status": "error", "message": "Could not verify proxy IP"}), 400
    except Exception as e:
        logger.error(f"Error tracking used proxy '{proxy_line}': {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal server error"}), 500


# --- Admin Routes (Protected) ---

@app.route("/admin")
@admin_required
def admin():
    """Admin dashboard page."""
    try:
        settings = get_app_settings()
        stats = {
            "total_checks": "N/A (Vercel)",
            "total_good": "N/A", # get_good_proxies was removed
            "max_paste": settings["MAX_PASTE"],
            "fraud_score_level": settings["FRAUD_SCORE_LEVEL"],
            "max_workers": settings["MAX_WORKERS"],
            "scamalytics_api_key": settings["SCAMALYTICS_API_KEY"],
            "scamalytics_api_url": settings["SCAMALYTICS_API_URL"],
            "scamalytics_username": settings["SCAMALYTICS_USERNAME"]
        }
        used_ips = get_all_used_ips() # Get list of used proxies/IPs
        # Pass empty lists for removed features
        return render_template( "admin.html", stats=stats, used_ips=used_ips, good_proxies=[], blocked_ips=[] )
    except Exception as e:
        logger.error(f"Admin panel error: {e}", exc_info=True)
        flash("Error loading admin panel data.", "danger")
        return render_template("admin.html", stats={}, used_ips=[], good_proxies=[], blocked_ips=[]) # Render template with empty data on error


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    """Admin settings page."""
    # Load current settings safely
    try:
        current_settings = get_app_settings()
    except Exception as e:
        logger.critical(f"CRITICAL ERROR getting app settings in ADMIN: {e}", exc_info=True)
        flash("Could not load current settings. Check configuration.", "danger")
        # Render with defaults if loading fails
        return render_template("admin_settings.html", settings=DEFAULT_SETTINGS, message=None)

    message = None
    if request.method == "POST":
        # --- Extract form data ---
        try: max_paste = int(request.form.get("max_paste", DEFAULT_SETTINGS["MAX_PASTE"]))
        except ValueError: max_paste = DEFAULT_SETTINGS["MAX_PASTE"]

        try: fraud_score_level = int(request.form.get("fraud_score_level", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]))
        except ValueError: fraud_score_level = DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]

        try: max_workers = int(request.form.get("max_workers", DEFAULT_SETTINGS["MAX_WORKERS"]))
        except ValueError: max_workers = DEFAULT_SETTINGS["MAX_WORKERS"]

        scamalytics_api_key = request.form.get("scamalytics_api_key", "").strip()
        scamalytics_api_url = request.form.get("scamalytics_api_url", "").strip()
        scamalytics_username = request.form.get("scamalytics_username", "").strip()

        # --- Validate form data ---
        error = False
        if not (5 <= max_paste <= 100): message = "Max proxies must be 5-100"; error = True
        elif not (0 <= fraud_score_level <= 100): message = "Fraud score must be 0-100"; error = True
        elif not (1 <= max_workers <= 100): message = "Max workers must be 1-100"; error = True
        elif len(scamalytics_api_key) < 5: message = "API Key too short"; error = True
        elif not scamalytics_api_url.startswith("http"): message = "API URL invalid"; error = True
        elif len(scamalytics_username) < 3: message = "Username too short"; error = True

        if not error:
            # --- Update settings in Google Sheet ---
            logger.info("Attempting to update settings...")
            success = True
            if not update_setting("MAX_PASTE", str(max_paste)): success = False
            if not update_setting("FRAUD_SCORE_LEVEL", str(fraud_score_level)): success = False
            if not update_setting("MAX_WORKERS", str(max_workers)): success = False
            if not update_setting("SCAMALYTICS_API_KEY", scamalytics_api_key): success = False
            if not update_setting("SCAMALYTICS_API_URL", scamalytics_api_url): success = False
            if not update_setting("SCAMALYTICS_USERNAME", scamalytics_username): success = False

            if success:
                logger.info("Settings updated successfully.")
                message = "Settings updated successfully"
                flash(message, "success")
                current_settings = get_app_settings() # Refresh settings display
            else:
                logger.error("Failed to update one or more settings in Google Sheet.")
                message = "Error saving one or more settings."
                flash(message, "danger")
        else:
             # If validation failed, flash the error message
             flash(message, "danger")
             # Keep the submitted (potentially invalid) values in the form for correction
             current_settings = {
                "MAX_PASTE": max_paste, "FRAUD_SCORE_LEVEL": fraud_score_level, "MAX_WORKERS": max_workers,
                "SCAMALYTICS_API_KEY": scamalytics_api_key, "SCAMALYTICS_API_URL": scamalytics_api_url,
                "SCAMALYTICS_USERNAME": scamalytics_username
             }

    # Pass current settings (or submitted values on error) to template
    return render_template("admin_settings.html", settings=current_settings, message=None) # Use flash for messages now


@app.route("/delete-used-ip/<ip>")
@admin_required
def delete_used_ip_route(ip):
    """Deletes a used IP record."""
    try:
        if delete_used_ip(ip):
            flash(f"Removed used IP record for {ip}.", "success")
            logger.info(f"Admin deleted used IP record: {ip}")
        else:
            flash(f"Could not find used IP record for {ip}.", "warning")
            logger.warning(f"Admin attempted to delete non-existent used IP: {ip}")
    except Exception as e:
        logger.error(f"Error deleting used IP {ip}: {e}", exc_info=True)
        flash("Error deleting used IP record.", "danger")
    return redirect(url_for("admin"))


@app.route('/static/<path:path>')
def send_static(path):
    """Serves static files."""
    return send_from_directory('static', path)


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"404 Not Found: {request.path}")
    return render_template('error.html', error='Page Not Found'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"500 Internal Server Error: {e}", exc_info=True)
    return render_template('error.html', error='An internal server error occurred.'), 500

# --- Main Execution ---
if __name__ == "__main__":
    # Ensure debug is False if running in production directly
    # Use gunicorn or similar for production deployments
    app.run(host="0.0.0.0", port=5000, debug=False) # Turn debug OFF for production
