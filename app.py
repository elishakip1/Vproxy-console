from flask import Flask, request, render_template, redirect, url_for, jsonify, send_from_directory
import os
import time
import requests
# BeautifulSoup is no longer needed for fraud score
# from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys
# --- UPDATED IMPORTS ---
# Removed: log_good_proxy, log_user_access, get_blocked_ips,
#          add_blocked_ip, remove_blocked_ip, is_ip_blocked
from sheets_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip,
    get_all_used_ips, get_good_proxies, # Kept get_good_proxies for stats
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

# Default configuration values
DEFAULT_SETTINGS = {
    "MAX_PASTE": 30,
    "FRAUD_SCORE_LEVEL": 0,
    "MAX_WORKERS": 5,
    "ALLOWED_PASSWORDS": "123456_country-us_state-washington_session-ddMJlZq3_lifetime-168h,JBZAeWoqvF1XqOuw,68166538",  # Comma-separated list
    # --- NEW SETTINGS ---
    "SCAMALYTICS_API_KEY": "YOUR_API_KEY_HERE", # Add your key to Google Sheets
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/", # US Node
    "SCAMALYTICS_USERNAME": "YOUR_USERNAME_HERE" # e.g., keishamartell329
}

# User agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

# Request timeout
REQUEST_TIMEOUT = 5
MIN_DELAY = 0.5
MAX_DELAY = 2.5

# IP restriction for admin
ADMIN_IP = "40.67.137.199" # This is currently disabled in before_request

def get_app_settings():
    settings = get_settings()
    allowed_passwords_str = settings.get("ALLOWED_PASSWORDS", DEFAULT_SETTINGS["ALLOWED_PASSWORDS"])

    # --- FIX: Cast to string *before* splitting ---
    allowed_passwords = [pwd.strip() for pwd in str(allowed_passwords_str).split(",") if pwd.strip()]

    return {
        "MAX_PASTE": int(settings.get("MAX_PASTE", DEFAULT_SETTINGS["MAX_PASTE"])),
        "FRAUD_SCORE_LEVEL": int(settings.get("FRAUD_SCORE_LEVEL", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"])),
        "MAX_WORKERS": int(settings.get("MAX_WORKERS", DEFAULT_SETTINGS["MAX_WORKERS"])),
        "ALLOWED_PASSWORDS": allowed_passwords,
        # --- NEW SETTINGS ---
        "SCAMALYTICS_API_KEY": settings.get("SCAMALYTICS_API_KEY", DEFAULT_SETTINGS["SCAMALYTICS_API_KEY"]),
        "SCAMALYTICS_API_URL": settings.get("SCAMALYTICS_API_URL", DEFAULT_SETTINGS["SCAMALYTICS_API_URL"]),
        "SCAMALYTICS_USERNAME": settings.get("SCAMALYTICS_USERNAME", DEFAULT_SETTINGS["SCAMALYTICS_USERNAME"])
    }

def validate_proxy_format(proxy_line):
    """Validate that proxy has complete format: host:port:username:password"""
    try:
        parts = proxy_line.strip().split(":")
        if len(parts) == 4:  # host:port:user:password
            host, port, user, password = parts
            # Check that all parts are non-empty
            if host and port and user and password:
                return True
        return False
    except Exception as e:
        logger.error(f"Error validating proxy format: {e}")
        return False

def validate_proxy_password(proxy_line, allowed_passwords):
    """Validate that proxy password matches any of the allowed passwords"""
    try:
        parts = proxy_line.strip().split(":")
        if len(parts) == 4:  # host:port:user:password
            host, port, user, password = parts
            # Check that all parts are non-empty AND password matches any allowed password
            if host and port and user and password and password in allowed_passwords:
                return True
        return False
    except Exception as e:
        logger.error(f"Error validating proxy password: {e}")
        return False

def get_ip_from_proxy(proxy_line, allowed_passwords):
    """Extract IP from proxy - with password validation"""
    if not validate_proxy_password(proxy_line, allowed_passwords):
        return None

    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }

        session = requests.Session()
        retries = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        ip = session.get(
            "https://api.ipify.org",
            proxies=proxies,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        ).text
        return ip
    except Exception as e:
        logger.error(f"❌ Failed to get IP from proxy {proxy_line}: {e}")
        return None

def get_fraud_score(ip, proxy_line, allowed_passwords, api_key, api_url, api_user):
    """Get fraud score via Scamalytics v3 API - with password validation"""
    if not validate_proxy_password(proxy_line, allowed_passwords):
        return None

    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_url = f"http://{user}:{pw}@{host}:{port}"
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }

        session = requests.Session()
        retries = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        session.mount('http://', HTTPAdapter(max_retries=retries))
        session.mount('https://', HTTPAdapter(max_retries=retries))

        # --- Use the correct URL format with username ---
        url = f"{api_url.rstrip('/')}/{api_user}/?key={api_key}&ip={ip}"

        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json", # Request JSON response
        }

        response = session.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 200:
            data = response.json()
            # Check for API-level error
            if data.get("scamalytics", {}).get("status") == "ok":
                score = data.get("scamalytics", {}).get("scamalytics_score")
                if score is not None:
                    return int(score)
                else:
                    logger.error(f"Scamalytics API OK but no score for {ip}")
            else:
                logger.error(f"Scamalytics API error for {ip}: {data.get('scamalytics', {}).get('status')}")
        else:
            logger.error(f"Scamalytics API request failed for {ip}: HTTP {response.status_code} {response.text}")

    except Exception as e:
        logger.error(f"⚠️ Error checking Scamalytics API for {ip}: {e}")
    return None

def single_check_proxy(proxy_line, fraud_score_level, allowed_passwords, api_key, api_url, api_user):
    """Check single proxy - with password validation"""
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

    # Validate password first
    if not validate_proxy_password(proxy_line, allowed_passwords):
        logger.warning(f"❌ Proxy rejected - invalid password or format: {proxy_line}")
        return None

    ip = get_ip_from_proxy(proxy_line, allowed_passwords)
    if not ip:
        return None

    score = get_fraud_score(ip, proxy_line, allowed_passwords, api_key, api_url, api_user)

    if score is not None:
        if score <= fraud_score_level:
            # Good proxy
            return {"proxy": proxy_line, "ip": ip}
        else:
            # Bad proxy - log it to the cache
            try:
                log_bad_proxy(proxy_line, ip, score)
            except Exception as e:
                logger.error(f"Error logging bad proxy from thread: {e}")
            return None # Not a good proxy

    return None # API check failed

# --- UPDATED: REMOVED IP BLOCKING AND ACCESS LOGGING ---
@app.before_request
def track_and_block():
    # Skip static files AND favicons
    if request.path.startswith('/static') or request.path.endswith(('.ico', '.png')):
        return

    # Get client IP (handling proxy headers)
    # if request.headers.getlist("X-Forwarded-For"):
    #     ip = request.headers.getlist("X-Forwarded-For")[0]
    # else:
    #     ip = request.remote_addr

    # --- REMOVED: Access Logging ---
    # user_agent = request.headers.get('User-Agent', 'Unknown')
    # log_user_access(ip, user_agent)

    # --- REMOVED: IP Blocking Check ---
    # if not request.path.startswith('/admin') and is_ip_blocked(ip):
    #     return render_template("blocked.html"), 403

    # --- REMOVED: Admin IP Lock (as requested earlier) ---
    # if request.path.startswith('/admin') and ip != ADMIN_IP:
    #     return render_template("admin_blocked.html"), 403
    pass # No actions needed before request anymore

@app.route("/", methods=["GET", "POST"])
def index():
    try:
        settings = get_app_settings()
    except Exception as e:
        # Catch the crash if it happens and show a user-friendly error
        logger.error(f"CRITICAL: Failed to get app settings: {e}", exc_info=True)
        return render_template("error.html", error="Could not load app settings. Check Google Sheets configuration and permissions."), 500

    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    ALLOWED_PASSWORDS = settings["ALLOWED_PASSWORDS"]
    # --- Get new settings ---
    API_KEY = settings["SCAMALYTICS_API_KEY"]
    API_URL = settings["SCAMALYTICS_API_URL"]
    API_USER = settings["SCAMALYTICS_USERNAME"]

    results = []
    message = ""

    if request.method == "POST":
        proxies = []
        all_lines = []
        input_count = 0
        truncation_warning = ""

        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            file = request.files['proxyfile']
            all_lines = file.read().decode("utf-8").strip().splitlines()
            input_count = len(all_lines)
            if input_count > MAX_PASTE:
                truncation_warning = f" Only the first {MAX_PASTE} proxies were processed."
                all_lines = all_lines[:MAX_PASTE]
            proxies = all_lines
        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            input_count = len(all_lines)
            if input_count > MAX_PASTE:
                truncation_warning = f" Only the first {MAX_PASTE} proxies were processed."
                all_lines = all_lines[:MAX_PASTE]
            proxies = all_lines

        # --- Load caches *before* processing ---
        try:
            used_ips_records = get_all_used_ips()
            used_ips_list = [r['IP'] for r in used_ips_records]
            # Cache of proxy strings that are already marked as used
            used_proxy_cache = set([r['Proxy'] for r in used_ips_records])
        except Exception as e:
            logger.error(f"Error getting used IP/Proxy cache: {e}")
            used_ips_list = []
            used_proxy_cache = set()

        try:
            # Cache of proxy strings that are already marked as bad
            bad_proxy_cache = set(get_bad_proxies_list())
        except Exception as e:
            logger.error(f"Error getting bad proxy cache: {e}")
            bad_proxy_cache = set()


        # Filter out empty lines and validate format
        valid_format_proxies = []
        invalid_format_proxies = []

        for proxy in proxies:
            proxy = proxy.strip()
            if not proxy:
                continue

            if validate_proxy_format(proxy):
                valid_format_proxies.append(proxy)
            else:
                invalid_format_proxies.append(proxy)
                logger.warning(f"Invalid proxy format: {proxy}")

        # --- Pre-filter proxies based on caches and password ---
        proxies_to_check = []
        invalid_password_proxies = []
        used_count_prefilter = 0
        bad_count_prefilter = 0

        for proxy in valid_format_proxies:
            if proxy in used_proxy_cache:
                used_count_prefilter += 1
                continue  # Exempt from search

            if proxy in bad_proxy_cache:
                bad_count_prefilter += 1
                continue  # Exempt from search (already known bad)

            if validate_proxy_password(proxy, ALLOWED_PASSWORDS):
                proxies_to_check.append(proxy)
            else:
                invalid_password_proxies.append(proxy)
                logger.warning(f"Invalid proxy password: {proxy}")

        logger.info(f"Prefiltered: {used_count_prefilter} used, {bad_count_prefilter} bad.")
        processed_count = len(proxies_to_check)


        if invalid_format_proxies:
            logger.warning(f"Found {len(invalid_format_proxies)} invalid format proxies")

        if invalid_password_proxies:
            logger.warning(f"Found {len(invalid_password_proxies)} error proxies")

        # Only show failed.html if ALL proxies have invalid passwords AND there are no valid format proxies
        if len(proxies_to_check) == 0 and len(valid_format_proxies) > 0 and len(invalid_password_proxies) > 0:
            logger.warning("All proxies have invalid passwords or are cached")
            # Only render failed if the *reason* is password
            if len(invalid_password_proxies) == len(valid_format_proxies):
                 return render_template("failed.html"), 403

        if proxies_to_check:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                # Pass API key, URL, and User to the worker
                futures = [executor.submit(single_check_proxy, proxy, FRAUD_SCORE_LEVEL, ALLOWED_PASSWORDS, API_KEY, API_URL, API_USER) for proxy in proxies_to_check]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        try:
                            # Check if the *exit IP* is in the used list
                            used = result["ip"] in used_ips_list
                        except Exception as e:
                            logger.error(f"Error checking used IPs: {e}")
                            used = False

                        results.append({
                            "proxy": result["proxy"],
                            "ip": result["ip"],
                            "used": used
                        })

            if results:
                # --- REMOVED: log_good_proxy call ---
                # for item in results:
                #     if not item["used"]:
                #         try:
                #             log_good_proxy(item["proxy"], item["ip"])
                #         except Exception as e:
                #             logger.error(f"Error logging good proxy: {e}")

                good_count = len([r for r in results if not r['used']])
                used_count = len([r for r in results if r['used']])

                invalid_format_count = len(invalid_format_proxies)
                invalid_password_count = len(invalid_password_proxies)

                format_warning = f" ({invalid_format_count}  error)" if invalid_format_count > 0 else ""
                password_warning = f" ({invalid_password_count} invalid password)" if invalid_password_count > 0 else ""
                prefilter_msg = f" (Skipped {used_count_prefilter} used, {bad_count_prefilter} bad)."

                message = f"✅ Processed {processed_count} proxies ({input_count} submitted{format_warning}{password_warning}). Found {good_count} good proxies ({used_count} used).{truncation_warning}{prefilter_msg}"
            else:
                invalid_format_count = len(invalid_format_proxies)
                invalid_password_count = len(invalid_password_proxies)

                format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
                password_warning = f" ({invalid_password_count} invalid password)" if invalid_password_count > 0 else ""
                prefilter_msg = f" (Skipped {used_count_prefilter} used, {bad_count_prefilter} bad)."

                message = f"⚠️ Processed {processed_count} proxies ({input_count} submitted{format_warning}{password_warning}). No good proxies found.{truncation_warning}{prefilter_msg}"
        else:
            # No valid proxies at all (either format or password or cached)
            prefilter_msg = f" (Skipped {used_count_prefilter} already used, {bad_count_prefilter} cached as bad)"
            message = f"⚠️ No valid proxies provided. Submitted {input_count} lines, but none were valid proxy formats (host:port:username:password) with correct password.{prefilter_msg}"

    return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)

@app.route("/track-used", methods=["POST"])
def track_used():
    data = request.get_json()
    if data and "proxy" in data:
        try:
            # Get current allowed passwords
            settings = get_app_settings()
            allowed_passwords = settings["ALLOWED_PASSWORDS"]

            # Validate password before tracking
            if not validate_proxy_password(data["proxy"], allowed_passwords):
                return jsonify({"status": "error", "message": "Invalid password"}), 403

            ip = get_ip_from_proxy(data["proxy"], allowed_passwords)
            if ip:
                add_used_ip(ip, data["proxy"])
            return jsonify({"status": "success"})
        except Exception as e:
            logger.error(f"Error tracking used proxy: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    return jsonify({"status": "error", "message": "Invalid request"}), 400

@app.route("/delete-used-ip/<ip>")
def delete_used_ip_route(ip):
    try:
        delete_used_ip(ip)
    except Exception as e:
        logger.error(f"Error deleting used IP: {e}")
    return redirect(url_for("admin"))

# --- UPDATED ADMIN ROUTE: REMOVED BLOCKED IPS ---
@app.route("/admin")
def admin():
    try:
        settings = get_app_settings()
        stats = {
            "total_checks": "N/A (Vercel)",
            "total_good": len(get_good_proxies()), # Kept for stats display
            "max_paste": settings["MAX_PASTE"],
            "fraud_score_level": settings["FRAUD_SCORE_LEVEL"],
            "max_workers": settings["MAX_WORKERS"],
            "allowed_passwords": ", ".join(settings["ALLOWED_PASSWORDS"]),
            # --- NEW STATS ---
            "scamalytics_api_key": settings["SCAMALYTICS_API_KEY"],
            "scamalytics_api_url": settings["SCAMALYTICS_API_URL"],
            "scamalytics_username": settings["SCAMALYTICS_USERNAME"]
        }

        used_ips = get_all_used_ips()
        good_proxies = get_good_proxies() # Kept for display
        # blocked_ips = get_blocked_ips() # REMOVED

        return render_template(
            "admin.html",
            stats=stats,
            used_ips=used_ips,
            good_proxies=good_proxies,
            blocked_ips=[] # Pass empty list as blocked_ips were removed
        )
    except Exception as e:
        logger.error(f"Admin panel error: {e}", exc_info=True)
        return render_template("error.html", error=str(e)), 500

@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    try:
        settings = get_app_settings()
    except Exception as e:
        logger.error(f"CRITICAL: Failed to get app settings in ADMIN: {e}", exc_info=True)
        return render_template("error.html", error="Could not load app settings. Check Google Sheets configuration and permissions."), 500

    message = None

    if request.method == "POST":
        max_paste = request.form.get("max_paste")
        fraud_score_level = request.form.get("fraud_score_level")
        max_workers = request.form.get("max_workers")
        allowed_passwords = request.form.get("allowed_passwords")
        # --- NEW FORM FIELDS ---
        scamalytics_api_key = request.form.get("scamalytics_api_key")
        scamalytics_api_url = request.form.get("scamalytics_api_url")
        scamalytics_username = request.form.get("scamalytics_username")


        # Validate inputs
        try:
            max_paste = int(max_paste)
            if max_paste < 5 or max_paste > 100:
                message = "Max proxies must be between 5 and 100"
                raise ValueError(message)
        except (ValueError, TypeError):
            max_paste = DEFAULT_SETTINGS["MAX_PASTE"]

        try:
            fraud_score_level = int(fraud_score_level)
            if fraud_score_level < 0 or fraud_score_level > 100:
                message = "Fraud score must be between 0 and 100"
                raise ValueError(message)
        except (ValueError, TypeError):
            fraud_score_level = DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]

        try:
            max_workers = int(max_workers)
            if max_workers < 1 or max_workers > 100:
                message = "Max workers must be between 1 and 100"
                raise ValueError(message)
        except (ValueError, TypeError):
            max_workers = DEFAULT_SETTINGS["MAX_WORKERS"]

        # Validate allowed passwords
        if not allowed_passwords or len(allowed_passwords.strip()) == 0:
            message = "Allowed passwords cannot be empty"
            allowed_passwords = DEFAULT_SETTINGS["ALLOWED_PASSWORDS"]
        else:
            # Validate that we have at least one valid password
            passwords_list = [pwd.strip() for pwd in allowed_passwords.split(",") if pwd.strip()]
            if len(passwords_list) == 0:
                message = "At least one valid password is required"
                allowed_passwords = DEFAULT_SETTINGS["ALLOWED_PASSWORDS"]

        # --- VALIDATE NEW FIELDS ---
        if not scamalytics_api_key or len(scamalytics_api_key.strip()) < 5:
            message = "Scamalytics API Key seems too short"
            scamalytics_api_key = DEFAULT_SETTINGS["SCAMALYTICS_API_KEY"]

        if not scamalytics_api_url or not scamalytics_api_url.strip().startswith("http"):
            message = "Scamalytics API URL must be a valid URL"
            scamalytics_api_url = DEFAULT_SETTINGS["SCAMALYTICS_API_URL"]

        if not scamalytics_username or len(scamalytics_username.strip()) < 3:
            message = "Scamalytics Username seems too short"
            scamalytics_username = DEFAULT_SETTINGS["SCAMALYTICS_USERNAME"]


        # Only update if no validation errors
        if not message:
            update_setting("MAX_PASTE", str(max_paste))
            update_setting("FRAUD_SCORE_LEVEL", str(fraud_score_level))
            update_setting("MAX_WORKERS", str(max_workers))
            update_setting("ALLOWED_PASSWORDS", allowed_passwords.strip())
            # --- UPDATE NEW SETTINGS ---
            update_setting("SCAMALYTICS_API_KEY", scamalytics_api_key.strip())
            update_setting("SCAMALYTICS_API_URL", scamalytics_api_url.strip())
            update_setting("SCAMALYTICS_USERNAME", scamalytics_username.strip())

            settings = get_app_settings()  # Refresh settings
            message = "Settings updated successfully"

    # Pass the raw (string) version of allowed passwords to the template
    settings_display = settings.copy()
    settings_display["ALLOWED_PASSWORDS"] = ", ".join(settings["ALLOWED_PASSWORDS"])

    # Ensure the template file is in the right location!
    # Remember to move admin_settings.html into the 'templates' folder
    return render_template("admin_settings.html", settings=settings_display, message=message)

# --- REMOVED block_ip and unblock_ip routes ---
# @app.route("/admin/block-ip", methods=["POST"])
# def block_ip(): ...

# @app.route("/admin/unblock-ip/<ip>")
# def unblock_ip(ip): ...

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)