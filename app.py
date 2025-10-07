from flask import Flask, request, render_template, redirect, url_for, jsonify, send_from_directory
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import logging
import sys
from sheets_util import (
    get_settings, update_setting, add_used_ip, delete_used_ip, 
    get_all_used_ips, log_good_proxy, get_good_proxies,
    log_user_access, get_blocked_ips, add_blocked_ip, 
    remove_blocked_ip, is_ip_blocked
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
    "ALLOWED_PASSWORDS": "YzCoO3h2M4XSTjM5,JBZAeWoqvF1XqOuw,54937335"  # Comma-separated list
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
ADMIN_IP = "41.90.211.111"

def get_app_settings():
    settings = get_settings()
    allowed_passwords_str = settings.get("ALLOWED_PASSWORDS", DEFAULT_SETTINGS["ALLOWED_PASSWORDS"])
    # Convert comma-separated string to list and strip whitespace
    allowed_passwords = [pwd.strip() for pwd in allowed_passwords_str.split(",") if pwd.strip()]
    
    return {
        "MAX_PASTE": int(settings.get("MAX_PASTE", DEFAULT_SETTINGS["MAX_PASTE"])),
        "FRAUD_SCORE_LEVEL": int(settings.get("FRAUD_SCORE_LEVEL", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"])),
        "MAX_WORKERS": int(settings.get("MAX_WORKERS", DEFAULT_SETTINGS["MAX_WORKERS"])),
        "ALLOWED_PASSWORDS": allowed_passwords
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

def get_fraud_score(ip, proxy_line, allowed_passwords):
    """Get fraud score for IP using proxy - with password validation"""
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
        
        url = f"https://scamalytics.com/ip/{ip}"
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        
        response = session.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            score_div = soup.find('div', class_='score')
            if score_div and "Fraud Score:" in score_div.text:
                score_text = score_div.text.strip().split(":")[1].strip()
                return int(score_text)
    except Exception as e:
        logger.error(f"⚠️ Error checking Scamalytics for {ip}: {e}")
    return None

def single_check_proxy(proxy_line, fraud_score_level, allowed_passwords):
    """Check single proxy - with password validation"""
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    
    # Validate password first
    if not validate_proxy_password(proxy_line, allowed_passwords):
        logger.warning(f"❌ Proxy rejected - invalid password or format: {proxy_line}")
        return None
    
    ip = get_ip_from_proxy(proxy_line, allowed_passwords)
    if not ip:
        return None

    score = get_fraud_score(ip, proxy_line, allowed_passwords)
    if score is not None and score <= fraud_score_level:
        return {"proxy": proxy_line, "ip": ip}
    return None

@app.before_request
def track_and_block():
    # Skip static files
    if request.path.startswith('/static'):
        return
    
    # Get client IP (handling proxy headers)
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    
    # Log access to AccessLogs
    user_agent = request.headers.get('User-Agent', 'Unknown')
    log_user_access(ip, user_agent)
    
    # Check if IP is blocked (except for admin routes)
    if not request.path.startswith('/admin') and is_ip_blocked(ip):
        return render_template("blocked.html"), 403
    
    # Restrict admin routes to specific IP
    if request.path.startswith('/admin') and ip != ADMIN_IP:
        return render_template("admin_blocked.html"), 403

@app.route("/", methods=["GET", "POST"])
def index():
    settings = get_app_settings()
    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    ALLOWED_PASSWORDS = settings["ALLOWED_PASSWORDS"]
    
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

        # Separate valid format proxies by password validation
        valid_password_proxies = []
        invalid_password_proxies = []
        
        for proxy in valid_format_proxies:
            if validate_proxy_password(proxy, ALLOWED_PASSWORDS):
                valid_password_proxies.append(proxy)
            else:
                invalid_password_proxies.append(proxy)
                logger.warning(f"Invalid proxy password: {proxy}")

        processed_count = len(valid_password_proxies)

        if invalid_format_proxies:
            logger.warning(f"Found {len(invalid_format_proxies)} invalid format proxies")

        if invalid_password_proxies:
            logger.warning(f"Found {len(invalid_password_proxies)} error  proxies")

        # Only show failed.html if ALL proxies have invalid passwords AND there are no valid format proxies
        if len(valid_password_proxies) == 0 and len(valid_format_proxies) > 0:
            logger.warning("All proxies have invalid passwords")
            return render_template("failed.html"), 403

        if valid_password_proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, proxy, FRAUD_SCORE_LEVEL, ALLOWED_PASSWORDS) for proxy in valid_password_proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        try:
                            used_ips = [ip['IP'] for ip in get_all_used_ips()]
                            used = result["ip"] in used_ips
                        except Exception as e:
                            logger.error(f"Error checking used IPs: {e}")
                            used = False
                            
                        results.append({
                            "proxy": result["proxy"],
                            "ip": result["ip"],
                            "used": used
                        })

            if results:
                for item in results:
                    if not item["used"]:
                        try:
                            log_good_proxy(item["proxy"], item["ip"])
                        except Exception as e:
                            logger.error(f"Error logging good proxy: {e}")

                good_count = len([r for r in results if not r['used']])
                used_count = len([r for r in results if r['used']])
                
                invalid_format_count = len(invalid_format_proxies)
                invalid_password_count = len(invalid_password_proxies)
                
                format_warning = f" ({invalid_format_count}  error)" if invalid_format_count > 0 else ""
                password_warning = f" ({invalid_password_count} invalid password)" if invalid_password_count > 0 else ""
                
                message = f"✅ Processed {processed_count} proxies ({input_count} submitted{format_warning}{password_warning}). Found {good_count} good proxies ({used_count} used).{truncation_warning}"
            else:
                invalid_format_count = len(invalid_format_proxies)
                invalid_password_count = len(invalid_password_proxies)
                
                format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
                password_warning = f" ({invalid_password_count} invalid password)" if invalid_password_count > 0 else ""
                
                message = f"⚠️ Processed {processed_count} proxies ({input_count} submitted{format_warning}{password_warning}). No good proxies found.{truncation_warning}"
        else:
            # No valid proxies at all (either format or password)
            message = f"⚠️ No valid proxies provided. Submitted {input_count} lines, but none were valid proxy formats (host:port:username:password) with correct password."
    
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

@app.route("/admin")
def admin():
    try:
        settings = get_app_settings()
        stats = {
            "total_checks": "N/A (Vercel)",
            "total_good": len(get_good_proxies()),
            "max_paste": settings["MAX_PASTE"],
            "fraud_score_level": settings["FRAUD_SCORE_LEVEL"],
            "max_workers": settings["MAX_WORKERS"],
            "allowed_passwords": ", ".join(settings["ALLOWED_PASSWORDS"])
        }
        
        used_ips = get_all_used_ips()
        good_proxies = get_good_proxies()
        blocked_ips = get_blocked_ips()
        
        return render_template(
            "admin.html", 
            stats=stats,
            used_ips=used_ips,
            good_proxies=good_proxies,
            blocked_ips=blocked_ips
        )
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        return render_template("error.html", error=str(e)), 500

@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    settings = get_app_settings()
    message = None
    
    if request.method == "POST":
        max_paste = request.form.get("max_paste")
        fraud_score_level = request.form.get("fraud_score_level")
        max_workers = request.form.get("max_workers")
        allowed_passwords = request.form.get("allowed_passwords")
        
        # Validate inputs
        try:
            max_paste = int(max_paste)
            if max_paste < 5 or max_paste > 100:
                message = "Max proxies must be between 5 and 100"
                raise ValueError(message)
        except ValueError:
            max_paste = DEFAULT_SETTINGS["MAX_PASTE"]
        
        try:
            fraud_score_level = int(fraud_score_level)
            if fraud_score_level < 0 or fraud_score_level > 100:
                message = "Fraud score must be between 0 and 100"
                raise ValueError(message)
        except ValueError:
            fraud_score_level = DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]
        
        try:
            max_workers = int(max_workers)
            if max_workers < 1 or max_workers > 100:
                message = "Max workers must be between 1 and 100"
                raise ValueError(message)
        except ValueError:
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
        
        # Only update if no validation errors
        if not message:
            update_setting("MAX_PASTE", str(max_paste))
            update_setting("FRAUD_SCORE_LEVEL", str(fraud_score_level))
            update_setting("MAX_WORKERS", str(max_workers))
            update_setting("ALLOWED_PASSWORDS", allowed_passwords.strip())
            settings = get_app_settings()  # Refresh settings
            message = "Settings updated successfully"
    
    return render_template("admin_settings.html", settings=settings, message=message)

@app.route("/admin/block-ip", methods=["POST"])
def block_ip():
    ip = request.form.get("ip")
    reason = request.form.get("reason", "Abuse")
    if ip:
        if add_blocked_ip(ip, reason):
            return redirect(url_for("admin"))
        else:
            return render_template("error.html", error="Failed to block IP"), 500
    return render_template("error.html", error="Invalid IP address"), 400

@app.route("/admin/unblock-ip/<ip>")
def unblock_ip(ip):
    try:
        if remove_blocked_ip(ip):
            return redirect(url_for("admin"))
        else:
            return render_template("error.html", error="IP not found"), 404
    except Exception as e:
        logger.error(f"Error unblocking IP: {e}")
        return render_template("error.html", error=str(e)), 500

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
