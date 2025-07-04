# app.py
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
import json
import gspread
from oauth2client.service_account import ServiceAccountCredentials
#
# --- CHANGE 1: Corrected the import statement to include all necessary functions ---
from sheets_util import get_settings, update_setting, add_used_ip, delete_used_ip, get_all_used_ips, log_good_proxy, get_good_proxies

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
    "MAX_WORKERS": 5
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

def get_app_settings():
    settings = get_settings()
    return {
        "MAX_PASTE": int(settings.get("MAX_PASTE", DEFAULT_SETTINGS["MAX_PASTE"])),
        "FRAUD_SCORE_LEVEL": int(settings.get("FRAUD_SCORE_LEVEL", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"])),
        "MAX_WORKERS": int(settings.get("MAX_WORKERS", DEFAULT_SETTINGS["MAX_WORKERS"]))
    }

def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
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
        logger.error(f"❌ Failed to get IP from proxy {proxy}: {e}")
        return None

def get_fraud_score(ip, proxy_line):
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

def single_check_proxy(proxy_line, fraud_score_level):
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    score = get_fraud_score(ip, proxy_line)
    if score is not None and score <= fraud_score_level:
        return {"proxy": proxy_line, "ip": ip}
    return None

@app.route("/", methods=["GET", "POST"])
def index():
    settings = get_app_settings()
    MAX_PASTE = settings["MAX_PASTE"]
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    
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

        proxies = list(set(p.strip() for p in proxies if p.strip()))
        processed_count = len(proxies)

        if proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, proxy, FRAUD_SCORE_LEVEL) for proxy in proxies]
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
                            "used": used
                        })

            if results:
                for item in results:
                    if not item["used"]:
                        try:
                            ip = get_ip_from_proxy(item["proxy"])
                            if ip:
                                log_good_proxy(item["proxy"], ip)
                        except Exception as e:
                            logger.error(f"Error logging good proxy: {e}")

                good_count = len([r for r in results if not r['used']])
                used_count = len([r for r in results if r['used']])
                
                message = f"✅ Processed {processed_count} proxies ({input_count} submitted). Found {good_count} good proxies ({used_count} used).{truncation_warning}"
            else:
                message = f"⚠️ Processed {processed_count} proxies ({input_count} submitted). No good proxies found.{truncation_warning}"
        else:
            message = f"⚠️ No valid proxies provided. Submitted {input_count} lines, but none were valid proxy formats."
    
    # --- CHANGE 2: Added 'settings=settings' to the render_template call ---
    return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)

@app.route("/track-used", methods=["POST"])
def track_used():
    data = request.get_json()
    if data and "proxy" in data:
        try:
            ip = get_ip_from_proxy(data["proxy"])
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
            "max_workers": settings["MAX_WORKERS"]
        }
        
        used_ips = get_all_used_ips()
        good_proxies = get_good_proxies()
        
        return render_template(
            "admin.html", 
            logs=[],
            stats=stats,
            graph_url=None,
            used_ips=used_ips,
            good_proxies=good_proxies
        )
    except Exception as e:
        logger.error(f"Admin panel error: {e}")
        return f"Admin Error: {str(e)}", 500

@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    settings = get_app_settings()
    message = None
    
    if request.method == "POST":
        max_paste = request.form.get("max_paste")
        fraud_score_level = request.form.get("fraud_score_level")
        max_workers = request.form.get("max_workers")
        
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
        
        # Only update if no validation errors
        if not message:
            update_setting("MAX_PASTE", str(max_paste))
            update_setting("FRAUD_SCORE_LEVEL", str(fraud_score_level))
            update_setting("MAX_WORKERS", str(max_workers))
            settings = get_app_settings()  # Refresh settings
            message = "Settings updated successfully"
    
    return render_template("admin_settings.html", settings=settings, message=message)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
