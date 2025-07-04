from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for
import os
import time
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import random
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from sheets_util import add_used_ip, get_all_used_ips, delete_used_ip, log_good_proxy, get_good_proxies
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Reduced limits for Vercel compatibility
MAX_WORKERS = 5  # Reduced concurrency for Vercel timeout limits
REQUEST_TIMEOUT = 5  # Reduced timeout for Vercel
PROXY_CHECK_HARD_LIMIT = 25  # Reduced limit for Vercel
MIN_DELAY = 0.5  # Minimum delay between requests in seconds
MAX_DELAY = 2.5  # Maximum delay between requests in seconds

# User agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

def get_ip_from_proxy(proxy):
    try:
        host, port, user, pw = proxy.strip().split(":")
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        
        # Create session with retries
        session = requests.Session()
        retries = Retry(
            total=2,  # Reduced for Vercel timeout
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
        # Parse proxy details
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_url = f"http://{user}:{pw}@{host}:{port}"
        proxies = {
            "http": proxy_url,
            "https": proxy_url,
        }
        
        # Create session with retries
        session = requests.Session()
        retries = Retry(
            total=2,  # Reduced for Vercel timeout
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

def single_check_proxy(proxy_line):
    # Random delay to space out requests
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        return None

    score = get_fraud_score(ip, proxy_line)
    if score == 0:
        return {"proxy": proxy_line, "ip": ip}
    return None

@app.route("/", methods=["GET", "POST"])
def index():
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
            if input_count > PROXY_CHECK_HARD_LIMIT:
                truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
            proxies = all_lines
        elif 'proxytext' in request.form:
            proxytext = request.form.get("proxytext", "")
            all_lines = proxytext.strip().splitlines()
            input_count = len(all_lines)
            if input_count > PROXY_CHECK_HARD_LIMIT:
                truncation_warning = f" Only the first {PROXY_CHECK_HARD_LIMIT} proxies were processed."
                all_lines = all_lines[:PROXY_CHECK_HARD_LIMIT]
            proxies = all_lines

        proxies = list(set(p.strip() for p in proxies if p.strip()))
        processed_count = len(proxies)

        if proxies:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = [executor.submit(single_check_proxy, proxy) for proxy in proxies]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        try:
                            used = result["ip"] in get_all_used_ips()
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

    return render_template("index.html", results=results, message=message)

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
        stats = {
            "total_checks": "N/A (Vercel)",
            "total_good": len(get_good_proxies())
        }
        
        # Get used IPs from sheet
        used_ips = []
        try:
            # This function should return a list of dictionaries
            # with keys: "IP", "Proxy", "Date"
            # If not, adjust accordingly
            used_ips = get_all_used_ips()
        except Exception as e:
            logger.error(f"Error getting used IPs: {e}")
        
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

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

@app.route('/debug')
def debug():
    debug_info = {
        "env_creds_set": "GOOGLE_CREDENTIALS" in os.environ,
        "used_sheet_access": bool(get_all_used_ips()),
        "good_sheet_access": bool(get_good_proxies()),
        "python_version": sys.version.split()[0]
    }
    return jsonify(debug_info)

if __name__ == "__main__":
    app.run()