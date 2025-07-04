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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration for Vercel compatibility
MAX_WORKERS = 5
REQUEST_TIMEOUT = 5
PROXY_CHECK_HARD_LIMIT = 25
MIN_DELAY = 0.5
MAX_DELAY = 2.5

# User agents to rotate
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

# Google Sheets setup
SCOPE = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

SHEET_NAME_VARIANTS = {
    "used_ips": ["Used IPs", "Used IP List", "Used_IPs"],
    "good_proxies": ["Good Proxies", "Good_Proxies", "GoodProxies"]
}

def get_sheet(sheet_type):
    """Get a sheet by type (used_ips or good_proxies) with fallback"""
    try:
        creds_json = os.environ.get("GOOGLE_CREDENTIALS")
        if not creds_json:
            raise ValueError("GOOGLE_CREDENTIALS environment variable not set")
            
        creds_dict = json.loads(creds_json)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
        client = gspread.authorize(creds)
        client.timeout = 10

        variants = SHEET_NAME_VARIANTS[sheet_type]
        
        for name in variants:
            try:
                return client.open(name).sheet1
            except gspread.SpreadsheetNotFound:
                continue
                
        return client.create(variants[0]).sheet1

    except Exception as e:
        logger.error(f"Error accessing Google Sheet: {str(e)}")
        return None

def add_used_ip(ip, proxy):
    try:
        sheet = get_sheet("used_ips")
        if sheet:
            sheet.append_row([ip, proxy, str(datetime.datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error adding used IP: {e}")

def delete_used_ip(ip):
    try:
        sheet = get_sheet("used_ips")
        if not sheet: 
            return False
        
        data = sheet.get_all_values()
        for i, row in enumerate(data):
            if row and row[0] == ip:
                sheet.delete_row(i + 1)
                return True
        return False
    except Exception as e:
        logger.error(f"Error deleting used IP: {e}")
        return False

def get_all_used_ips():
    try:
        sheet = get_sheet("used_ips")
        if not sheet:
            return []
            
        headers = sheet.row_values(1)
        records = sheet.get_all_records()
        
        if not headers or len(headers) < 3:
            return [{"IP": row[0], "Proxy": row[1], "Date": row[2]} for row in sheet.get_all_values()[1:] if row]
            
        return records
    except Exception as e:
        logger.error(f"Error getting used IPs: {e}")
        return []

def log_good_proxy(proxy, ip):
    try:
        sheet = get_sheet("good_proxies")
        if sheet:
            sheet.append_row([proxy, ip, str(datetime.datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error logging good proxy: {e}")

def get_good_proxies():
    try:
        sheet = get_sheet("good_proxies")
        if not sheet:
            return []
            
        return [row[0] for row in sheet.get_all_values()[1:] if row]
    except Exception as e:
        logger.error(f"Error getting good proxies: {e}")
        return []

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

def single_check_proxy(proxy_line):
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

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)