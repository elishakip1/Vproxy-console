from flask import Flask, request, render_template, jsonify, redirect, url_for
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simple in-memory storage
memory_storage = {
    'used_ips': [],
    'good_proxies': [],
    'settings': {
        'MAX_PASTE': 30,
        'MAX_WORKERS': 5,
        'FRAUD_SCORE_LEVEL': 0,
        'ALLOWED_PASSWORDS': ['8soFs0QqNJivObgW', 'JBZAeWoqvF1XqOuw', '68166538']
    }
}

# User agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
]

def validate_proxy_format(proxy_line):
    """Validate proxy format: host:port:username:password"""
    try:
        parts = proxy_line.strip().split(':')
        return len(parts) == 4 and all(parts)
    except:
        return False

def validate_proxy_password(proxy_line, allowed_passwords):
    """Validate proxy password"""
    try:
        if not validate_proxy_format(proxy_line):
            return False
        parts = proxy_line.strip().split(':')
        return parts[3] in allowed_passwords
    except:
        return False

def get_ip_from_proxy(proxy_line, allowed_passwords):
    """Get IP address using proxy"""
    if not validate_proxy_password(proxy_line, allowed_passwords):
        return None
    
    try:
        host, port, user, pw = proxy_line.strip().split(':')
        proxies = {
            "http": f"http://{user}:{pw}@{host}:{port}",
            "https": f"http://{user}:{pw}@{host}:{port}",
        }
        
        session = requests.Session()
        session.mount('http://', HTTPAdapter(max_retries=1))
        session.mount('https://', HTTPAdapter(max_retries=1))
        
        response = session.get(
            "https://api.ipify.org", 
            proxies=proxies, 
            timeout=5,
            headers={"User-Agent": random.choice(USER_AGENTS)}
        )
        return response.text
    except Exception as e:
        logger.error(f"Failed to get IP from proxy: {e}")
        return None

def single_check_proxy(proxy_line, allowed_passwords):
    """Check single proxy"""
    time.sleep(random.uniform(0.5, 1.5))
    
    if not validate_proxy_password(proxy_line, allowed_passwords):
        return None
    
    ip = get_ip_from_proxy(proxy_line, allowed_passwords)
    if ip:
        # For now, just return success if we can get IP
        # In full version, we would check fraud score here
        return {"proxy": proxy_line, "ip": ip}
    return None

@app.route("/")
def index():
    settings = memory_storage['settings']
    
    results = []
    message = ""
    
    if request.method == "POST":
        proxytext = request.form.get("proxytext", "")
        proxies = [p.strip() for p in proxytext.splitlines() if p.strip()]
        
        # Apply max limit
        if len(proxies) > settings['MAX_PASTE']:
            proxies = proxies[:settings['MAX_PASTE']]
            message = f"Processed first {settings['MAX_PASTE']} proxies (max limit)"
        
        # Filter valid proxies
        valid_proxies = [
            p for p in proxies 
            if validate_proxy_password(p, settings['ALLOWED_PASSWORDS'])
        ]
        
        if valid_proxies:
            # Check proxies in parallel
            with ThreadPoolExecutor(max_workers=settings['MAX_WORKERS']) as executor:
                futures = [
                    executor.submit(single_check_proxy, proxy, settings['ALLOWED_PASSWORDS']) 
                    for proxy in valid_proxies
                ]
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        # Check if IP was used before
                        used = any(item['ip'] == result['ip'] for item in memory_storage['used_ips'])
                        results.append({
                            "proxy": result["proxy"],
                            "ip": result["ip"],
                            "used": used
                        })
            
            if results:
                # Add to used IPs and good proxies
                for item in results:
                    if not item['used']:
                        memory_storage['used_ips'].append({'ip': item['ip'], 'proxy': item['proxy']})
                        memory_storage['good_proxies'].append(item['proxy'])
                
                message = f"✅ Found {len(results)} working proxies out of {len(valid_proxies)} valid"
            else:
                message = "❌ No working proxies found"
        else:
            message = "⚠️ No valid proxies found (check format and passwords)"
    
    return render_template(
        "index.html", 
        results=results, 
        message=message, 
        max_paste=settings['MAX_PASTE']
    )

@app.route("/admin")
def admin():
    settings = memory_storage['settings']
    stats = {
        "total_used": len(memory_storage['used_ips']),
        "total_good": len(memory_storage['good_proxies']),
        "max_paste": settings['MAX_PASTE'],
        "max_workers": settings['MAX_WORKERS']
    }
    
    return render_template(
        "admin.html",
        stats=stats,
        used_ips=memory_storage['used_ips'],
        good_proxies=memory_storage['good_proxies']
    )

@app.route("/test")
def test():
    return {"status": "success", "message": "API is working!"}

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", error="Page not found"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template("error.html", error=str(e)), 500

# Vercel handler
def handler(request, context):
    return app(request, context)

if __name__ == "__main__":
    app.run(debug=True)