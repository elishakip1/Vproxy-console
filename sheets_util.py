import os
import logging
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

# Simple in-memory storage for Vercel
class MemoryStorage:
    def __init__(self):
        self.used_ips = []
        self.good_proxies = []
        self.blocked_ips = []
        self.settings = {
            "MAX_PASTE": "30",
            "FRAUD_SCORE_LEVEL": "0",
            "MAX_WORKERS": "5",
            "ALLOWED_PASSWORDS": "8soFs0QqNJivObgW,JBZAeWoqvF1XqOuw,68166538"
        }
        self.access_logs = []

storage = MemoryStorage()

def get_eat_time():
    """Get current time in EAT (East Africa Time)"""
    try:
        utc_now = datetime.utcnow()
        eat_timezone = pytz.timezone('Africa/Nairobi')
        eat_now = utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone)
        return eat_now.strftime("%Y-%m-%d %H:%M")
    except:
        return datetime.now().strftime("%Y-%m-%d %H:%M")

# Simple memory-based implementations
def add_used_ip(ip, proxy):
    try:
        # Check if IP already exists
        for item in storage.used_ips:
            if item["IP"] == ip:
                return True
        
        storage.used_ips.append({
            "IP": ip, 
            "Proxy": proxy, 
            "Date": get_eat_time()
        })
        return True
    except Exception as e:
        logger.error(f"Error adding used IP: {e}")
        return False

def delete_used_ip(ip):
    try:
        storage.used_ips = [item for item in storage.used_ips if item["IP"] != ip]
        return True
    except Exception as e:
        logger.error(f"Error deleting used IP: {e}")
        return False

def get_all_used_ips():
    try:
        return storage.used_ips
    except Exception as e:
        logger.error(f"Error getting used IPs: {e}")
        return []

def log_good_proxy(proxy, ip):
    try:
        # Check if proxy already exists
        for item in storage.good_proxies:
            if item["Proxy"] == proxy:
                return True
        
        storage.good_proxies.append({
            "Proxy": proxy, 
            "IP": ip, 
            "Timestamp": get_eat_time()
        })
        return True
    except Exception as e:
        logger.error(f"Error logging good proxy: {e}")
        return False

def get_good_proxies():
    try:
        return [item["Proxy"] for item in storage.good_proxies]
    except Exception as e:
        logger.error(f"Error getting good proxies: {e}")
        return []

def get_settings():
    try:
        return storage.settings.copy()
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return {}

def update_setting(setting_name, value):
    try:
        storage.settings[setting_name] = str(value)
        return True
    except Exception as e:
        logger.error(f"Error updating setting: {e}")
        return False

def log_user_access(ip, user_agent):
    try:
        storage.access_logs.append({
            "IP": ip,
            "Type": "ACCESS", 
            "UserAgent": user_agent,
            "Timestamp": get_eat_time()
        })
        return True
    except Exception as e:
        logger.error(f"Error logging user access: {e}")
        return False

def get_blocked_ips():
    try:
        return storage.blocked_ips
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return []

def add_blocked_ip(ip, reason):
    try:
        # Check if IP is already blocked
        for item in storage.blocked_ips:
            if item["IP"] == ip:
                return True
        
        storage.blocked_ips.append({
            "IP": ip,
            "Reason": reason,
            "Timestamp": get_eat_time()
        })
        return True
    except Exception as e:
        logger.error(f"Error adding blocked IP: {e}")
        return False

def remove_blocked_ip(ip):
    try:
        storage.blocked_ips = [item for item in storage.blocked_ips if item["IP"] != ip]
        return True
    except Exception as e:
        logger.error(f"Error removing blocked IP: {e}")
        return False

def is_ip_blocked(ip):
    try:
        return any(item["IP"] == ip for item in storage.blocked_ips)
    except Exception as e:
        logger.error(f"Error checking blocked IP: {e}")
        return False
