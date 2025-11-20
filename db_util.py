import os
import logging
from supabase import create_client, Client
from datetime import datetime, timedelta
import pytz

logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    logger.critical(f"Failed to initialize Supabase: {e}")
    supabase = None

def get_eat_time():
    """Get current time formatted for display."""
    utc_now = datetime.utcnow()
    eat_timezone = pytz.timezone('Africa/Nairobi')
    return utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone).strftime("%Y-%m-%d %H:%M:%S")

# --- SETTINGS ---
def get_settings():
    if not supabase: return {}
    try:
        response = supabase.table('settings').select("*").execute()
        return {row['key']: row['value'] for row in response.data}
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        return {}

def update_setting(key, value):
    if not supabase: return False
    try:
        supabase.table('settings').upsert({"key": key, "value": str(value)}).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating setting {key}: {e}")
        return False

# --- USED PROXIES (Updated to track Username) ---
def add_used_ip(ip, proxy, username="Unknown"):
    if not supabase: return False
    try:
        exists = supabase.table('used_proxies').select("id").eq("ip", ip).execute()
        if exists.data: return True
        
        # Now storing username too
        supabase.table('used_proxies').insert({
            "ip": ip, 
            "proxy": proxy,
            "username": username
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding used IP: {e}")
        return False

def delete_used_ip(ip):
    if not supabase: return False
    try:
        supabase.table('used_proxies').delete().eq("ip", ip).execute()
        return True
    except Exception: return False

def get_all_used_ips():
    if not supabase: return []
    try:
        response = supabase.table('used_proxies').select("ip, proxy, created_at, username").order("created_at", desc=True).execute()
        # Map 'created_at' to 'Date' and include User
        return [{
            "IP": r['ip'], 
            "Proxy": r['proxy'], 
            "Date": r['created_at'],
            "User": r.get('username', 'Unknown')
        } for r in response.data]
    except Exception: return []

# --- BAD PROXIES ---
def log_bad_proxy(proxy, ip, score):
    if not supabase: return False
    try:
        supabase.table('bad_proxies').insert({"proxy": proxy, "ip": ip, "score": score}).execute()
        return True
    except Exception: return False

def get_bad_proxies_list():
    if not supabase: return []
    try:
        response = supabase.table('bad_proxies').select("proxy").execute()
        return [r['proxy'] for r in response.data]
    except Exception: return []

# --- LOGS ---
def add_log_entry(level, message, ip="N/A"):
    if not supabase: return False
    try:
        supabase.table('system_logs').insert({"level": level, "message": message, "ip": ip}).execute()
        return True
    except Exception: return False

def get_all_system_logs():
    if not supabase: return []
    try:
        response = supabase.table('system_logs').select("*").order("created_at", desc=True).limit(200).execute()
        return [{"Timestamp": r['created_at'], "Level": r['level'], "Message": r['message'], "IP": r['ip']} for r in response.data]
    except Exception: return []

def clear_all_system_logs():
    if not supabase: return False
    try:
        supabase.table('system_logs').delete().neq("id", 0).execute() 
        return True
    except Exception: return False

# --- API USAGE & STATS (Updated) ---
def add_api_usage_log(username, ip, submitted_count, api_calls_count, good_proxies_count):
    """Logs usage session including how many good proxies were found."""
    if not supabase: return False
    try:
        supabase.table('api_usage').insert({
            "username": username, 
            "user_ip": ip, 
            "submitted_count": submitted_count, 
            "api_calls_count": api_calls_count,
            "good_proxies_count": good_proxies_count # New field
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error logging usage: {e}")
        return False

def get_all_api_usage_logs():
    if not supabase: return []
    try:
        response = supabase.table('api_usage').select("*").execute()
        return response.data
    except Exception: return []

def get_user_stats_summary():
    """Fetches the auto-calculated stats view from Supabase."""
    if not supabase: return []
    try:
        # Query the View we created in Step 1
        response = supabase.table('user_stats_view').select("*").execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching user stats view: {e}")
        return []
