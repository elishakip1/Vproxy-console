import os
import logging
from supabase import create_client, Client
from datetime import datetime
import pytz

# Configure Logging
logger = logging.getLogger(__name__)

# --- INIT SUPABASE CLIENT ---
# We look for these in environment variables
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

# Create client (Fail gracefully if vars are missing, useful for local testing)
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

# --- SETTINGS FUNCTIONS ---

def get_settings():
    """Fetch all settings as a dictionary {key: value}."""
    if not supabase: return {}
    try:
        response = supabase.table('settings').select("*").execute()
        # Convert list of rows [{'key': 'X', 'value': 'Y'}] -> {'X': 'Y'}
        return {row['key']: row['value'] for row in response.data}
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        return {}

def update_setting(key, value):
    """Update or Insert a setting."""
    if not supabase: return False
    try:
        # Upsert handles both update and insert
        supabase.table('settings').upsert({"key": key, "value": str(value)}).execute()
        logger.info(f"Updated setting {key} to {value}")
        return True
    except Exception as e:
        logger.error(f"Error updating setting {key}: {e}")
        return False

# --- USED PROXY FUNCTIONS ---

def add_used_ip(ip, proxy):
    """Log a used IP."""
    if not supabase: return False
    try:
        # Check if exists first to avoid duplicates (optional, but good)
        exists = supabase.table('used_proxies').select("id").eq("ip", ip).execute()
        if exists.data:
            return True # Already there
        
        supabase.table('used_proxies').insert({"ip": ip, "proxy": proxy}).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding used IP {ip}: {e}")
        return False

def delete_used_ip(ip):
    """Delete a used IP."""
    if not supabase: return False
    try:
        supabase.table('used_proxies').delete().eq("ip", ip).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting IP {ip}: {e}")
        return False

def get_all_used_ips():
    """Get list of all used IPs."""
    if not supabase: return []
    try:
        # Order by newest first
        response = supabase.table('used_proxies').select("ip, proxy, created_at").order("created_at", desc=True).execute()
        # Remap 'created_at' to 'Date' to match app expectations
        return [{"IP": r['ip'], "Proxy": r['proxy'], "Date": r['created_at']} for r in response.data]
    except Exception as e:
        logger.error(f"Error fetching used IPs: {e}")
        return []

# --- BAD PROXY FUNCTIONS ---

def log_bad_proxy(proxy, ip, score):
    if not supabase: return False
    try:
        supabase.table('bad_proxies').insert({"proxy": proxy, "ip": ip, "score": score}).execute()
        return True
    except Exception as e:
        logger.error(f"Error logging bad proxy: {e}")
        return False

def get_bad_proxies_list():
    if not supabase: return []
    try:
        response = supabase.table('bad_proxies').select("proxy").execute()
        return [r['proxy'] for r in response.data]
    except Exception as e:
        return []

# --- LOGGING FUNCTIONS ---

def add_log_entry(level, message, ip="N/A"):
    if not supabase: return False
    try:
        supabase.table('system_logs').insert({"level": level, "message": message, "ip": ip}).execute()
        return True
    except Exception as e:
        # Don't log logging errors recursively
        print(f"Failed to log to Supabase: {e}")
        return False

def get_all_system_logs():
    if not supabase: return []
    try:
        response = supabase.table('system_logs').select("*").order("created_at", desc=True).limit(200).execute()
        # Remap keys for template
        return [{"Timestamp": r['created_at'], "Level": r['level'], "Message": r['message'], "IP": r['ip']} for r in response.data]
    except Exception as e:
        logger.error(f"Error fetching logs: {e}")
        return []

def clear_all_system_logs():
    if not supabase: return False
    try:
        # Delete all rows
        supabase.table('system_logs').delete().neq("id", 0).execute() 
        return True
    except Exception as e:
        logger.error(f"Error clearing logs: {e}")
        return False

def add_api_usage_log(username, ip, submitted_count, api_calls_count):
    if not supabase: return False
    try:
        supabase.table('api_usage').insert({
            "username": username, 
            "user_ip": ip, 
            "submitted_count": submitted_count, 
            "api_calls_count": api_calls_count
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error logging usage: {e}")
        return False

def get_all_api_usage_logs():
    if not supabase: return []
    try:
        # We just need the sums usually, but fetching data is fine
        response = supabase.table('api_usage').select("api_calls_count").execute()
        return [{"API Calls Made": r['api_calls_count']} for r in response.data]
    except Exception as e:
        return []
