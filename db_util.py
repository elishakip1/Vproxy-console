import os
import logging
from supabase import create_client, Client
from datetime import datetime
import pytz
import random
import time

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

# --- USED PROXIES ---
def add_used_ip(ip, proxy, username="Unknown"):
    if not supabase: return False
    try:
        exists = supabase.table('used_proxies').select("id").eq("ip", ip).execute()
        if exists.data: return True
        
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
        return [{
            "IP": r['ip'], 
            "Proxy": r['proxy'], 
            "Date": r['created_at'],
            "User": r.get('username', 'Unknown')
        } for r in response.data]
    except Exception: return []

# --- BAD PROXIES (FIXED) ---
def log_bad_proxy(proxy, ip, score):
    if not supabase: return False
    try:
        exists = supabase.table('bad_proxies').select("id").eq("ip", ip).execute()
        if exists.data: return True

        supabase.table('bad_proxies').insert({"proxy": proxy, "ip": ip, "score": score}).execute()
        return True
    except Exception: return False

def get_bad_proxies_list():
    """
    FIXED: Returns a list of DICTIONARIES (including IP), not just strings.
    This prevents the 'AttributeError' in app.py.
    """
    if not supabase: return []
    try:
        response = supabase.table('bad_proxies').select("ip, proxy").execute()
        return response.data # Returns [{'ip': '...', 'proxy': '...'}, ...]
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

# --- API USAGE & STATS ---
def add_api_usage_log(username, ip, submitted_count, api_calls_count, good_proxies_count):
    if not supabase: return False
    try:
        supabase.table('api_usage').insert({
            "username": username, 
            "user_ip": ip, 
            "submitted_count": submitted_count, 
            "api_calls_count": api_calls_count,
            "good_proxies_count": good_proxies_count
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
    if not supabase: return []
    try:
        response = supabase.table('user_stats_view').select("*").execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching user stats: {e}")
        return []

# --- DAILY API USAGE TRACKING ---
def get_daily_api_usage_for_user(username):
    """Get total API calls for a user today"""
    if not supabase: return 0
    
    try:
        # Get today's date in UTC
        today = datetime.utcnow().strftime("%Y-%m-%d")
        
        # Query using date filtering
        response = supabase.table('api_usage').select("api_calls_count, created_at").eq("username", username).execute()
        
        total = 0
        for row in response.data:
            # Parse the date from created_at
            created_at = row.get('created_at', '')
            if created_at.startswith(today):
                total += int(row.get('api_calls_count', 0))
        
        return total
    except Exception as e:
        logger.error(f"Error getting daily API usage: {e}")
        return 0

# --- API CREDITS MANAGEMENT ---
def update_api_credits(used, remaining):
    """Update API credits in settings"""
    if not supabase: return False
    
    try:
        # Update used credits
        supabase.table('settings').upsert({"key": "API_CREDITS_USED", "value": str(used)}).execute()
        # Update remaining credits
        supabase.table('settings').upsert({"key": "API_CREDITS_REMAINING", "value": str(remaining)}).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating API credits: {e}")
        return False

# --- PROXY POOL FUNCTIONS ---

def add_bulk_proxies(proxy_list, provider="manual"):
    if not supabase or not proxy_list: return 0
    data = [{"proxy": p.strip(), "provider": provider} for p in proxy_list if p.strip()]
    total_added = 0; chunk_size = 1000
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        try:
            supabase.table('proxy_pool').upsert(chunk, on_conflict='proxy', ignore_duplicates=True).execute()
            total_added += len(chunk)
        except Exception as e: logger.error(f"Error adding bulk proxies: {e}")
    return total_added

def get_random_proxies_from_pool(limit=100):
    """Fetches TRUE random proxies using RPC."""
    if not supabase: return []
    try:
        response = supabase.rpc('get_random_proxies', {'limit_count': limit}).execute()
        proxies = [r['proxy'] for r in response.data]
        return proxies
    except Exception as e:
        logger.error(f"Error fetching from pool: {e}")
        return []

def get_pool_count():
    if not supabase: return 0
    try:
        res = supabase.table('proxy_pool').select("id", count="exact", head=True).execute()
        return res.count
    except: return 0

def clear_proxy_pool(provider=None):
    if not supabase: return False
    try:
        query = supabase.table('proxy_pool').delete()
        if provider: query = query.eq('provider', provider)
        else: query = query.neq('id', 0) 
        query.execute()
        return True
    except Exception as e: logger.error(f"Error clearing pool: {e}"); return False
