import os
import logging
from supabase import create_client, Client
from datetime import datetime
import pytz
import random
import time

logger = logging.getLogger(__name__)

# --- SUPABASE CONFIG ---
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

try:
    if not SUPABASE_URL or not SUPABASE_KEY:
        logger.error("Supabase credentials missing from environment variables.")
        supabase = None
    else:
        supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    logger.critical(f"Failed to initialize Supabase: {e}")
    supabase = None

def get_eat_time():
    """Get current time in East Africa Time (EAT)."""
    utc_now = datetime.utcnow()
    eat_timezone = pytz.timezone('Africa/Nairobi')
    return utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone).strftime("%Y-%m-%d %H:%M:%S")

# --- USER MANAGEMENT FUNCTIONS ---

def get_all_users():
    """Retrieve all users from the database."""
    if not supabase: return []
    try:
        response = supabase.table('users').select("*").execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return []

def add_user(username, password, role="user", can_fetch=False):
    """Add a new user (Admin, Normal, or Guest)."""
    if not supabase: return False
    try:
        supabase.table('users').insert({
            "username": username,
            "password": password,
            "role": role,
            "can_fetch": can_fetch
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding user {username}: {e}")
        return False

def delete_user(username):
    """Remove a user from the database."""
    if not supabase: return False
    try:
        supabase.table('users').delete().eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting user {username}: {e}")
        return False

def update_user_fetch_permission(username, can_fetch):
    """Toggle the 'can fetch' permission for a specific user."""
    if not supabase: return False
    try:
        supabase.table('users').update({"can_fetch": can_fetch}).eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating fetch permission for {username}: {e}")
        return False

# --- SETTINGS MANAGEMENT ---

def get_settings():
    """Fetch all application settings."""
    if not supabase: return {}
    try:
        response = supabase.table('settings').select("*").execute()
        return {row['key']: row['value'] for row in response.data}
    except Exception as e:
        logger.error(f"Error fetching settings: {e}")
        return {}

def update_setting(key, value):
    """Update or insert a setting key-value pair."""
    if not supabase: return False
    try:
        supabase.table('settings').upsert({"key": key, "value": str(value)}).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating setting {key}: {e}")
        return False

# --- PROXY USAGE & LOGGING ---

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

def log_bad_proxy(proxy, ip, score):
    if not supabase: return False
    try:
        exists = supabase.table('bad_proxies').select("id").eq("ip", ip).execute()
        if exists.data: return True
        supabase.table('bad_proxies').insert({"proxy": proxy, "ip": ip, "score": score}).execute()
        return True
    except Exception: return False

def get_bad_proxies_list():
    if not supabase: return []
    try:
        response = supabase.table('bad_proxies').select("ip, proxy").execute()
        return response.data 
    except Exception: return []

# --- SYSTEM LOGS ---

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

# --- API USAGE TRACKING ---

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

def get_user_stats_summary():
    if not supabase: return []
    try:
        response = supabase.table('user_stats_view').select("*").execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching user stats: {e}")
        return []

def get_daily_api_usage_for_user(username):
    if not supabase: return 0
    try:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        response = supabase.table('api_usage').select("api_calls_count, created_at").eq("username", username).execute()
        total = 0
        for row in response.data:
            if row.get('created_at', '').startswith(today):
                total += int(row.get('api_calls_count', 0))
        return total
    except Exception: return 0

# --- PROXY POOL MANAGEMENT ---

def add_bulk_proxies(proxy_list, provider="manual"):
    if not supabase or not proxy_list: return 0
    data = [{"proxy": p.strip(), "provider": provider} for p in proxy_list if p.strip()]
    total_added = 0
    chunk_size = 1000
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        try:
            supabase.table('proxy_pool').upsert(chunk, on_conflict='proxy', ignore_duplicates=True).execute()
            total_added += len(chunk)
        except Exception as e: logger.error(f"Error adding bulk proxies: {e}")
    return total_added

def get_random_proxies_from_pool(limit=100):
    if not supabase: return []
    try:
        response = supabase.rpc('get_random_proxies', {'limit_count': limit}).execute()
        return [r['proxy'] for r in response.data]
    except Exception as e:
        logger.error(f"Error fetching from pool: {e}")
        return []

def get_pool_stats():
    if not supabase: return {"total": 0, "pyproxy": 0, "piaproxy": 0}
    stats = {"total": 0, "pyproxy": 0, "piaproxy": 0}
    try:
        stats["total"] = supabase.table('proxy_pool').select("id", count="exact").limit(1).execute().count
        stats["pyproxy"] = supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'pyproxy').limit(1).execute().count
        stats["piaproxy"] = supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'piaproxy').limit(1).execute().count
    except: pass
    return stats

def get_pool_preview(provider, limit=50):
    if not supabase: return []
    try:
        res = supabase.table('proxy_pool').select("proxy, created_at").eq('provider', provider).order('created_at', desc=True).limit(limit).execute()
        return res.data
    except: return []

def clear_proxy_pool(provider=None):
    if not supabase: return False
    try:
        query = supabase.table('proxy_pool').delete()
        if provider and provider != 'all': query = query.eq('provider', provider)
        else: query = query.neq('id', 0) 
        query.execute()
        return True
    except: return False
