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

# --- BAD PROXIES ---
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
        today = datetime.utcnow().strftime("%Y-%m-%d")
        response = supabase.table('api_usage').select("api_calls_count, created_at").eq("username", username).execute()
        total = 0
        for row in response.data:
            created_at = row.get('created_at', '')
            if created_at.startswith(today):
                total += int(row.get('api_calls_count', 0))
        return total
    except Exception as e:
        logger.error(f"Error getting daily API usage: {e}")
        return 0

# --- USER ACTIVITY MONITOR DELETION ---
def delete_user_activity_logs(username):
    """Wipes all usage and system logs for a specific user to reset their stats."""
    if not supabase: return False
    try:
        # Remove from usage stats and system logs
        supabase.table('api_usage').delete().eq('username', username).execute()
        supabase.table('system_logs').delete().eq('username', username).execute()
        return True
    except Exception as e:
        logger.error(f"Error clearing logs for {username}: {e}")
        return False

# --- DYNAMIC BUTTON MANAGEMENT ---
def get_active_fetch_buttons():
    if not supabase: return []
    try:
        response = supabase.table('fetch_buttons').select('*').eq('is_active', True).order('display_order').execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching active buttons: {e}")
        return []

def get_all_fetch_buttons():
    if not supabase: return []
    try:
        response = supabase.table('fetch_buttons').select('*').order('display_order').execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching all buttons: {e}")
        return []

def add_fetch_button(name, b_type, target):
    if not supabase: return False
    try:
        supabase.table('fetch_buttons').insert({'name': name, 'type': b_type, 'target': target}).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding button: {e}")
        return False

def delete_fetch_button(btn_id):
    if not supabase: return False
    try:
        supabase.table('fetch_buttons').delete().eq('id', btn_id).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting button: {e}")
        return False

# --- API CREDITS MANAGEMENT ---
def update_api_credits(used, remaining):
    if not supabase: return False
    try:
        supabase.table('settings').upsert({"key": "API_CREDITS_USED", "value": str(used)}).execute()
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
    if not supabase: return []
    try:
        response = supabase.rpc('get_random_proxies', {'limit_count': limit}).execute()
        proxies = [r['proxy'] for r in response.data]
        return proxies
    except Exception as e:
        logger.error(f"Error fetching from pool: {e}")
        return []

def get_pool_stats():
    """Fetches counts robustly using limit(1) to ensure count is returned."""
    if not supabase: return {"total": 0, "pyproxy": 0, "piaproxy": 0}
    stats = {"total": 0, "pyproxy": 0, "piaproxy": 0}
    
    def safe_count(query):
        try:
            res = query.limit(1).execute()
            if hasattr(res, 'count') and res.count is not None:
                return res.count
            return 0
        except Exception as e:
            logger.error(f"Count error: {e}")
            return 0

    try:
        stats["total"] = safe_count(supabase.table('proxy_pool').select("id", count="exact"))
        stats["pyproxy"] = safe_count(supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'pyproxy'))
        stats["piaproxy"] = safe_count(supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'piaproxy'))
    except Exception as e:
        logger.error(f"Pool stats error: {e}")
    
    return stats

def get_pool_preview(provider, limit=50):
    """Fetches a preview list of proxies for a provider"""
    if not supabase: return []
    try:
        res = supabase.table('proxy_pool').select("proxy, created_at").eq('provider', provider).order('created_at', desc=True).limit(limit).execute()
        return res.data
    except Exception as e:
        logger.error(f"Preview fetch error: {e}")
        return []

def clear_proxy_pool(provider=None):
    if not supabase: return False
    try:
        query = supabase.table('proxy_pool').delete()
        if provider and provider != 'all': 
            query = query.eq('provider', provider)
        else: 
            query = query.neq('id', 0) 
        query.execute()
        return True
    except Exception as e: logger.error(f"Error clearing pool: {e}"); return False

# --- USER MANAGEMENT FUNCTIONS ---

def get_all_users():
    """Get all users from database"""
    if not supabase: return []
    try:
        response = supabase.table('users').select("*").order('id').execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return []

def get_user_by_username(username):
    """Get a user by username"""
    if not supabase: return None
    try:
        response = supabase.table('users').select("*").eq('username', username).execute()
        if response.data:
            return response.data[0]
        return None
    except Exception as e:
        logger.error(f"Error fetching user {username}: {e}")
        return None

def create_user(username, password, role="user", can_fetch=False, daily_api_limit=0):
    """Create a new user"""
    if not supabase: return False
    try:
        existing = get_user_by_username(username)
        if existing:
            return False
        
        all_users = get_all_users()
        new_id = max([u['id'] for u in all_users]) + 1 if all_users else 1
        
        user_data = {
            "id": new_id,
            "username": username,
            "password": password,
            "role": role,
            "can_fetch": can_fetch,
            "daily_api_limit": daily_api_limit if role == 'guest' else 0
        }
        
        supabase.table('users').insert(user_data).execute()
        return True
    except Exception as e:
        logger.error(f"Error creating user {username}: {e}")
        return False

def update_user(user_id, **updates):
    """Update a user's information"""
    if not supabase: return False
    try:
        if user_id == 1 and 'role' in updates and updates['role'] != 'admin':
            return False
        
        clean_updates = {k: v for k, v in updates.items() if v is not None}
        
        if clean_updates:
            supabase.table('users').update(clean_updates).eq('id', user_id).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}")
        return False

def delete_user(user_id):
    """Delete a user"""
    if not supabase: return False
    try:
        if user_id == 1:
            return False
        
        supabase.table('users').delete().eq('id', user_id).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        return False

def init_default_users():
    """Initialize default users if table is empty"""
    if not supabase: return False
    try:
        users = get_all_users()
        if not users:
            create_user("EL", "ADMIN123", "admin", True, 0)
            return True
        return False
    except Exception as e:
        logger.error(f"Error initializing default users: {e}")
        return False
