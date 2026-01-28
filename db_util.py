import os
import logging
from supabase import create_client, Client
from datetime import datetime, timedelta
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

# --- USER MANAGEMENT ---
def get_user_by_id(user_id):
    """Get user by ID (for Flask-Login)."""
    if not supabase: return None
    try:
        response = supabase.table('users').select("*").eq('id', user_id).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        logger.error(f"Error fetching user {user_id}: {e}")
        return None

def get_user_by_username(username):
    if not supabase: return None
    try:
        response = supabase.table('users').select("*").eq('username', username).execute()
        return response.data[0] if response.data else None
    except Exception as e:
        logger.error(f"Error fetching user {username}: {e}")
        return None

def get_all_users():
    if not supabase: return []
    try:
        response = supabase.table('users').select("*").order('id').execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return []

def create_user(username, password, role="user", can_fetch=False, daily_api_limit=0):
    if not supabase: return False
    try:
        # Check if user exists
        if get_user_by_username(username):
            return False
        
        # Get next ID
        all_users = get_all_users()
        new_id = max([u['id'] for u in all_users]) + 1 if all_users else 1
        
        supabase.table('users').insert({
            "id": new_id,
            "username": username,
            "password": password,
            "role": role,
            "can_fetch": can_fetch,
            "daily_api_limit": daily_api_limit,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        
        return True
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return False

def update_user(user_id, **updates):
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
    if not supabase or user_id == 1: return False
    try:
        supabase.table('users').delete().eq('id', user_id).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        return False

def init_default_users():
    if not supabase: return False
    try:
        if not get_all_users():
            create_user("EL", "ADMIN123", "admin", True, 0)
            create_user("Work2", "password", "user", True, 0)
            return True
        return False
    except Exception as e:
        logger.error(f"Error initializing default users: {e}")
        return False

# --- USED PROXIES ---
def add_used_ip(ip, proxy, username="Unknown"):
    if not supabase: return False
    try:
        # Check if already exists
        exists = supabase.table('used_proxies').select("id").eq("ip", ip).execute()
        if exists.data:
            return True
        
        supabase.table('used_proxies').insert({
            "ip": ip,
            "proxy": proxy,
            "username": username,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding used IP: {e}")
        return False

def delete_used_ip(ip):
    if not supabase: return False
    try:
        supabase.table('used_proxies').delete().eq('ip', ip).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting used IP {ip}: {e}")
        return False

def get_all_used_ips():
    if not supabase: return []
    try:
        response = supabase.table('used_proxies').select("*").order("created_at", desc=True).limit(100).execute()
        return [{
            "IP": r['ip'],
            "Proxy": r['proxy'],
            "Date": r['created_at'],
            "User": r.get('username', 'Unknown')
        } for r in response.data]
    except Exception as e:
        logger.error(f"Error fetching used IPs: {e}")
        return []

# --- BAD PROXIES ---
def log_bad_proxy(proxy, ip, score):
    if not supabase: return False
    try:
        # Check if already exists
        exists = supabase.table('bad_proxies').select("id").eq("ip", ip).execute()
        if exists.data:
            return True
        
        supabase.table('bad_proxies').insert({
            "proxy": proxy,
            "ip": ip,
            "score": score,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error logging bad proxy: {e}")
        return False

def get_bad_proxies_list():
    if not supabase: return []
    try:
        response = supabase.table('bad_proxies').select("ip, proxy").limit(1000).execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching bad proxies: {e}")
        return []

# --- LOGS ---
def add_log_entry(level, message, ip="N/A", username=None):
    if not supabase: return False
    try:
        data = {
            "level": level,
            "message": message,
            "ip": ip,
            "created_at": datetime.utcnow().isoformat()
        }
        
        if username:
            data["username"] = username
        
        supabase.table('system_logs').insert(data).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding log entry: {e}")
        return False

def get_all_system_logs():
    if not supabase: return []
    try:
        response = supabase.table('system_logs').select("*").order("created_at", desc=True).limit(200).execute()
        return [{
            "Timestamp": r['created_at'],
            "Level": r['level'],
            "Message": r['message'],
            "IP": r['ip'],
            "Username": r.get('username')
        } for r in response.data]
    except Exception as e:
        logger.error(f"Error fetching system logs: {e}")
        return []

def clear_all_system_logs():
    if not supabase: return False
    try:
        supabase.table('system_logs').delete().neq("id", 0).execute()
        return True
    except Exception as e:
        logger.error(f"Error clearing system logs: {e}")
        return False

# --- API USAGE & STATS ---
def add_api_usage_log(username, ip, submitted_count, api_calls_count, good_proxies_count):
    if not supabase: return False
    try:
        supabase.table('api_usage').insert({
            "username": username,
            "user_ip": ip,
            "submitted_count": submitted_count,
            "api_calls_count": api_calls_count,
            "good_proxies_count": good_proxies_count,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error logging API usage: {e}")
        return False

def get_all_api_usage_logs():
    if not supabase: return []
    try:
        response = supabase.table('api_usage').select("*").order("created_at", desc=True).execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching API usage logs: {e}")
        return []

def get_user_stats_summary():
    if not supabase: return []
    try:
        # Use the view if it exists, otherwise create a query
        response = supabase.table('user_stats_view').select("*").execute()
        return response.data
    except Exception:
        # Fallback query
        try:
            # This is a simplified version - you should create a view in Supabase
            query = """
                SELECT 
                    u.username,
                    MAX(a.created_at) as last_active,
                    COALESCE(SUM(a.api_calls_count), 0) as total_api_calls,
                    COALESCE(SUM(a.good_proxies_count), 0) as total_good_proxies
                FROM users u
                LEFT JOIN api_usage a ON u.username = a.username
                GROUP BY u.username
                ORDER BY last_active DESC
            """
            # For Supabase, you might need to create a stored function or view
            # This is a placeholder - adjust based on your Supabase setup
            response = supabase.table('users').select("username").execute()
            stats = []
            for user in response.data:
                username = user['username']
                # Get user activity
                usage_res = supabase.table('api_usage').select("*").eq('username', username).order('created_at', desc=True).limit(1).execute()
                last_active = usage_res.data[0]['created_at'] if usage_res.data else None
                
                # Get totals
                totals_res = supabase.table('api_usage').select("api_calls_count, good_proxies_count").eq('username', username).execute()
                total_api = sum([r['api_calls_count'] for r in totals_res.data])
                total_good = sum([r['good_proxies_count'] for r in totals_res.data])
                
                stats.append({
                    'username': username,
                    'last_active': last_active or 'Never',
                    'total_api_calls': total_api,
                    'total_good_proxies': total_good
                })
            
            return stats
        except Exception as e:
            logger.error(f"Error fetching user stats: {e}")
            return []

def get_daily_api_usage_for_user(username):
    if not supabase: return 0
    try:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        response = supabase.table('api_usage').select("api_calls_count").eq("username", username).gte("created_at", f"{today}T00:00:00").lte("created_at", f"{today}T23:59:59").execute()
        total = sum([int(row.get('api_calls_count', 0)) for row in response.data])
        return total
    except Exception as e:
        logger.error(f"Error getting daily usage for {username}: {e}")
        return 0

def delete_user_activity_logs(username):
    if not supabase: return False
    try:
        supabase.table('api_usage').delete().eq('username', username).execute()
        supabase.table('system_logs').delete().eq('username', username).execute()
        return True
    except Exception as e:
        logger.error(f"Error clearing logs for {username}: {e}")
        return False

# --- DYNAMIC BUTTONS ---
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
        # Get next display order
        all_buttons = get_all_fetch_buttons()
        next_order = max([b.get('display_order', 0) for b in all_buttons]) + 1 if all_buttons else 1
        
        supabase.table('fetch_buttons').insert({
            'name': name,
            'type': b_type,
            'target': target,
            'is_active': True,
            'display_order': next_order,
            'created_at': datetime.utcnow().isoformat()
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding fetch button: {e}")
        return False

def delete_fetch_button(btn_id):
    if not supabase: return False
    try:
        supabase.table('fetch_buttons').delete().eq('id', btn_id).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting button {btn_id}: {e}")
        return False

# --- API CREDITS ---
def update_api_credits(used, remaining):
    """Update API credit settings in DB."""
    if not supabase: return False
    try:
        update_setting("API_CREDITS_USED", str(used))
        update_setting("API_CREDITS_REMAINING", str(remaining))
        return True
    except Exception as e:
        logger.error(f"Error updating API credits: {e}")
        return False

# --- PROXY POOL ---
def add_bulk_proxies(proxy_list, provider="manual"):
    if not supabase or not proxy_list: return 0
    try:
        data = [{
            "proxy": p.strip(),
            "provider": provider,
            "created_at": datetime.utcnow().isoformat()
        } for p in proxy_list if p.strip()]
        
        total_added = 0
        chunk_size = 500  # Smaller chunks for better reliability
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            try:
                # Use upsert to avoid duplicates
                supabase.table('proxy_pool').upsert(
                    chunk,
                    on_conflict='proxy',
                    ignore_duplicates=True
                ).execute()
                total_added += len(chunk)
            except Exception as e:
                logger.warning(f"Error inserting chunk {i}: {e}")
                # Try individual inserts for this chunk
                for item in chunk:
                    try:
                        supabase.table('proxy_pool').insert(item).execute()
                        total_added += 1
                    except:
                        pass
        
        return total_added
    except Exception as e:
        logger.error(f"Error adding bulk proxies: {e}")
        return 0

def get_random_proxies_from_pool(limit=100):
    if not supabase: return []
    try:
        # Try to use RPC function if it exists
        response = supabase.rpc('get_random_proxies', {'limit_count': limit}).execute()
        return [r['proxy'] for r in response.data]
    except Exception:
        # Fallback: simple query (not truly random but works)
        try:
            response = supabase.table('proxy_pool').select("proxy").limit(limit).execute()
            proxies = [r['proxy'] for r in response.data]
            random.shuffle(proxies)
            return proxies
        except Exception as e:
            logger.error(f"Error fetching random proxies: {e}")
            return []

def get_pool_stats():
    if not supabase: return {"total": 0, "pyproxy": 0, "piaproxy": 0}
    try:
        stats = {"total": 0, "pyproxy": 0, "piaproxy": 0}
        
        # Get total count
        total_res = supabase.table('proxy_pool').select("id", count="exact").execute()
        stats["total"] = total_res.count if hasattr(total_res, 'count') else 0
        
        # Get provider counts
        pyproxy_res = supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'pyproxy').execute()
        stats["pyproxy"] = pyproxy_res.count if hasattr(pyproxy_res, 'count') else 0
        
        piaproxy_res = supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'piaproxy').execute()
        stats["piaproxy"] = piaproxy_res.count if hasattr(piaproxy_res, 'count') else 0
        
        return stats
    except Exception as e:
        logger.error(f"Error fetching pool stats: {e}")
        return {"total": 0, "pyproxy": 0, "piaproxy": 0}

def get_pool_preview(provider, limit=20):
    if not supabase: return []
    try:
        response = supabase.table('proxy_pool').select("proxy, created_at").eq('provider', provider).order('created_at', desc=True).limit(limit).execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching pool preview for {provider}: {e}")
        return []

def clear_proxy_pool(provider=None):
    if not supabase: return False
    try:
        if provider and provider != 'all':
            supabase.table('proxy_pool').delete().eq('provider', provider).execute()
        else:
            supabase.table('proxy_pool').delete().neq('id', 0).execute()
        return True
    except Exception as e:
        logger.error(f"Error clearing proxy pool: {e}")
        return False
