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

# --- USER MANAGEMENT ---

def get_all_users():
    """Fetch all users from the database."""
    if not supabase: return []
    try:
        response = supabase.table('users').select("*").execute()
        return response.data
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        return []

def get_user_by_id(user_id):
    """Fetch one user by id (used on every request, so don't load the whole table)."""
    if not supabase: return None
    try:
        r = supabase.table('users').select("*").eq("id", user_id).limit(1).execute()
        return r.data[0] if r.data else None
    except Exception as e:
        logger.error(f"Error fetching user {user_id}: {e}")
        return None

def get_user_by_username(username):
    if not supabase or not username: return None
    try:
        r = supabase.table('users').select("*").eq("username", username).limit(1).execute()
        return r.data[0] if r.data else None
    except Exception as e:
        logger.error(f"Error fetching user {username}: {e}")
        return None

def get_user_by_api_key(api_key):
    """Look up one user by API key hash. Returns the row or None."""
    if not supabase or not api_key: return None
    try:
        import hashlib
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        r = supabase.table('users').select("*").eq("api_key_hash", key_hash).limit(1).execute()
        return r.data[0] if r.data else None
    except Exception as e:
        logger.error(f"Error looking up API key: {e}")
        return None

def set_user_api_key_hash(username, key_hash):
    """Store (or clear, with None) the SHA-256 hash of a user's API key."""
    if not supabase: return False
    try:
        supabase.table('users').update({"api_key_hash": key_hash}).eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error setting API key: {e}")
        return False

def add_user(username, password, role="user", can_fetch=False, api_limit=None):
    """Add a new user (admin, user, or guest) to the system."""
    if not supabase: return False
    try:
        supabase.table('users').insert({
            "username": username,
            "password": password,
            "role": role,
            "can_fetch": can_fetch,
            "api_limit": api_limit
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        return False

def delete_user(username):
    """Remove a user from the system."""
    if not supabase: return False
    try:
        supabase.table('users').delete().eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        return False

def update_user_fetch_permission(username, can_fetch):
    """Toggle a user's ability to use fetch buttons."""
    if not supabase: return False
    try:
        supabase.table('users').update({"can_fetch": can_fetch}).eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating fetch permission: {e}")
        return False

def update_user_role(username, role):
    """Update a user's role (admin, user, or guest)."""
    if not supabase: return False
    try:
        supabase.table('users').update({"role": role}).eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating role: {e}")
        return False

def update_user_api_limit(username, api_limit):
    """Update a user's daily API limit."""
    if not supabase: return False
    try:
        supabase.table('users').update({"api_limit": api_limit}).eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating API limit: {e}")
        return False

def update_username(current_username, new_username):
    if not supabase: return False
    try:
        supabase.table('users').update({"username": new_username}).eq("username", current_username).execute()
        supabase.table('used_proxies').update({"username": new_username}).eq("username", current_username).execute()
        supabase.table('api_usage').update({"username": new_username}).eq("username", current_username).execute()
        supabase.table('recent_checks').update({"username": new_username}).eq("username", current_username).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating username: {e}")
        return False

def update_password(username, new_password):
    if not supabase: return False
    try:
        supabase.table('users').update({"password": new_password}).eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating password: {e}")
        return False

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

def add_recent_checks(username, checks):
    if not supabase or not checks: return False
    try:
        rows = []
        for item in checks:
            proxy = item.get("proxy")
            ip = item.get("ip")
            if not proxy or not ip:
                continue
            geo = item.get("geo") or {}
            rows.append({
                "username": username,
                "proxy": proxy,
                "ip": ip,
                "country": geo.get("country_code"),
                "state": geo.get("state"),
                "city": geo.get("city"),
                "postcode": geo.get("postcode"),
                "score": item.get("score"),
                "copied": False
            })
        if not rows:
            return False
        supabase.table('recent_checks').insert(rows).execute()
        return True
    except Exception as e:
        logger.error(f"Error adding recent checks: {e}")
        return False

def get_pending_checks(username, limit=200):
    if not supabase: return []
    try:
        response = supabase.table('recent_checks').select("id, proxy, ip, country, state, city, postcode, score, created_at").eq("username", username).eq("copied", False).order("created_at", desc=True).limit(limit).execute()
        rows = response.data or []
        seen_ips = set()
        unique_rows = []
        for row in rows:
            ip = row.get("ip")
            if not ip or ip in seen_ips:
                continue
            seen_ips.add(ip)
            unique_rows.append(row)
        return unique_rows
    except Exception as e:
        logger.error(f"Error fetching pending checks: {e}")
        return []

def mark_recent_check_copied(username, proxy, ip):
    if not supabase: return False
    try:
        supabase.table('recent_checks').update({"copied": True}).eq("username", username).eq("proxy", proxy).eq("ip", ip).execute()
        return True
    except Exception as e:
        logger.error(f"Error marking check copied: {e}")
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

def clear_all_api_usage():
    if not supabase: return False
    try:
        supabase.table('api_usage').delete().neq("id", 0).execute()
        return True
    except Exception as e:
        logger.error(f"Error clearing api usage: {e}")
        return False

def clear_user_stats(username):
    """Remove API usage stats for a user without deleting the user."""
    if not supabase: return False
    try:
        supabase.table('api_usage').delete().eq("username", username).execute()
        return True
    except Exception as e:
        logger.error(f"Error clearing stats for {username}: {e}")
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
            "good_proxies_count": good_proxies_count
        }).execute()
        return True
    except Exception as e:
        logger.error(f"Error logging usage: {e}")
        return False

def get_all_api_usage_logs():
    if not supabase: return []
    try:
        all_rows = []
        page_size = 1000
        start = 0
        while True:
            response = supabase.table('api_usage').select("*").range(start, start + page_size - 1).execute()
            data = response.data or []
            all_rows.extend(data)
            if len(data) < page_size:
                break
            start += page_size
        return all_rows
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
    """Get total API calls for a user this month"""
    if not supabase: return 0
    try:
        month_prefix = datetime.utcnow().strftime("%Y-%m")
        response = supabase.table('api_usage').select("api_calls_count, created_at").eq("username", username).execute()
        total = 0
        for row in response.data:
            created_at = row.get('created_at', '')
            if created_at.startswith(month_prefix):
                total += int(row.get('api_calls_count', 0))
        return total
    except Exception as e:
        logger.error(f"Error getting monthly API usage: {e}")
        return 0

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
    if not supabase: return {"total": 0, "pyproxy": 0, "piaproxy": 0}
    stats = {"total": 0, "pyproxy": 0, "piaproxy": 0}
    def safe_count(query):
        try:
            res = query.limit(1).execute()
            if hasattr(res, 'count') and res.count is not None:
                return res.count
            return 0
        except: return 0
    try:
        stats["total"] = safe_count(supabase.table('proxy_pool').select("id", count="exact"))
        stats["pyproxy"] = safe_count(supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'pyproxy'))
        stats["piaproxy"] = safe_count(supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'piaproxy'))
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
