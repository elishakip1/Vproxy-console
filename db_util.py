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
    utc_now = datetime.utcnow()
    eat_timezone = pytz.timezone('Africa/Nairobi')
    return utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone).strftime("%Y-%m-%d %H:%M:%S")

# --- SETTINGS ---
def get_settings():
    if not supabase: return {}
    try:
        response = supabase.table('settings').select("*").execute()
        return {row['key']: row['value'] for row in response.data}
    except: return {}

def update_setting(key, value):
    if not supabase: return False
    try:
        supabase.table('settings').upsert({"key": key, "value": str(value)}).execute()
        return True
    except: return False

# --- DYNAMIC BUTTONS ---
def get_active_fetch_buttons():
    if not supabase: return []
    try:
        res = supabase.table('fetch_buttons').select('*').eq('is_active', True).order('display_order').execute()
        return res.data
    except: return []

def get_all_fetch_buttons():
    if not supabase: return []
    try:
        res = supabase.table('fetch_buttons').select('*').order('display_order').execute()
        return res.data
    except: return []

def add_fetch_button(name, b_type, target):
    if not supabase: return False
    try:
        supabase.table('fetch_buttons').insert({'name': name, 'type': b_type, 'target': target}).execute()
        return True
    except: return False

def delete_fetch_button(btn_id):
    if not supabase: return False
    try:
        supabase.table('fetch_buttons').delete().eq('id', btn_id).execute()
        return True
    except: return False

# --- USED & BAD PROXIES ---
def add_used_ip(ip, proxy, username="Unknown"):
    if not supabase: return False
    try:
        exists = supabase.table('used_proxies').select("id").eq("ip", ip).execute()
        if exists.data: return True
        supabase.table('used_proxies').insert({"ip": ip, "proxy": proxy, "username": username}).execute()
        return True
    except: return False

def delete_used_ip(ip):
    if not supabase: return False
    try:
        supabase.table('used_proxies').delete().eq("ip", ip).execute()
        return True
    except: return False

def get_all_used_ips():
    if not supabase: return []
    try:
        res = supabase.table('used_proxies').select("ip, proxy, created_at, username").order("created_at", desc=True).execute()
        return [{"IP": r['ip'], "Proxy": r['proxy'], "Date": r['created_at'], "User": r.get('username', 'Unknown')} for r in res.data]
    except: return []

def log_bad_proxy(proxy, ip, score):
    if not supabase: return False
    try:
        exists = supabase.table('bad_proxies').select("id").eq("ip", ip).execute()
        if exists.data: return True
        supabase.table('bad_proxies').insert({"proxy": proxy, "ip": ip, "score": score}).execute()
        return True
    except: return False

def get_bad_proxies_list():
    if not supabase: return []
    try:
        res = supabase.table('bad_proxies').select("ip, proxy").execute()
        return res.data 
    except: return []

# --- LOGS & USAGE ---
def add_log_entry(level, message, ip="N/A"):
    if not supabase: return False
    try:
        supabase.table('system_logs').insert({"level": level, "message": message, "ip": ip}).execute()
        return True
    except: return False

def get_all_system_logs():
    if not supabase: return []
    try:
        res = supabase.table('system_logs').select("*").order("created_at", desc=True).limit(200).execute()
        return [{"Timestamp": r['created_at'], "Level": r['level'], "Message": r['message'], "IP": r['ip']} for r in res.data]
    except: return []

def clear_all_system_logs():
    if not supabase: return False
    try:
        supabase.table('system_logs').delete().neq("id", 0).execute() 
        return True
    except: return False

def add_api_usage_log(username, ip, submitted, api_calls, good):
    if not supabase: return False
    try:
        supabase.table('api_usage').insert({"username": username, "user_ip": ip, "submitted_count": submitted, "api_calls_count": api_calls, "good_proxies_count": good}).execute()
        return True
    except: return False

def get_all_api_usage_logs():
    if not supabase: return []
    try:
        res = supabase.table('api_usage').select("*").execute()
        return res.data
    except: return []

def get_user_stats_summary():
    if not supabase: return []
    try:
        res = supabase.table('user_stats_view').select("*").execute()
        return res.data
    except: return []

def get_daily_api_usage_for_user(username):
    if not supabase: return 0
    try:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        res = supabase.table('api_usage').select("api_calls_count, created_at").eq("username", username).execute()
        return sum(int(row.get('api_calls_count', 0)) for row in res.data if row.get('created_at', '').startswith(today))
    except: return 0

def delete_user_activity_logs(username):
    if not supabase: return False
    try:
        supabase.table('api_usage').delete().eq('username', username).execute()
        supabase.table('system_logs').delete().eq('username', username).execute()
        return True
    except: return False

# --- PROXY POOL ---
def add_bulk_proxies(proxy_list, provider="manual"):
    if not supabase or not proxy_list: return 0
    data = [{"proxy": p.strip(), "provider": provider} for p in proxy_list if p.strip()]
    try:
        supabase.table('proxy_pool').upsert(data, on_conflict='proxy', ignore_duplicates=True).execute()
        return len(data)
    except: return 0

def get_random_proxies_from_pool(limit=100):
    if not supabase: return []
    try:
        res = supabase.rpc('get_random_proxies', {'limit_count': limit}).execute()
        return [r['proxy'] for r in res.data]
    except: return []

def get_pool_stats():
    if not supabase: return {"total": 0, "pyproxy": 0, "piaproxy": 0}
    try:
        def c(q):
            r = q.limit(1).execute()
            return r.count if hasattr(r, 'count') else 0
        return {
            "total": c(supabase.table('proxy_pool').select("id", count="exact")),
            "pyproxy": c(supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'pyproxy')),
            "piaproxy": c(supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'piaproxy'))
        }
    except: return {"total": 0, "pyproxy": 0, "piaproxy": 0}

def get_pool_preview(provider, limit=50):
    if not supabase: return []
    try:
        res = supabase.table('proxy_pool').select("proxy, created_at").eq('provider', provider).order('created_at', desc=True).limit(limit).execute()
        return res.data
    except: return []

def clear_proxy_pool(provider=None):
    if not supabase: return False
    try:
        q = supabase.table('proxy_pool').delete()
        if provider and provider != 'all': q = q.eq('provider', provider)
        else: q = q.neq('id', 0)
        q.execute()
        return True
    except: return False

# --- USER MANAGEMENT ---
def get_all_users():
    if not supabase: return []
    try:
        res = supabase.table('users').select("*").order('id').execute()
        return res.data
    except: return []

def get_user_by_username(username):
    if not supabase: return None
    try:
        res = supabase.table('users').select("*").eq('username', username).execute()
        return res.data[0] if res.data else None
    except: return None

def create_user(username, password, role="user", can_fetch=False, daily_limit=0):
    if not supabase: return False
    try:
        if get_user_by_username(username): return False
        all_u = get_all_users()
        new_id = max([u['id'] for u in all_u]) + 1 if all_u else 1
        supabase.table('users').insert({"id": new_id, "username": username, "password": password, "role": role, "can_fetch": can_fetch, "daily_api_limit": daily_limit}).execute()
        return True
    except: return False

def update_user(user_id, **updates):
    if not supabase: return False
    try:
        if user_id == 1 and 'role' in updates and updates['role'] != 'admin': return False
        clean = {k: v for k, v in updates.items() if v is not None}
        if clean: supabase.table('users').update(clean).eq('id', user_id).execute()
        return True
    except: return False

def delete_user(user_id):
    if not supabase or user_id == 1: return False
    try:
        supabase.table('users').delete().eq('id', user_id).execute()
        return True
    except: return False

def init_default_users():
    if not supabase: return False
    try:
        if not get_all_users(): create_user("EL", "ADMIN123", "admin", True, 0)
        return True
    except: return False
