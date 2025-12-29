import os
import logging
from supabase import create_client, Client
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
except Exception as e:
    logger.critical(f"Failed to initialize Supabase: {e}")
    supabase = None

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

def add_used_ip(ip, proxy, username="Unknown"):
    if not supabase: return False
    try:
        exists = supabase.table('used_proxies').select("id").eq("ip", ip).execute()
        if exists.data: return True
        supabase.table('used_proxies').insert({"ip": ip, "proxy": proxy, "username": username}).execute()
        return True
    except Exception: return False

def get_all_used_ips():
    if not supabase: return []
    try:
        res = supabase.table('used_proxies').select("ip, proxy, created_at, username").order("created_at", desc=True).execute()
        return [{"IP": r['ip'], "Proxy": r['proxy'], "Date": r['created_at'], "User": r.get('username', 'Unknown')} for r in res.data]
    except Exception: return []

def log_bad_proxy(proxy, ip, score):
    if not supabase: return False
    try:
        exists = supabase.table('bad_proxies').select("id").eq("ip", ip).execute()
        if not exists.data:
            supabase.table('bad_proxies').insert({"proxy": proxy, "ip": ip, "score": score}).execute()
        return True
    except Exception: return False

def get_bad_proxies_list():
    if not supabase: return []
    try: return supabase.table('bad_proxies').select("ip, proxy").execute().data 
    except Exception: return []

def add_log_entry(level, message, ip="N/A"):
    if not supabase: return False
    try:
        supabase.table('system_logs').insert({"level": level, "message": message, "ip": ip}).execute()
        return True
    except Exception: return False

def get_all_system_logs():
    if not supabase: return []
    try:
        res = supabase.table('system_logs').select("*").order("created_at", desc=True).limit(200).execute()
        return [{"Timestamp": r['created_at'], "Level": r['level'], "Message": r['message'], "IP": r['ip']} for r in res.data]
    except Exception: return []

def add_api_usage_log(username, ip, submitted_count, api_calls_count, good_proxies_count):
    if not supabase: return False
    try:
        supabase.table('api_usage').insert({
            "username": username, "user_ip": ip, "submitted_count": submitted_count, 
            "api_calls_count": api_calls_count, "good_proxies_count": good_proxies_count
        }).execute()
        return True
    except: return False

def get_daily_api_usage_for_user(username):
    if not supabase: return 0
    try:
        today = datetime.utcnow().strftime("%Y-%m-%d")
        res = supabase.table('api_usage').select("api_calls_count, created_at").eq("username", username).execute()
        return sum(int(r.get('api_calls_count', 0)) for r in res.data if r.get('created_at', '').startswith(today))
    except: return 0

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
        total = supabase.table('proxy_pool').select("id", count="exact").limit(1).execute().count
        py = supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'pyproxy').limit(1).execute().count
        pia = supabase.table('proxy_pool').select("id", count="exact").eq('provider', 'piaproxy').limit(1).execute().count
        return {"total": total or 0, "pyproxy": py or 0, "piaproxy": pia or 0}
    except: return {"total": 0, "pyproxy": 0, "piaproxy": 0}

def get_pool_preview(provider, limit=50):
    if not supabase: return []
    try: return supabase.table('proxy_pool').select("proxy, created_at").eq('provider', provider).order('created_at', desc=True).limit(limit).execute().data
    except: return []

def clear_proxy_pool(target=None):
    if not supabase: return False
    try:
        q = supabase.table('proxy_pool').delete()
        if target and target != 'all': q = q.eq('provider', target)
        else: q = q.neq('id', 0)
        q.execute()
        return True
    except: return False
