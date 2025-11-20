import os
import json
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import logging
import pytz
import time
from functools import wraps

logger = logging.getLogger(__name__)

SCOPE = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

# Sheet configuration
SHEET_CONFIG = {
    "used_ips": {
        "name": "Used IPs",
        "worksheets": {
            "proxies": {
                "name": "UsedProxies",
                "headers": ["IP", "Proxy", "Date"]
            },
            "bad_proxies": {
                "name": "BAD",
                "headers": ["Proxy", "IP", "Score", "Timestamp"]
            }
        }
    },
    "settings": {
        "name": "Settings",
        "worksheets": {
            "main": {
                "name": "Settings",
                "headers": ["Setting", "Value"]
            }
        }
    },
    "system_logs": { 
        "name": "System Logs",
        "worksheets": {
            "logs": {
                "name": "ApplicationLogs",
                "headers": ["Timestamp", "Level", "Message", "IP"]
            }
        }
    },
    "api_usage": {
        "name": "ApiUsageLog",
        "worksheets": {
            "logs": {
                "name": "UsageLogs",
                "headers": ["Timestamp", "Username", "User IP", "Proxies Submitted", "API Calls Made"]
            }
        }
    }
}

# --- GLOBAL CLIENT CACHE ---
# Stores the authenticated client so we don't log in for every single request.
_CACHED_CLIENT = None

def get_eat_time():
    """Get current time in EAT (East Africa Time)"""
    utc_now = datetime.utcnow()
    eat_timezone = pytz.timezone('Africa/Nairobi')
    eat_now = utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone)
    return eat_now.strftime("%Y-%m-%d %H:%M:%S")

def get_gspread_client():
    """
    Returns a singleton gspread client. 
    Reuses the connection to prevent re-authenticating on every call (which hits rate limits).
    """
    global _CACHED_CLIENT
    if _CACHED_CLIENT:
        try:
            # Test if client is still active by trying to perform a lightweight op
            # If this fails, we assume the session expired and re-auth below.
            _CACHED_CLIENT.list_spreadsheet_files() 
            return _CACHED_CLIENT
        except Exception:
            logger.warning("Cached Google client expired or failed. Re-authenticating...")
            _CACHED_CLIENT = None

    try:
        creds_json = os.environ.get("GOOGLE_CREDENTIALS")
        if not creds_json:
            raise ValueError("GOOGLE_CREDENTIALS environment variable not set")

        creds_dict = json.loads(creds_json)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
        _CACHED_CLIENT = gspread.authorize(creds)
        # Set a default timeout to prevent hanging
        _CACHED_CLIENT.timeout = 15
        return _CACHED_CLIENT
    except Exception as e:
        logger.critical(f"Failed to authorize Google Sheets client: {e}")
        return None

def retry_on_api_error(max_retries=3, delay=1.5):
    """
    Decorator to automatically retry a function if it hits a Google API error.
    This is the key to fixing 'saving is a hustle'.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for i in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except gspread.exceptions.APIError as e:
                    last_exception = e
                    # Check if it's a quota error (429) or server error (500+)
                    if hasattr(e, 'response') and e.response.status_code in [429, 500, 502, 503]:
                        wait_time = delay * (i + 1) # Linear backoff (1.5s, 3s, 4.5s)
                        logger.warning(f"Google API Error (attempt {i+1}/{max_retries}). Retrying in {wait_time}s... Error: {e}")
                        time.sleep(wait_time)
                    else:
                        # If it's a permission error or not found, don't retry.
                        raise e 
                except Exception as e:
                     last_exception = e
                     logger.error(f"Unexpected error in {func.__name__}: {e}. Retrying...")
                     time.sleep(delay)
            
            logger.error(f"Function {func.__name__} failed after {max_retries} retries.")
            return None # Return None on final failure
        return wrapper
    return decorator

@retry_on_api_error()
def get_spreadsheet(sheet_type):
    """Get the entire spreadsheet by type using the cached client."""
    client = get_gspread_client()
    if not client: return None

    config = SHEET_CONFIG[sheet_type]
    try:
        return client.open(config["name"])
    except gspread.SpreadsheetNotFound:
        logger.warning(f"Creating new spreadsheet: {config['name']}")
        spreadsheet = client.create(config["name"])
        # Initialize worksheets
        for ws_key, ws_config in config["worksheets"].items():
            try:
                worksheet = spreadsheet.add_worksheet(
                    title=ws_config["name"], rows=100, cols=len(ws_config["headers"])
                )
                worksheet.append_row(ws_config["headers"])
            except: pass
        return spreadsheet

@retry_on_api_error()
def get_worksheet(sheet_type, worksheet_key):
    """Get a specific worksheet by key, ensuring headers."""
    spreadsheet = get_spreadsheet(sheet_type)
    if not spreadsheet: return None

    if sheet_type not in SHEET_CONFIG or worksheet_key not in SHEET_CONFIG[sheet_type]["worksheets"]:
        return None

    config = SHEET_CONFIG[sheet_type]["worksheets"][worksheet_key]
    expected_headers = config["headers"]

    try:
        worksheet = spreadsheet.worksheet(config["name"])
        # Header check optimization: Only read first row to save bandwidth
        header_values = worksheet.get_values('1:1')
        existing_headers = header_values[0] if header_values else []

        if existing_headers != expected_headers:
            worksheet.clear() 
            worksheet.append_row(expected_headers)
        return worksheet
    except gspread.WorksheetNotFound:
        worksheet = spreadsheet.add_worksheet(title=config["name"], rows=100, cols=len(expected_headers))
        worksheet.append_row(expected_headers)
        return worksheet

@retry_on_api_error()
def add_used_ip(ip, proxy):
    sheet = get_worksheet("used_ips", "proxies")
    if not sheet: return False
    
    # Check existence - optimized to use find within retry block
    try:
        cell = sheet.find(ip, in_column=1)
        if cell: return True # Already exists
    except gspread.exceptions.CellNotFound:
        pass

    sheet.append_row([ip, proxy, get_eat_time()])
    return True

@retry_on_api_error()
def delete_used_ip(ip):
    sheet = get_worksheet("used_ips", "proxies")
    if not sheet: return False
    
    try:
        cell = sheet.find(ip, in_column=1)
        if cell:
            sheet.delete_rows(cell.row)
            return True
        return False
    except gspread.exceptions.CellNotFound:
        return False

@retry_on_api_error()
def get_all_used_ips():
    sheet = get_worksheet("used_ips", "proxies")
    return sheet.get_all_records() if sheet else []

@retry_on_api_error()
def log_bad_proxy(proxy, ip, score):
    sheet = get_worksheet("used_ips", "bad_proxies")
    if not sheet: return False
    
    try:
        cell = sheet.find(proxy, in_column=1)
        if cell: return True
    except gspread.exceptions.CellNotFound:
        pass
        
    sheet.append_row([proxy, ip, score, get_eat_time()])
    return True

@retry_on_api_error()
def get_bad_proxies_list():
    sheet = get_worksheet("used_ips", "bad_proxies")
    if not sheet: return []
    # Use col_values to save bandwidth (only fetches column A)
    return sheet.col_values(1)[1:]

@retry_on_api_error()
def get_settings():
    sheet = get_worksheet("settings", "main")
    if not sheet: return {}
    
    records = sheet.get_all_records()
    settings = {}
    for row in records:
        if row.get("Setting"):
            settings[row["Setting"]] = row.get("Value", "")
    return settings

@retry_on_api_error()
def update_setting(setting_name, value):
    sheet = get_worksheet("settings", "main")
    if not sheet: return False
    
    try:
        cell = sheet.find(setting_name, in_column=1)
        if cell:
            sheet.update_cell(cell.row, 2, str(value))
        else:
            sheet.append_row([setting_name, str(value)])
        return True
    except gspread.exceptions.CellNotFound:
        sheet.append_row([setting_name, str(value)])
        return True

@retry_on_api_error()
def add_log_entry(level, message, ip="N/A"):
    sheet = get_worksheet("system_logs", "logs")
    if not sheet: return False
    # Insert row at top (index 2 because 1 is header) so newest logs are first
    sheet.insert_row([get_eat_time(), level, message, ip], index=2)
    return True

@retry_on_api_error()
def get_all_system_logs():
    sheet = get_worksheet("system_logs", "logs")
    return sheet.get_all_records() if sheet else []

@retry_on_api_error()
def clear_all_system_logs():
    sheet_type = "system_logs"
    worksheet_key = "logs"
    # We use get_worksheet to get the object
    spreadsheet = get_spreadsheet(sheet_type)
    if not spreadsheet: return False

    config = SHEET_CONFIG[sheet_type]["worksheets"][worksheet_key]
    try:
        worksheet = spreadsheet.worksheet(config["name"])
        worksheet.clear()
        worksheet.append_row(config["headers"])
        return True
    except: return False

@retry_on_api_error()
def add_api_usage_log(username, ip, submitted_count, api_calls_count):
    sheet = get_worksheet("api_usage", "logs")
    if not sheet: return False
    sheet.insert_row([get_eat_time(), username, ip, submitted_count, api_calls_count], index=2)
    return True

@retry_on_api_error()
def get_all_api_usage_logs():
    sheet = get_worksheet("api_usage", "logs")
    return sheet.get_all_records() if sheet else []
