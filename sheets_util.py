import os
import json
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import logging
import pytz

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
            # --- REMOVED "access" and "blocked" worksheets ---
            "bad_proxies": {
                "name": "BAD",
                "headers": ["Proxy", "IP", "Score", "Timestamp"]
            }
        }
    },
    # --- REMOVED "good_proxies" sheet ---
    "settings": {
        "name": "Settings",
        "worksheets": {
            "main": {
                "name": "Settings",
                "headers": ["Setting", "Value"]
            }
        }
    }
}

def get_eat_time():
    """Get current time in EAT (East Africa Time) and format as YYYY-MM-DD HH:MM"""
    utc_now = datetime.utcnow()
    eat_timezone = pytz.timezone('Africa/Nairobi')
    eat_now = utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone)
    return eat_now.strftime("%Y-%m-%d %H:%M")

def get_spreadsheet(sheet_type):
    """Get the entire spreadsheet by type"""
    try:
        creds_json = os.environ.get("GOOGLE_CREDENTIALS")
        if not creds_json:
            raise ValueError("GOOGLE_CREDENTIALS environment variable not set")
            
        creds_dict = json.loads(creds_json)
        creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
        client = gspread.authorize(creds)
        client.timeout = 10  # seconds

        config = SHEET_CONFIG[sheet_type]
        
        try:
            return client.open(config["name"])
        except gspread.SpreadsheetNotFound:
            logger.warning(f"Creating new spreadsheet: {config['name']}")
            spreadsheet = client.create(config["name"])
            # Initialize worksheets
            for ws_config in config["worksheets"].values():
                worksheet = spreadsheet.add_worksheet(
                    title=ws_config["name"], 
                    rows=100, 
                    cols=len(ws_config["headers"])
                )
                worksheet.append_row(ws_config["headers"])
            return spreadsheet

    except Exception as e:
        logger.error(f"Error accessing Google Sheet: {str(e)}")
        return None

def get_worksheet(sheet_type, worksheet_key):
    """Get a specific worksheet by key within a spreadsheet"""
    spreadsheet = get_spreadsheet(sheet_type)
    if not spreadsheet:
        return None
        
    config = SHEET_CONFIG[sheet_type]["worksheets"][worksheet_key]
    
    try:
        worksheet = spreadsheet.worksheet(config["name"])
        # Ensure headers exist
        existing_headers = worksheet.row_values(1)
        if existing_headers != config["headers"]:
            worksheet.clear()
            worksheet.append_row(config["headers"])
        return worksheet
    except gspread.WorksheetNotFound:
        try:
            worksheet = spreadsheet.add_worksheet(
                title=config["name"], 
                rows=100, 
                cols=len(config["headers"])
            )
            worksheet.append_row(config["headers"])
            return worksheet
        except Exception as e:
            logger.error(f"Error creating worksheet: {e}")
            return None

def add_used_ip(ip, proxy):
    """Add a used proxy IP to the UsedProxies worksheet"""
    try:
        sheet = get_worksheet("used_ips", "proxies")
        if sheet:
            # Check if IP already exists
            records = sheet.get_all_records()
            for record in records:
                if record["IP"] == ip:
                    return True
            
            sheet.append_row([ip, proxy, get_eat_time()])
            return True
        return False
    except Exception as e:
        logger.error(f"Error adding used IP: {e}")
        return False

def delete_used_ip(ip):
    """Delete a used IP from the UsedProxies worksheet"""
    try:
        sheet = get_worksheet("used_ips", "proxies")
        if not sheet: 
            return False
        
        cell = sheet.find(ip, in_column=1)  # Column 1 is IP
        if cell:
            sheet.delete_row(cell.row)
            return True
        return False
    except Exception as e:
        logger.error(f"Error deleting used IP: {e}")
        return False

def get_all_used_ips():
    """Get all used IPs from UsedProxies worksheet"""
    try:
        sheet = get_worksheet("used_ips", "proxies")
        if not sheet:
            return []
        return sheet.get_all_records()
    except Exception as e:
        logger.error(f"Error getting used IPs: {e}")
        return []

# --- REMOVED log_good_proxy ---
# --- REMOVED get_good_proxies ---

def log_bad_proxy(proxy, ip, score):
    """Log a bad proxy to the BAD worksheet"""
    try:
        sheet = get_worksheet("used_ips", "bad_proxies")
        if sheet:
            # Check if proxy already exists
            records = sheet.get_all_records()
            for record in records:
                if record["Proxy"] == proxy:
                    return True # Already logged
            
            sheet.append_row([proxy, ip, score, get_eat_time()])
            return True
        return False
    except Exception as e:
        logger.error(f"Error logging bad proxy: {e}")
        return False

def get_bad_proxies_list():
    """Get all bad proxy strings from BAD worksheet"""
    try:
        sheet = get_worksheet("used_ips", "bad_proxies")
        if not sheet:
            return []
        # Return only the proxy string for efficient cache lookup
        return [row["Proxy"] for row in sheet.get_all_records()]
    except Exception as e:
        logger.error(f"Error getting bad proxies list: {e}")
        return []

def get_settings():
    """Get application settings from Settings worksheet"""
    try:
        sheet = get_worksheet("settings", "main")
        if not sheet:
            return {}
        settings = {}
        for row in sheet.get_all_records():
            settings[row["Setting"]] = row["Value"]
        return settings
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return {}

def update_setting(setting_name, value):
    """Update a setting in Settings worksheet"""
    try:
        sheet = get_worksheet("settings", "main")
        if not sheet:
            return False
            
        # Find the setting if it exists
        cell = sheet.find(setting_name, in_column=1)  # Column 1 is Setting
        if cell:
            sheet.update_cell(cell.row, 2, value)  # Column 2 is Value
        else:
            sheet.append_row([setting_name, value])
        return True
    except Exception as e:
        logger.error(f"Error updating setting: {e}")
        return False

# --- REMOVED ALL IP MANAGEMENT FUNCTIONS ---
# (log_user_access, get_blocked_ips, add_blocked_ip, remove_blocked_ip, is_ip_blocked)