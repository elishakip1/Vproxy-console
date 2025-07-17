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

# Allow name variations
SHEET_NAME_VARIANTS = {
    "used_ips": ["Used IPs", "Used IP List", "Used_IPs"],
    "good_proxies": ["Good Proxies", "Good_Proxies", "GoodProxies"],
    "settings": ["Settings", "App Settings", "Settings_Sheet"]
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

        variants = SHEET_NAME_VARIANTS[sheet_type]
        
        for name in variants:
            try:
                return client.open(name)
            except gspread.SpreadsheetNotFound:
                continue
                
        # If none found, create first variant
        logger.warning(f"Creating new sheet: {variants[0]}")
        return client.create(variants[0])

    except Exception as e:
        logger.error(f"Error accessing Google Sheet: {str(e)}")
        return None

def get_worksheet(sheet_type, worksheet_name):
    """Get a specific worksheet by name within a spreadsheet"""
    spreadsheet = get_spreadsheet(sheet_type)
    if not spreadsheet:
        return None
        
    try:
        return spreadsheet.worksheet(worksheet_name)
    except gspread.WorksheetNotFound:
        try:
            return spreadsheet.add_worksheet(title=worksheet_name, rows=100, cols=10)
        except Exception as e:
            logger.error(f"Error creating worksheet: {e}")
            return None

def add_used_ip(ip, proxy):
    try:
        sheet = get_worksheet("used_ips", "UsedProxies")
        if sheet:
            sheet.append_row([ip, proxy, get_eat_time()])
    except Exception as e:
        logger.error(f"Error adding used IP: {e}")

def delete_used_ip(ip):
    try:
        sheet = get_worksheet("used_ips", "UsedProxies")
        if not sheet: 
            return False
        
        data = sheet.get_all_values()
        for i, row in enumerate(data):
            if row and row[0] == ip:
                sheet.delete_row(i + 1)
                return True
        return False
    except Exception as e:
        logger.error(f"Error deleting used IP: {e}")
        return False

def get_all_used_ips():
    try:
        sheet = get_worksheet("used_ips", "UsedProxies")
        if not sheet:
            return []
            
        # Return as list of dicts for admin panel
        headers = sheet.row_values(1)
        records = sheet.get_all_records()
        
        # If no headers, create default structure
        if not headers or len(headers) < 3:
            return [{"IP": row[0], "Proxy": row[1], "Date": row[2]} for row in sheet.get_all_values()[1:] if row]
            
        return records
    except Exception as e:
        logger.error(f"Error getting used IPs: {e}")
        return []

def log_good_proxy(proxy, ip):
    try:
        sheet = get_worksheet("good_proxies", "GoodProxies")
        if sheet:
            sheet.append_row([proxy, ip, get_eat_time()])
    except Exception as e:
        logger.error(f"Error logging good proxy: {e}")

def get_good_proxies():
    try:
        sheet = get_worksheet("good_proxies", "GoodProxies")
        if not sheet:
            return []
            
        # Return just the proxy strings for display
        return [row[0] for row in sheet.get_all_values()[1:] if row]
    except Exception as e:
        logger.error(f"Error getting good proxies: {e}")
        return []

def get_settings():
    try:
        sheet = get_worksheet("settings", "Settings")
        if not sheet:
            return {}
        records = sheet.get_all_records()
        settings = {}
        for row in records:
            if 'Setting' in row and 'Value' in row:
                settings[row['Setting']] = row['Value']
        return settings
    except Exception as e:
        logger.error(f"Error getting settings: {e}")
        return {}

def update_setting(setting_name, value):
    try:
        sheet = get_worksheet("settings", "Settings")
        if not sheet:
            return False
            
        data = sheet.get_all_values()
        headers = data[0] if data else []
        if not headers or headers[0] != 'Setting' or headers[1] != 'Value':
            sheet.clear()
            sheet.append_row(['Setting', 'Value'])
            data = []
            
        found = False
        for i, row in enumerate(data[1:], start=2):
            if row and row[0] == setting_name:
                sheet.update_cell(i, 2, value)
                found = True
                break
                
        if not found:
            sheet.append_row([setting_name, value])
            
        return True
    except Exception as e:
        logger.error(f"Error updating setting: {e}")
        return False

# New functions for IP management
def log_user_access(ip, user_agent):
    """Log user access to AccessLogs worksheet"""
    try:
        sheet = get_worksheet("used_ips", "AccessLogs")
        if sheet:
            sheet.append_row([ip, "ACCESS", user_agent, get_eat_time()])
    except Exception as e:
        logger.error(f"Error logging user access: {e}")

def get_blocked_ips():
    """Get blocked IPs from BlockedIPs worksheet"""
    try:
        sheet = get_worksheet("used_ips", "BlockedIPs")
        if not sheet:
            return []
        # Return as list of dicts
        return [{"IP": row[0], "Reason": row[1], "Date": row[2]} 
                for row in sheet.get_all_values()[1:] 
                if row]
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return []

def add_blocked_ip(ip, reason):
    """Add blocked IP to BlockedIPs worksheet"""
    try:
        sheet = get_worksheet("used_ips", "BlockedIPs")
        if sheet:
            sheet.append_row([ip, reason, get_eat_time()])
            return True
        return False
    except Exception as e:
        logger.error(f"Error adding blocked IP: {e}")
        return False

def remove_blocked_ip(ip):
    """Remove blocked IP from BlockedIPs worksheet"""
    try:
        sheet = get_worksheet("used_ips", "BlockedIPs")
        if not sheet: 
            return False
        data = sheet.get_all_values()
        for i, row in enumerate(data):
            if row and row[0] == ip:
                sheet.delete_row(i + 1)
                return True
        return False
    except Exception as e:
        logger.error(f"Error removing blocked IP: {e}")
        return False
