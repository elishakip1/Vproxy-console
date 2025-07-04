import os
import json
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime
import logging

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

def get_sheet(sheet_type):
    """Get a sheet by type (used_ips or good_proxies) with fallback"""
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
                return client.open(name).sheet1
            except gspread.SpreadsheetNotFound:
                continue
                
        # If none found, create first variant
        logger.warning(f"Creating new sheet: {variants[0]}")
        return client.create(variants[0]).sheet1

    except Exception as e:
        logger.error(f"Error accessing Google Sheet: {str(e)}")
        return None

def add_used_ip(ip, proxy):
    try:
        sheet = get_sheet("used_ips")
        if sheet:
            sheet.append_row([ip, proxy, str(datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error adding used IP: {e}")

def delete_used_ip(ip):
    try:
        sheet = get_sheet("used_ips")
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
        sheet = get_sheet("used_ips")
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
        sheet = get_sheet("good_proxies")
        if sheet:
            sheet.append_row([proxy, ip, str(datetime.utcnow())])
    except Exception as e:
        logger.error(f"Error logging good proxy: {e}")

def get_good_proxies():
    try:
        sheet = get_sheet("good_proxies")
        if not sheet:
            return []
            
        # Return just the proxy strings for display
        return [row[0] for row in sheet.get_all_values()[1:] if row]
    except Exception as e:
        logger.error(f"Error getting good proxies: {e}")
        return []

def get_settings():
    try:
        sheet = get_sheet("settings")
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
        sheet = get_sheet("settings")
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