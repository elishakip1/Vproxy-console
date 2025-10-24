import os
import json
import logging
from datetime import datetime
import pytz

logger = logging.getLogger(__name__)

# In-memory storage for Vercel deployment
_memory_storage = {
    "used_ips": [],
    "good_proxies": [], 
    "blocked_ips": [],
    "settings": {
        "MAX_PASTE": "30",
        "FRAUD_SCORE_LEVEL": "0", 
        "MAX_WORKERS": "5",
        "ALLOWED_PASSWORDS": "8soFs0QqNJivObgW,JBZAeWoqvF1XqOuw,68166538"
    }
}

def get_eat_time():
    """Get current time in EAT (East Africa Time)"""
    utc_now = datetime.utcnow()
    eat_timezone = pytz.timezone('Africa/Nairobi')
    eat_now = utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone)
    return eat_now.strftime("%Y-%m-%d %H:%M")

# Check if we're on Vercel and credentials are available
def _use_google_sheets():
    if os.environ.get('VERCEL') and not os.environ.get("GOOGLE_CREDENTIALS"):
        return False
    try:
        import gspread
        from oauth2client.service_account import ServiceAccountCredentials
        return True
    except ImportError:
        return False

# Google Sheets functions (only if available)
if _use_google_sheets():
    import gspread
    from oauth2client.service_account import ServiceAccountCredentials
    
    SCOPE = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ]

    SHEET_CONFIG = {
        "used_ips": {
            "name": "Used IPs",
            "worksheets": {
                "proxies": {
                    "name": "UsedProxies",
                    "headers": ["IP", "Proxy", "Date"]
                },
                "access": {
                    "name": "AccessLogs",
                    "headers": ["IP", "Type", "UserAgent", "Timestamp"]
                },
                "blocked": {
                    "name": "BlockedIPs",
                    "headers": ["IP", "Reason", "Timestamp"]
                }
            }
        },
        "good_proxies": {
            "name": "Good Proxies",
            "worksheets": {
                "main": {
                    "name": "GoodProxies",
                    "headers": ["Proxy", "IP", "Timestamp"]
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
        }
    }

    def get_spreadsheet(sheet_type):
        try:
            creds_json = os.environ.get("GOOGLE_CREDENTIALS")
            if not creds_json:
                return None
                
            creds_dict = json.loads(creds_json)
            creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
            client = gspread.authorize(creds)
            client.timeout = 10

            config = SHEET_CONFIG[sheet_type]
            
            try:
                return client.open(config["name"])
            except gspread.SpreadsheetNotFound:
                logger.warning(f"Spreadsheet not found: {config['name']}")
                return None
        except Exception as e:
            logger.error(f"Error accessing Google Sheet: {str(e)}")
            return None

    def get_worksheet(sheet_type, worksheet_key):
        spreadsheet = get_spreadsheet(sheet_type)
        if not spreadsheet:
            return None
            
        config = SHEET_CONFIG[sheet_type]["worksheets"][worksheet_key]
        
        try:
            return spreadsheet.worksheet(config["name"])
        except gspread.WorksheetNotFound:
            return None

    def add_used_ip(ip, proxy):
        if not _use_google_sheets():
            # Memory fallback
            _memory_storage["used_ips"].append({
                "IP": ip, "Proxy": proxy, "Date": get_eat_time()
            })
            return True
            
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
        if not _use_google_sheets():
            _memory_storage["used_ips"] = [
                item for item in _memory_storage["used_ips"] 
                if item["IP"] != ip
            ]
            return True
            
        try:
            sheet = get_worksheet("used_ips", "proxies")
            if not sheet: 
                return False
            
            cell = sheet.find(ip, in_column=1)
            if cell:
                sheet.delete_row(cell.row)
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting used IP: {e}")
            return False

    def get_all_used_ips():
        if not _use_google_sheets():
            return _memory_storage["used_ips"]
            
        try:
            sheet = get_worksheet("used_ips", "proxies")
            if not sheet:
                return []
            return sheet.get_all_records()
        except Exception as e:
            logger.error(f"Error getting used IPs: {e}")
            return []

    def log_good_proxy(proxy, ip):
        if not _use_google_sheets():
            _memory_storage["good_proxies"].append({
                "Proxy": proxy, "IP": ip, "Timestamp": get_eat_time()
            })
            return True
            
        try:
            sheet = get_worksheet("good_proxies", "main")
            if sheet:
                # Check if proxy already exists
                records = sheet.get_all_records()
                for record in records:
                    if record["Proxy"] == proxy:
                        return True
                
                sheet.append_row([proxy, ip, get_eat_time()])
                return True
            return False
        except Exception as e:
            logger.error(f"Error logging good proxy: {e}")
            return False

    def get_good_proxies():
        if not _use_google_sheets():
            return [item["Proxy"] for item in _memory_storage["good_proxies"]]
            
        try:
            sheet = get_worksheet("good_proxies", "main")
            if not sheet:
                return []
            return [row["Proxy"] for row in sheet.get_all_records()]
        except Exception as e:
            logger.error(f"Error getting good proxies: {e}")
            return []

    def get_settings():
        if not _use_google_sheets():
            return _memory_storage["settings"]
            
        try:
            sheet = get_worksheet("settings", "main")
            if not sheet:
                return {}
            settings = {}
            for row in sheet.get_all_records():
                # Ensure ALLOWED_PASSWORDS is always a string
                if row["Setting"] == "ALLOWED_PASSWORDS":
                    settings[row["Setting"]] = str(row["Value"])
                else:
                    settings[row["Setting"]] = row["Value"]
            return settings
        except Exception as e:
            logger.error(f"Error getting settings: {e}")
            return {}

    def update_setting(setting_name, value):
        if not _use_google_sheets():
            _memory_storage["settings"][setting_name] = str(value)
            return True
            
        try:
            sheet = get_worksheet("settings", "main")
            if not sheet:
                return False
                
            # Find the setting if it exists
            cell = sheet.find(setting_name, in_column=1)
            if cell:
                sheet.update_cell(cell.row, 2, str(value))
            else:
                sheet.append_row([setting_name, str(value)])
            return True
        except Exception as e:
            logger.error(f"Error updating setting: {e}")
            return False

    def log_user_access(ip, user_agent):
        if not _use_google_sheets():
            return True
            
        try:
            sheet = get_worksheet("used_ips", "access")
            if sheet:
                sheet.append_row([ip, "ACCESS", user_agent, get_eat_time()])
                return True
            return False
        except Exception as e:
            logger.error(f"Error logging user access: {e}")
            return False

    def get_blocked_ips():
        if not _use_google_sheets():
            return _memory_storage["blocked_ips"]
            
        try:
            sheet = get_worksheet("used_ips", "blocked")
            if not sheet:
                return []
            return sheet.get_all_records()
        except Exception as e:
            logger.error(f"Error getting blocked IPs: {e}")
            return []

    def add_blocked_ip(ip, reason):
        if not _use_google_sheets():
            _memory_storage["blocked_ips"].append({
                "IP": ip, "Reason": reason, "Timestamp": get_eat_time()
            })
            return True
            
        try:
            sheet = get_worksheet("used_ips", "blocked")
            if sheet:
                # Check if IP is already blocked
                records = sheet.get_all_records()
                for record in records:
                    if record["IP"] == ip:
                        return True
                
                sheet.append_row([ip, reason, get_eat_time()])
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding blocked IP: {e}")
            return False

    def remove_blocked_ip(ip):
        if not _use_google_sheets():
            _memory_storage["blocked_ips"] = [
                item for item in _memory_storage["blocked_ips"]
                if item["IP"] != ip
            ]
            return True
            
        try:
            sheet = get_worksheet("used_ips", "blocked")
            if not sheet: 
                return False
            
            cell = sheet.find(ip, in_column=1)
            if cell:
                sheet.delete_row(cell.row)
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing blocked IP: {e}")
            return False

    def is_ip_blocked(ip):
        if not _use_google_sheets():
            return any(item["IP"] == ip for item in _memory_storage["blocked_ips"])
            
        try:
            sheet = get_worksheet("used_ips", "blocked")
            if not sheet:
                return False
            cell = sheet.find(ip, in_column=1)
            return bool(cell)
        except Exception as e:
            logger.error(f"Error checking blocked IP: {e}")
            return False

else:
    # Memory-based implementations for Vercel
    def add_used_ip(ip, proxy):
        _memory_storage["used_ips"].append({
            "IP": ip, "Proxy": proxy, "Date": get_eat_time()
        })
        return True

    def get_all_used_ips():
        return _memory_storage["used_ips"]

    def delete_used_ip(ip):
        _memory_storage["used_ips"] = [
            item for item in _memory_storage["used_ips"] 
            if item["IP"] != ip
        ]
        return True

    def log_good_proxy(proxy, ip):
        _memory_storage["good_proxies"].append({
            "Proxy": proxy, "IP": ip, "Timestamp": get_eat_time()
        })
        return True

    def get_good_proxies():
        return [item["Proxy"] for item in _memory_storage["good_proxies"]]

    def get_settings():
        # Ensure ALLOWED_PASSWORDS is always a string
        settings = _memory_storage["settings"].copy()
        if "ALLOWED_PASSWORDS" in settings:
            settings["ALLOWED_PASSWORDS"] = str(settings["ALLOWED_PASSWORDS"])
        return settings

    def update_setting(setting_name, value):
        _memory_storage["settings"][setting_name] = str(value)
        return True

    def log_user_access(ip, user_agent):
        return True  # Skip logging on Vercel

    def get_blocked_ips():
        return _memory_storage["blocked_ips"]

    def add_blocked_ip(ip, reason):
        _memory_storage["blocked_ips"].append({
            "IP": ip, "Reason": reason, "Timestamp": get_eat_time()
        })
        return True

    def remove_blocked_ip(ip):
        _memory_storage["blocked_ips"] = [
            item for item in _memory_storage["blocked_ips"]
            if item["IP"] != ip
        ]
        return True

    def is_ip_blocked(ip):
        return any(item["IP"] == ip for item in _memory_storage["blocked_ips"])
