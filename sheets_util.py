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
    "system_logs": { # <-- NEW CONFIG
        "name": "System Logs",
        "worksheets": {
            "logs": {
                "name": "ApplicationLogs",
                "headers": ["Timestamp", "Level", "Message"]
            }
        }
    }
}

def get_eat_time():
    """Get current time in EAT (East Africa Time) and format as YYYY-MM-DD HH:MM:SS"""
    utc_now = datetime.utcnow()
    eat_timezone = pytz.timezone('Africa/Nairobi') # EAT Timezone
    eat_now = utc_now.replace(tzinfo=pytz.utc).astimezone(eat_timezone)
    return eat_now.strftime("%Y-%m-%d %H:%M:%S") # MODIFIED: Added Seconds

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
            # Initialize worksheets and headers
            for ws_key, ws_config in config["worksheets"].items():
                try:
                    worksheet = spreadsheet.add_worksheet(
                        title=ws_config["name"],
                        rows=100, # Initial size
                        cols=len(ws_config["headers"])
                    )
                    worksheet.append_row(ws_config["headers"])
                    logger.info(f"Created worksheet '{ws_config['name']}' with headers.")
                except Exception as create_ws_e:
                     logger.error(f"Error creating initial worksheet '{ws_config['name']}': {create_ws_e}")
            # Special handling for default settings sheet if needed
            if sheet_type == "settings":
                settings_ws = spreadsheet.worksheet("Settings")
                # Add default settings if you want them pre-populated
                # settings_ws.append_row(["MAX_PASTE", "30"])
                # ... etc.
            return spreadsheet
        except gspread.exceptions.APIError as api_e:
             logger.error(f"Google API Error accessing spreadsheet '{config['name']}': {api_e}")
             return None

    except ValueError as ve:
         logger.critical(f"Configuration error: {ve}")
         return None
    except Exception as e:
        logger.error(f"Unexpected error accessing Google Sheet '{config.get('name', 'N/A')}': {str(e)}", exc_info=True)
        return None


def get_worksheet(sheet_type, worksheet_key):
    """Get a specific worksheet by key within a spreadsheet, ensuring headers."""
    spreadsheet = get_spreadsheet(sheet_type)
    if not spreadsheet:
        return None

    if sheet_type not in SHEET_CONFIG or worksheet_key not in SHEET_CONFIG[sheet_type]["worksheets"]:
        logger.error(f"Invalid sheet_type '{sheet_type}' or worksheet_key '{worksheet_key}' in config.")
        return None

    config = SHEET_CONFIG[sheet_type]["worksheets"][worksheet_key]
    expected_headers = config["headers"]

    try:
        worksheet = spreadsheet.worksheet(config["name"])
        # Check and fix headers if necessary
        try:
            # Use get_values to avoid errors on empty sheets after header row
            header_values = worksheet.get_values('1:1')
            existing_headers = header_values[0] if header_values else []

            if existing_headers != expected_headers:
                logger.warning(f"Worksheet '{config['name']}' headers mismatch. Expected: {expected_headers}, Found: {existing_headers}. Resetting headers.")
                worksheet.clear() # Clear might be too destructive, consider updating instead if needed
                worksheet.append_row(expected_headers)
        except IndexError: # Happens if sheet is completely empty
             logger.warning(f"Worksheet '{config['name']}' was empty. Setting headers.")
             worksheet.append_row(expected_headers)
        except gspread.exceptions.APIError as api_e:
             logger.error(f"API Error checking/setting headers for worksheet '{config['name']}': {api_e}")
             # Decide if you want to proceed without headers or return None
             # return None
        return worksheet

    except gspread.WorksheetNotFound:
        logger.warning(f"Worksheet '{config['name']}' not found. Creating it.")
        try:
            worksheet = spreadsheet.add_worksheet(
                title=config["name"],
                rows=100,
                cols=len(expected_headers)
            )
            worksheet.append_row(expected_headers)
            logger.info(f"Created worksheet '{config['name']}' with headers.")
            return worksheet
        except Exception as e:
            logger.error(f"Error creating worksheet '{config['name']}': {e}")
            return None
    except gspread.exceptions.APIError as api_e:
        logger.error(f"Google API Error opening worksheet '{config['name']}': {api_e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting worksheet '{config.get('name', 'N/A')}': {e}", exc_info=True)
        return None


def add_used_ip(ip, proxy):
    """Add a used proxy IP to the UsedProxies worksheet"""
    try:
        sheet = get_worksheet("used_ips", "proxies")
        if sheet:
            # Optimization: Check if IP already exists *before* getting all records
            try:
                cell = sheet.find(ip, in_column=1) # Find IP in the first column
                if cell:
                    logger.debug(f"IP {ip} already marked as used.")
                    return True # Already exists
            except gspread.exceptions.CellNotFound:
                # Good, IP not found, proceed to add
                pass
            except gspread.exceptions.APIError as api_e:
                 logger.error(f"API Error searching for IP {ip} in UsedProxies: {api_e}")
                 # Decide whether to attempt append anyway or fail
                 # return False
            except Exception as find_e:
                logger.error(f"Unexpected error searching for IP {ip} in UsedProxies: {find_e}")
                # Decide whether to attempt append anyway or fail
                # return False

            # Append the new row
            try:
                sheet.append_row([ip, proxy, get_eat_time()])
                logger.debug(f"Appended used IP {ip} / Proxy {proxy}")
                return True
            except gspread.exceptions.APIError as api_e:
                 logger.error(f"API Error appending used IP {ip}: {api_e}")
                 return False
            except Exception as append_e:
                logger.error(f"Unexpected error appending used IP {ip}: {append_e}")
                return False
        else:
             logger.error("Could not get 'UsedProxies' worksheet to add used IP.")
             return False
    except Exception as e:
        logger.error(f"Error in add_used_ip function: {e}", exc_info=True)
        return False


def delete_used_ip(ip):
    """Delete a used IP from the UsedProxies worksheet"""
    try:
        sheet = get_worksheet("used_ips", "proxies")
        if not sheet:
            logger.error("Could not get 'UsedProxies' worksheet to delete IP.")
            return False

        try:
            cell = sheet.find(ip, in_column=1)  # Column 1 is IP
            if cell:
                sheet.delete_rows(cell.row) # Use delete_rows for robustness
                logger.info(f"Deleted row {cell.row} for IP {ip}.")
                return True
            else:
                logger.warning(f"IP {ip} not found in UsedProxies sheet for deletion.")
                return False # Not found is not an error, but indicates nothing deleted
        except gspread.exceptions.CellNotFound:
             logger.warning(f"IP {ip} not found in UsedProxies sheet for deletion.")
             return False
        except gspread.exceptions.APIError as api_e:
             logger.error(f"API Error deleting IP {ip}: {api_e}")
             return False
        except Exception as e:
            logger.error(f"Unexpected error deleting used IP {ip}: {e}", exc_info=True)
            return False

    except Exception as e:
        logger.error(f"Error in delete_used_ip function: {e}", exc_info=True)
        return False


def get_all_used_ips():
    """Get all used IPs from UsedProxies worksheet as records"""
    try:
        sheet = get_worksheet("used_ips", "proxies")
        if not sheet:
            logger.error("Could not get 'UsedProxies' worksheet to get all IPs.")
            return []
        try:
            # Fetch all values, skip header row for get_all_records
            # Handle potential empty sheet after headers
            data = sheet.get_all_records()
            return data
        except gspread.exceptions.APIError as api_e:
             logger.error(f"API Error getting all used IPs: {api_e}")
             return []
        except Exception as get_e:
            logger.error(f"Unexpected error getting all used IPs: {get_e}", exc_info=True)
            return []

    except Exception as e:
        logger.error(f"Error in get_all_used_ips function: {e}", exc_info=True)
        return []


def log_bad_proxy(proxy, ip, score):
    """Log a bad proxy to the BAD worksheet"""
    try:
        sheet = get_worksheet("used_ips", "bad_proxies")
        if sheet:
            # Optimization: Check if Proxy already exists *before* getting all records
            try:
                cell = sheet.find(proxy, in_column=1) # Find Proxy in the first column
                if cell:
                    logger.debug(f"Proxy {proxy} already marked as bad.")
                    return True # Already logged
            except gspread.exceptions.CellNotFound:
                 pass # Good, proceed to add
            except gspread.exceptions.APIError as api_e:
                 logger.error(f"API Error searching for bad proxy {proxy}: {api_e}")
                 # return False
            except Exception as find_e:
                 logger.error(f"Unexpected error searching for bad proxy {proxy}: {find_e}")
                 # return False

            # Append new row
            try:
                sheet.append_row([proxy, ip, score, get_eat_time()])
                logger.debug(f"Logged bad proxy: {proxy}")
                return True
            except gspread.exceptions.APIError as api_e:
                logger.error(f"API Error logging bad proxy {proxy}: {api_e}")
                return False
            except Exception as append_e:
                logger.error(f"Unexpected error logging bad proxy {proxy}: {append_e}")
                return False
        else:
            logger.error("Could not get 'BAD' worksheet to log bad proxy.")
            return False
    except Exception as e:
        logger.error(f"Error in log_bad_proxy function: {e}", exc_info=True)
        return False


def get_bad_proxies_list():
    """Get all bad proxy strings from BAD worksheet for cache"""
    try:
        sheet = get_worksheet("used_ips", "bad_proxies")
        if not sheet:
             logger.error("Could not get 'BAD' worksheet to get bad proxy list.")
             return []
        try:
            # Fetch only the first column (Proxy) after the header
            # Adjust range if sheet grows significantly, but 'A2:A' is usually fine
            proxy_values = sheet.col_values(1, value_render_option='UNFORMATTED_VALUE')[1:] # Skip header
            return proxy_values
        except gspread.exceptions.APIError as api_e:
            logger.error(f"API Error getting bad proxies list: {api_e}")
            return []
        except Exception as get_e:
            logger.error(f"Unexpected error getting bad proxies list: {get_e}", exc_info=True)
            return []

    except Exception as e:
        logger.error(f"Error in get_bad_proxies_list function: {e}", exc_info=True)
        return []


def get_settings():
    """Get application settings from Settings worksheet"""
    settings = {}
    try:
        sheet = get_worksheet("settings", "main")
        if not sheet:
            logger.error("Could not get 'Settings' worksheet.")
            return {} # Return empty dict, app.py will use defaults
        try:
            records = sheet.get_all_records()
            for row in records:
                if row.get("Setting"): # Ensure Setting key exists
                    settings[row["Setting"]] = row.get("Value", "") # Default to empty string if Value missing
            return settings
        except gspread.exceptions.APIError as api_e:
            logger.error(f"API Error getting settings: {api_e}")
            return {}
        except Exception as get_e:
            logger.error(f"Unexpected error getting settings: {get_e}", exc_info=True)
            return {}

    except Exception as e:
        logger.error(f"Error in get_settings function: {e}", exc_info=True)
        return {}


def update_setting(setting_name, value):
    """Update a setting in Settings worksheet, or add if it doesn't exist"""
    try:
        sheet = get_worksheet("settings", "main")
        if not sheet:
            logger.error("Could not get 'Settings' worksheet to update setting.")
            return False

        try:
            cell = sheet.find(setting_name, in_column=1)  # Column 1 is Setting
            if cell:
                # Update existing setting
                sheet.update_cell(cell.row, 2, str(value))  # Column 2 is Value, ensure string
                logger.info(f"Updated setting '{setting_name}' to '{value}'.")
            else:
                # Append new setting if not found
                sheet.append_row([setting_name, str(value)]) # Ensure string
                logger.info(f"Appended new setting '{setting_name}' with value '{value}'.")
            return True
        except gspread.exceptions.CellNotFound:
             # Append new setting if find fails explicitly
             try:
                 sheet.append_row([setting_name, str(value)])
                 logger.info(f"Appended new setting '{setting_name}' with value '{value}'.")
                 return True
             except Exception as append_e:
                 logger.error(f"Error appending new setting '{setting_name}': {append_e}")
                 return False
        except gspread.exceptions.APIError as api_e:
             logger.error(f"API Error updating setting '{setting_name}': {api_e}")
             return False
        except Exception as e:
            logger.error(f"Unexpected error updating setting '{setting_name}': {e}", exc_info=True)
            return False

    except Exception as e:
        logger.error(f"Error in update_setting function: {e}", exc_info=True)
        return False


# --- NEW SYSTEM LOGGING FUNCTIONS ---

def add_log_entry(level, message):
    """Add a system log entry to the ApplicationLogs worksheet."""
    try:
        sheet = get_worksheet("system_logs", "logs")
        if not sheet:
            logger.error("Could not get 'ApplicationLogs' worksheet to add log entry.")
            return False
        
        # Append new row
        try:
            # Add at the top by inserting a row, then updating its cells
            # This keeps the latest logs at the top for viewing (index=2 means second row, after header)
            sheet.insert_row([get_eat_time(), level, message], index=2)
            logger.debug(f"Logged system event: {level} - {message}")
            return True
        except gspread.exceptions.APIError as api_e:
            logger.error(f"API Error logging system event: {api_e}")
            return False
        except Exception as append_e:
            logger.error(f"Unexpected error logging system event: {append_e}")
            return False
    except Exception as e:
        logger.error(f"Error in add_log_entry function: {e}", exc_info=True)
        return False

def get_all_system_logs():
    """Get all system log records from the ApplicationLogs worksheet."""
    try:
        sheet = get_worksheet("system_logs", "logs")
        if not sheet:
            logger.error("Could not get 'ApplicationLogs' worksheet to get logs.")
            return []
        try:
            # Fetch all records (skips the header row)
            data = sheet.get_all_records()
            return data
        except gspread.exceptions.APIError as api_e:
             logger.error(f"API Error getting system logs: {api_e}")
             return []
        except Exception as get_e:
            logger.error(f"Unexpected error getting system logs: {get_e}", exc_info=True)
            return []

    except Exception as e:
        logger.error(f"Error in get_all_system_logs function: {e}", exc_info=True)
        return []
