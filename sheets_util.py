import os
import json
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from datetime import datetime

SCOPE = [
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/drive"
]

USED_IPS_SHEET_NAME = "Used IPs"
GOOD_PROXIES_SHEET_NAME = "Good Proxies"

def get_sheet(sheet_name):
    creds_dict = json.loads(os.environ.get("GOOGLE_CREDENTIALS"))
    creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, SCOPE)
    client = gspread.authorize(creds)
    return client.open(sheet_name).sheet1

def add_used_ip(ip, proxy):
    sheet = get_sheet(USED_IPS_SHEET_NAME)
    sheet.append_row([ip, proxy, str(datetime.utcnow())])

def delete_used_ip(ip):
    sheet = get_sheet(USED_IPS_SHEET_NAME)
    data = sheet.get_all_values()
    for i, row in enumerate(data):
        if row and row[0] == ip:
            sheet.delete_row(i + 1)
            return True
    return False

def get_all_used_ips():
    sheet = get_sheet(USED_IPS_SHEET_NAME)
    return [row[0] for row in sheet.get_all_values() if row]

def log_good_proxy(proxy, ip):
    sheet = get_sheet(GOOD_PROXIES_SHEET_NAME)
    sheet.append_row([proxy, ip, str(datetime.utcnow())])

def get_good_proxies():
    sheet = get_sheet(GOOD_PROXIES_SHEET_NAME)
    return [row[0] for row in sheet.get_all_values() if row]