# --- IMPORTS ---
from flask import (
    Flask, request, render_template, redirect, url_for,
    jsonify, send_from_directory, flash, session
)
# ... (all other imports remain the same) ...

# ... (logging, app setup, Flask-Login setup, User class all remain the same) ...


# Default configuration values
DEFAULT_SETTINGS = {
    "MAX_PASTE": 30, "FRAUD_SCORE_LEVEL": 0, "MAX_WORKERS": 5,
    "SCAMALYTICS_API_KEY": "YOUR_API_KEY_HERE",
    "SCAMALYTICS_API_URL": "https://api11.scamalytics.com/v3/",
    "SCAMALYTICS_USERNAME": "YOUR_USERNAME_HERE",
    "ANNOUNCEMENT": "",
    "API_CREDITS_USED": "N/A",  # <-- ADDED
    "API_CREDITS_REMAINING": "N/A" # <-- ADDED
}

# ... (USER_AGENTS, REQUEST_TIMEOUT, etc. remain the same) ...


def get_app_settings():
    """Fetches settings from Google Sheet, providing defaults."""
    settings = get_settings()
    return {
        "MAX_PASTE": int(settings.get("MAX_PASTE", DEFAULT_SETTINGS["MAX_PASTE"])),
        "FRAUD_SCORE_LEVEL": int(settings.get("FRAUD_SCORE_LEVEL", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"])),
        "MAX_WORKERS": int(settings.get("MAX_WORKERS", DEFAULT_SETTINGS["MAX_WORKERS"])),
        "SCAMALYTICS_API_KEY": settings.get("SCAMALYTICS_API_KEY", DEFAULT_SETTINGS["SCAMALYTICS_API_KEY"]),
        "SCAMALYTICS_API_URL": settings.get("SCAMALYTICS_API_URL", DEFAULT_SETTINGS["SCAMALYTICS_API_URL"]),
        "SCAMALYTICS_USERNAME": settings.get("SCAMALYTICS_USERNAME", DEFAULT_SETTINGS["SCAMALYTICS_USERNAME"]),
        "ANNOUNCEMENT": settings.get("ANNOUNCEMENT", DEFAULT_SETTINGS["ANNOUNCEMENT"]),
        "API_CREDITS_USED": settings.get("API_CREDITS_USED", DEFAULT_SETTINGS["API_CREDITS_USED"]), # <-- ADDED
        "API_CREDITS_REMAINING": settings.get("API_CREDITS_REMAINING", DEFAULT_SETTINGS["API_CREDITS_REMAINING"]) # <-- ADDED
    }

# ... (validate_proxy_format and get_ip_from_proxy remain the same) ...


def get_fraud_score(ip, proxy_line, api_key, api_url, api_user):
    """Get fraud score via Scamalytics v3 API. (Returns score only)"""
    # This function remains unchanged for the main index page
    if not validate_proxy_format(proxy_line): return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_url = f"http://{user}:{pw}@{host}:{port}"; proxies = { "http": proxy_url, "https": proxy_url }
        session = requests.Session(); retries = Retry(total=1, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries)); session.mount('https://', HTTPAdapter(max_retries=retries))
        url = f"{api_url.rstrip('/')}/{api_user}/?key={api_key}&ip={ip}"; headers = { "User-Agent": random.choice(USER_AGENTS), "Accept": "application/json", }
        response = session.get(url, headers=headers, proxies=proxies, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            try:
                data = response.json()
                if data.get("scamalytics", {}).get("status") == "ok":
                    score = data.get("scamalytics", {}).get("scamalytics_score")
                    if score is not None: return int(score)
                    else: logger.warning(f"API OK but no score for IP {ip} via {proxy_line}")
                else: api_status = data.get('scamalytics', {}).get('status', 'N/A'); logger.error(f"API error '{api_status}' for IP {ip} via {proxy_line}")
            except requests.exceptions.JSONDecodeError: logger.error(f"JSON decode error for IP {ip} via {proxy_line}. Response: {response.text[:100]}")
        else: logger.error(f"API request failed for IP {ip} via {proxy_line}: HTTP {response.status_code} {response.text[:100]}")
    except requests.exceptions.RequestException as e: logger.error(f"⚠️ Network error checking API for IP {ip} via {proxy_line}: {e}")
    except Exception as e: logger.error(f"⚠️ Unexpected error checking API for IP {ip} via {proxy_line}: {e}", exc_info=False)
    return None

# --- NEW FUNCTION ---
def get_fraud_score_detailed(ip, proxy_line, api_key, api_url, api_user):
    """Get detailed fraud score report via Scamalytics v3 API. (Returns full data)"""
    if not validate_proxy_format(proxy_line): return None
    try:
        host, port, user, pw = proxy_line.strip().split(":")
        proxy_url = f"http://{user}:{pw}@{host}:{port}"; proxies = { "http": proxy_url, "https": proxy_url }
        session = requests.Session(); retries = Retry(total=1, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries)); session.mount('https://', HTTPAdapter(max_retries=retries))
        url = f"{api_url.rstrip('/')}/{api_user}/?key={api_key}&ip={ip}"; headers = { "User-Agent": random.choice(USER_AGENTS), "Accept": "application/json", }
        response = session.get(url, headers=headers, proxies=proxies, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            try:
                data = response.json()
                # We need the 'scamalytics' block and 'credits' block
                if data.get("scamalytics", {}).get("status") == "ok":
                    return data # Return the full successful response
                else:
                    api_status = data.get('scamalytics', {}).get('status', 'N/A')
                    logger.error(f"API error '{api_status}' for IP {ip} via {proxy_line}")
                    return None # API error
            except requests.exceptions.JSONDecodeError:
                logger.error(f"JSON decode error for IP {ip} via {proxy_line}. Response: {response.text[:100]}")
                return None # JSON error
        else:
            logger.error(f"API request failed for IP {ip} via {proxy_line}: HTTP {response.status_code} {response.text[:100]}")
            return None # HTTP error
    except requests.exceptions.RequestException as e:
        logger.error(f"⚠️ Network error checking API for IP {ip} via {proxy_line}: {e}")
    except Exception as e:
        logger.error(f"⚠️ Unexpected error checking API for IP {ip} via {proxy_line}: {e}", exc_info=False)
    return None # General error
# --- END NEW FUNCTION ---


def single_check_proxy(proxy_line, fraud_score_level, api_key, api_url, api_user):
    """Checks a single proxy: gets IP and score. (Returns dict or None)"""
    # This function remains unchanged for the main index page
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    if not validate_proxy_format(proxy_line): logger.warning(f"❌ Format fail: {proxy_line}"); return None
    ip = get_ip_from_proxy(proxy_line)
    if not ip: logger.warning(f"❌ No IP: {proxy_line}"); return None
    score = get_fraud_score(ip, proxy_line, api_key, api_url, api_user)
    if score is not None:
        if score <= fraud_score_level:
            logger.info(f"✅ Good: {proxy_line} (IP: {ip}, Score: {score})")
            return {"proxy": proxy_line, "ip": ip}
        else:
            logger.info(f"❌ Score fail: {proxy_line} (IP: {ip}, Score: {score})")
            try: log_bad_proxy(proxy_line, ip, score)
            except Exception as e: logger.error(f"Error logging bad proxy '{proxy_line}': {e}")
            return None
    else: logger.warning(f"❓ No score: {proxy_line} (IP: {ip})"); return None


# --- NEW FUNCTION ---
def single_check_proxy_detailed(proxy_line, fraud_score_level, api_key, api_url, api_user):
    """
    Checks a single proxy with detailed criteria.
    Returns: A dict {'proxy': '...', 'ip': '...', 'credits': {...}} or None
    """
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))
    if not validate_proxy_format(proxy_line):
        logger.warning(f"❌ [Strict] Format fail: {proxy_line}"); return None
        
    ip = get_ip_from_proxy(proxy_line)
    if not ip:
        logger.warning(f"❌ [Strict] No IP: {proxy_line}"); return None
        
    data = get_fraud_score_detailed(ip, proxy_line, api_key, api_url, api_user)
    
    if data and data.get("scamalytics"):
        scam_data = data.get("scamalytics", {})
        credits_data = data.get("credits", {}) # Get credits
        score = scam_data.get("scamalytics_score")
        
        # --- Apply Strict Filtering ---
        try:
            passed = True
            if score is None:
                passed = False
            
            # 1. Score check
            if not (int(score) <= fraud_score_level):
                logger.info(f"❌ [Strict] Score fail: {proxy_line} (Score: {score})")
                passed = False
            
            # 2. Risk check
            if not (scam_data.get("scamalytics_risk") == "low"):
                logger.info(f"❌ [Strict] Risk fail: {proxy_line} (Risk: {scam_data.get('scamalytics_risk')})")
                passed = False

            # 3. Boolean checks (must all be False)
            flags_to_check = [
                "is_datacenter", "is_vpn", "ip_blacklisted", 
                "is_apple_icloud_private_relay", "is_amazon_aws", 
                "is_google", "is_blacklisted_external"
            ]
            
            for flag in flags_to_check:
                if scam_data.get(flag) is True: # Explicitly check for True
                    logger.info(f"❌ [Strict] Flag fail: {proxy_line} ({flag} is True)")
                    passed = False
                    break # One failure is enough
            
            if passed:
                logger.info(f"✅ [Strict] Good: {proxy_line} (IP: {ip}, Score: {score})")
                # Return result *with* credits
                return {"proxy": proxy_line, "ip": ip, "credits": credits_data}
            else:
                # Still log to bad proxies if score was the failure
                if score is not None and int(score) > fraud_score_level:
                    try: log_bad_proxy(proxy_line, ip, score)
                    except Exception as e: logger.error(f"Error logging bad proxy '{proxy_line}': {e}")
                
                # Return None but *with* credits so we can track usage
                return {"proxy": None, "ip": ip, "credits": credits_data}

        except Exception as e:
            logger.error(f"Error during strict check logic for {proxy_line}: {e}")
            return {"proxy": None, "ip": ip, "credits": credits_data} # Return credits even on logic error

    else:
        logger.warning(f"❓ [Strict] No score data: {proxy_line} (IP: {ip})")
        return None # No data from API
# --- END NEW FUNCTION ---


@app.before_request
def before_request_func():
    # Allow /admin/test
    if request.path.startswith(('/static', '/login', '/logout')) or request.path.endswith(('.ico', '.png')) or '/admin/test' in request.path:
        return
    pass

# ... (login, logout routes remain the same) ...


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """Main proxy checker page with early exit."""
    # This function remains unchanged
    try: settings = get_app_settings()
    except Exception as e: logger.critical(f"CRITICAL ERROR getting app settings: {e}", exc_info=True); return render_template("error.html", error="Could not load critical settings."), 500
    MAX_PASTE = settings["MAX_PASTE"]; FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]; MAX_WORKERS = settings["MAX_WORKERS"]
    API_KEY = settings["SCAMALYTICS_API_KEY"]; API_URL = settings["SCAMALYTICS_API_URL"]; API_USER = settings["SCAMALYTICS_USERNAME"]
    announcement = settings.get("ANNOUNCEMENT") 
    results = []; message = None

    if request.method == "POST":
        start_time = time.time(); proxies_input = []; input_count = 0; truncation_warning = ""
        # ... (Handle Input remains the same) ...
        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            try:
                file = request.files['proxyfile']; all_lines = file.read().decode("utf-8", errors='ignore').strip().splitlines(); input_count = len(all_lines)
                if input_count > MAX_PASTE: truncation_warning = f" Input truncated to first {MAX_PASTE}."; proxies_input = all_lines[:MAX_PASTE]
                else: proxies_input = all_lines
                logger.info(f"Received {input_count} via file.")
            except Exception as e: logger.error(f"File read error: {e}", exc_info=True); message = "Error reading file."; return render_template("index.html", results=[], message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement)
        elif 'proxytext' in request.form and request.form.get("proxytext", "").strip():
            proxytext = request.form.get("proxytext", ""); all_lines = proxytext.strip().splitlines(); input_count = len(all_lines)
            if input_count > MAX_PASTE: truncation_warning = f" Input truncated to first {MAX_PASTE}."; proxies_input = all_lines[:MAX_PASTE]
            else: proxies_input = all_lines
            logger.info(f"Received {input_count} via text.")
        else: message = "Please paste proxies or upload file."; return render_template("index.html", results=[], message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement)

        # ... (Load Caches remains the same) ...
        try: used_ips_records = get_all_used_ips(); used_ips_list = {r.get('IP') for r in used_ips_records if r.get('IP')}; used_proxy_cache = {r.get('Proxy') for r in used_ips_records if r.get('Proxy')}; logger.info(f"Loaded {len(used_proxy_cache)} used proxies.")
        except Exception as e: logger.error(f"Error loading used cache: {e}"); used_ips_list = set(); used_proxy_cache = set(); message = "Warn: Could not load used cache."
        try: bad_proxy_cache = set(get_bad_proxies_list()); logger.info(f"Loaded {len(bad_proxy_cache)} bad proxies.")
        except Exception as e: logger.error(f"Error loading bad cache: {e}"); bad_proxy_cache = set(); message = (message or "") + " Warn: Could not load bad cache."
        
        # ... (Filter Proxies remains the same) ...
        proxies_to_check = []; invalid_format_proxies = []; used_count_prefilter = 0; bad_count_prefilter = 0
        unique_proxies_input = set(p.strip() for p in proxies_input if p.strip())
        for proxy in unique_proxies_input:
            if not validate_proxy_format(proxy): invalid_format_proxies.append(proxy); continue
            if proxy in used_proxy_cache: used_count_prefilter += 1; continue
            if proxy in bad_proxy_cache: bad_count_prefilter += 1; continue
            proxies_to_check.append(proxy)
        processed_count = len(proxies_to_check); logger.info(f"Prefiltering done: {len(unique_proxies_input)} unique -> {len(invalid_format_proxies)} invalid, {used_count_prefilter} used, {bad_count_prefilter} bad. {processed_count} to check.")


        # --- Execute Checks (Unchanged) ---
        good_proxy_results = []
        target_good_proxies = 2 
        futures = set()
        cancelled_count = 0

        if proxies_to_check:
            actual_workers = min(MAX_WORKERS, processed_count); logger.info(f"Starting check for {processed_count} proxies using {actual_workers} workers (target: {target_good_proxies} good)...")
            with ThreadPoolExecutor(max_workers=actual_workers) as executor:
                for proxy in proxies_to_check:
                    # Calls the ORIGINAL check function
                    futures.add(executor.submit(single_check_proxy, proxy, FRAUD_SCORE_LEVEL, API_KEY, API_URL, API_USER))

                while futures:
                    done, futures = wait(futures, return_when=FIRST_COMPLETED)
                    for future in done:
                        try:
                            result = future.result()
                            if result:
                                result['used'] = result.get('ip') in used_ips_list
                                good_proxy_results.append(result)
                                if len([r for r in good_proxy_results if not r['used']]) >= target_good_proxies:
                                    logger.info(f"Target of {target_good_proxies} usable proxies reached. Cancelling remaining checks.")
                                    for f in futures:
                                        if f.cancel(): cancelled_count += 1
                                    futures = set()
                                    break 
                        except Exception as exc:
                            logger.error(f'A proxy check generated an exception: {exc}', exc_info=False) 

                    if not futures:
                        break
            logger.info(f"Finished checking. Found {len(good_proxy_results)} potential good proxies. Cancelled {cancelled_count} tasks.")
        
        # ... (Final Processing and Message Construction remains the same) ...
        final_results_display = sorted(good_proxy_results, key=lambda x: x['used']) # Show non-used first
        good_count_final = len([r for r in final_results_display if not r['used']])
        used_count_final = len([r for r in final_results_display if r['used']])
        invalid_format_count = len(invalid_format_proxies)
        checks_attempted = processed_count - cancelled_count
        format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
        prefilter_msg = f" (Skipped {used_count_prefilter} used cache, {bad_count_prefilter} bad cache)." if used_count_prefilter > 0 or bad_count_prefilter > 0 else ""
        cancel_msg = f" Stopped early after finding {good_count_final} usable proxies (checked {checks_attempted})." if cancelled_count > 0 else ""
        if good_count_final > 0 or used_count_final > 0:
            message_prefix = f"✅ Checked {checks_attempted} proxies ({input_count} submitted{format_warning})."
            message_suffix = f" Found {good_count_final} usable proxies ({used_count_final} previously used IPs found).{truncation_warning}{prefilter_msg}{cancel_msg}"
            message = message_prefix + message_suffix
        else:
             message = f"⚠️ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). No new usable proxies found.{truncation_warning}{prefilter_msg}"
        results = final_results_display
        end_time = time.time()
        logger.info(f"Request processing took {end_time - start_time:.2f} seconds.")

    return render_template("index.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings, announcement=announcement)


@app.route("/track-used", methods=["POST"])
@login_required
def track_used():
    # This function remains unchanged
    data = request.get_json(); proxy_line = data.get("proxy") if data else None
    if not proxy_line: return jsonify({"status": "error", "message": "Invalid request data"}), 400
    if not validate_proxy_format(proxy_line): logger.warning(f"Track-used invalid format: {proxy_line}"); return jsonify({"status": "error", "message": "Invalid proxy format"}), 400
    try:
        ip = get_ip_from_proxy(proxy_line)
        if ip:
            if add_used_ip(ip, proxy_line): logger.info(f"Marked used: {proxy_line} (IP: {ip})"); return jsonify({"status": "success"})
            else: logger.error(f"Failed add used IP/Proxy: {proxy_line} (IP: {ip})"); return jsonify({"status": "error", "message": "Failed update"}), 500
        else: logger.warning(f"Could not get IP to mark used: {proxy_line}"); return jsonify({"status": "error", "message": "Could not verify IP"}), 400
    except Exception as e: logger.error(f"Error tracking used proxy '{proxy_line}': {e}", exc_info=True); return jsonify({"status": "error", "message": "Server error"}), 500


# --- Admin Routes (Protected) ---

@app.route("/admin")
@admin_required
def admin():
    """Admin dashboard page."""
    try:
        settings = get_app_settings()
        stats = {
            "total_checks": "N/A (Vercel)", "total_good": "N/A", 
            "max_paste": settings["MAX_PASTE"], 
            "fraud_score_level": settings["FRAUD_SCORE_LEVEL"], 
            "max_workers": settings["MAX_WORKERS"], 
            "scamalytics_api_key": settings["SCAMALYTICS_API_KEY"], 
            "scamalytics_api_url": settings["SCAMALYTICS_API_URL"], 
            "scamalytics_username": settings["SCAMALYTICS_USERNAME"],
            "api_credits_used": settings.get("API_CREDITS_USED", "N/A"), # <-- ADDED
            "api_credits_remaining": settings.get("API_CREDITS_REMAINING", "N/A") # <-- ADDED
        }
        used_ips = get_all_used_ips()
        announcement = settings.get("ANNOUNCEMENT") 
        return render_template( "admin.html", stats=stats, used_ips=used_ips, good_proxies=[], blocked_ips=[], announcement=announcement )
    except Exception as e: 
        logger.error(f"Admin panel error: {e}", exc_info=True)
        flash("Error loading admin panel data.", "danger")
        # Provide defaults even on error
        stats_error = {
            "api_credits_used": "Error", "api_credits_remaining": "Error"
        }
        return render_template("admin.html", stats=stats_error, used_ips=[], good_proxies=[], blocked_ips=[], announcement="")


# --- NEW ROUTE ---
@app.route("/admin/test", methods=["GET", "POST"])
@admin_required
def admin_test():
    """Admin-only strict proxy checker page."""
    try: 
        settings = get_app_settings()
    except Exception as e: 
        logger.critical(f"CRITICAL ERROR getting app settings: {e}", exc_info=True)
        return render_template("error.html", error="Could not load critical settings."), 500
    
    # Use settings from main config
    MAX_PASTE = settings["MAX_PASTE"]
    # We use the *same* fraud score setting, but apply more filters
    FRAUD_SCORE_LEVEL = settings["FRAUD_SCORE_LEVEL"]
    MAX_WORKERS = settings["MAX_WORKERS"]
    API_KEY = settings["SCAMALYTICS_API_KEY"]
    API_URL = settings["SCAMALYTICS_API_URL"]
    API_USER = settings["SCAMALYTICS_USERNAME"]
    
    results = []; message = None
    last_credits = None # To store credit info

    if request.method == "POST":
        start_time = time.time(); proxies_input = []; input_count = 0; truncation_warning = ""
        
        # --- Handle Input (Same as index) ---
        if 'proxyfile' in request.files and request.files['proxyfile'].filename:
            try:
                file = request.files['proxyfile']; all_lines = file.read().decode("utf-8", errors='ignore').strip().splitlines(); input_count = len(all_lines)
                if input_count > MAX_PASTE: truncation_warning = f" Input truncated to first {MAX_PASTE}."; proxies_input = all_lines[:MAX_PASTE]
                else: proxies_input = all_lines
                logger.info(f"[Strict] Received {input_count} via file.")
            except Exception as e: logger.error(f"[Strict] File read error: {e}", exc_info=True); message = "Error reading file."; return render_template("admin_test.html", results=[], message=message, max_paste=MAX_PASTE, settings=settings)
        elif 'proxytext' in request.form and request.form.get("proxytext", "").strip():
            proxytext = request.form.get("proxytext", ""); all_lines = proxytext.strip().splitlines(); input_count = len(all_lines)
            if input_count > MAX_PASTE: truncation_warning = f" Input truncated to first {MAX_PASTE}."; proxies_input = all_lines[:MAX_PASTE]
            else: proxies_input = all_lines
            logger.info(f"[Strict] Received {input_count} via text.")
        else: 
            message = "Please paste proxies or upload file."
            return render_template("admin_test.html", results=[], message=message, max_paste=MAX_PASTE, settings=settings)

        # --- Load Caches (Same as index) ---
        try: used_ips_records = get_all_used_ips(); used_ips_list = {r.get('IP') for r in used_ips_records if r.get('IP')}; used_proxy_cache = {r.get('Proxy') for r in used_ips_records if r.get('Proxy')}; logger.info(f"[Strict] Loaded {len(used_proxy_cache)} used proxies.")
        except Exception as e: logger.error(f"[Strict] Error loading used cache: {e}"); used_ips_list = set(); used_proxy_cache = set(); message = "Warn: Could not load used cache."
        try: bad_proxy_cache = set(get_bad_proxies_list()); logger.info(f"[Strict] Loaded {len(bad_proxy_cache)} bad proxies.")
        except Exception as e: logger.error(f"[Strict] Error loading bad cache: {e}"); bad_proxy_cache = set(); message = (message or "") + " Warn: Could not load bad cache."

        # --- Filter Proxies (Same as index) ---
        proxies_to_check = []; invalid_format_proxies = []; used_count_prefilter = 0; bad_count_prefilter = 0
        unique_proxies_input = set(p.strip() for p in proxies_input if p.strip())
        for proxy in unique_proxies_input:
            if not validate_proxy_format(proxy): invalid_format_proxies.append(proxy); continue
            if proxy in used_proxy_cache: used_count_prefilter += 1; continue
            if proxy in bad_proxy_cache: bad_count_prefilter += 1; continue
            proxies_to_check.append(proxy)
        processed_count = len(proxies_to_check); logger.info(f"[Strict] Prefiltering done: {len(unique_proxies_input)} unique -> {len(invalid_format_proxies)} invalid, {used_count_prefilter} used, {bad_count_prefilter} bad. {processed_count} to check.")

        # --- Execute Checks Concurrently (DIFFERENT) ---
        good_proxy_results = []
        # No early exit for this page, we want to check all of them
        futures = set()

        if proxies_to_check:
            actual_workers = min(MAX_WORKERS, processed_count)
            logger.info(f"[Strict] Starting check for {processed_count} proxies using {actual_workers} workers...")
            with ThreadPoolExecutor(max_workers=actual_workers) as executor:
                for proxy in proxies_to_check:
                    # --- Calls the NEW detailed check function ---
                    futures.add(executor.submit(single_check_proxy_detailed, proxy, FRAUD_SCORE_LEVEL, API_KEY, API_URL, API_USER))
                
                # Process results as they complete
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            # Store credits from the latest completed check
                            if result.get("credits"):
                                last_credits = result.get("credits")
                            
                            # Check if the proxy was good (not None)
                            if result.get("proxy"):
                                result['used'] = result.get('ip') in used_ips_list
                                good_proxy_results.append(result)
                                
                    except Exception as exc:
                        logger.error(f'[Strict] A proxy check generated an exception: {exc}', exc_info=False) 

            logger.info(f"[Strict] Finished checking. Found {len(good_proxy_results)} potential good proxies.")

        # --- Update API Credits ---
        if last_credits:
            try:
                used = last_credits.get("used", "N/A")
                remaining = last_credits.get("remaining", "N/A")
                if update_setting("API_CREDITS_USED", str(used)) and \
                   update_setting("API_CREDITS_REMAINING", str(remaining)):
                    logger.info(f"Updated API credits: Used={used}, Remaining={remaining}")
                    message = (message or "") + f" (API Credits Updated: {remaining} left)"
                else:
                    logger.error("Failed to update API credits in Google Sheet.")
                    message = (message or "") + " (Failed to update API credits)"
            except Exception as e:
                logger.error(f"Error updating API credits: {e}")

        # --- Final Processing and Message Construction (Simplified) ---
        final_results_display = sorted(good_proxy_results, key=lambda x: x['used']) 
        good_count_final = len([r for r in final_results_display if not r['used']])
        used_count_final = len([r for r in final_results_display if r['used']])
        invalid_format_count = len(invalid_format_proxies)
        checks_attempted = processed_count # We checked all

        format_warning = f" ({invalid_format_count} invalid format)" if invalid_format_count > 0 else ""
        prefilter_msg = f" (Skipped {used_count_prefilter} used cache, {bad_count_prefilter} bad cache)." if used_count_prefilter > 0 or bad_count_prefilter > 0 else ""

        if good_count_final > 0 or used_count_final > 0:
            message_prefix = f"✅ Checked {checks_attempted} proxies ({input_count} submitted{format_warning})."
            message_suffix = f" Found {good_count_final} usable proxies ({used_count_final} previously used IPs found).{truncation_warning}{prefilter_msg}"
            message = message_prefix + message_suffix
        else:
             message = f"⚠️ Checked {checks_attempted} proxies ({input_count} submitted{format_warning}). No new usable proxies found.{truncation_warning}{prefilter_msg}"

        results = final_results_display
        end_time = time.time()
        logger.info(f"[Strict] Request processing took {end_time - start_time:.2f} seconds.")

    # Always pass settings to the template
    return render_template("admin_test.html", results=results, message=message, max_paste=MAX_PASTE, settings=settings)
# --- END NEW ROUTE ---


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    # This function remains unchanged
    # ... (all existing code for admin_settings) ...
    try: current_settings = get_app_settings()
    except Exception as e: logger.critical(f"CRITICAL ERROR getting settings in ADMIN: {e}", exc_info=True); flash("Could not load settings.", "danger"); return render_template("admin_settings.html", settings=DEFAULT_SETTINGS, message=None)
    message = None # Use flash for user feedback
    if request.method == "POST":
        try: max_paste = int(request.form.get("max_paste", DEFAULT_SETTINGS["MAX_PASTE"]))
        except ValueError: max_paste = DEFAULT_SETTINGS["MAX_PASTE"]
        try: fraud_score_level = int(request.form.get("fraud_score_level", DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]))
        except ValueError: fraud_score_level = DEFAULT_SETTINGS["FRAUD_SCORE_LEVEL"]
        try: max_workers = int(request.form.get("max_workers", DEFAULT_SETTINGS["MAX_WORKERS"]))
        except ValueError: max_workers = DEFAULT_SETTINGS["MAX_WORKERS"]
        scamalytics_api_key = request.form.get("scamalytics_api_key", "").strip()
        scamalytics_api_url = request.form.get("scamalytics_api_url", "").strip()
        scamalytics_username = request.form.get("scamalytics_username", "").strip()
        error_msg = None
        if not (5 <= max_paste <= 100): error_msg = "Max proxies must be 5-100"
        elif not (0 <= fraud_score_level <= 100): error_msg = "Fraud score must be 0-100"
        elif not (1 <= max_workers <= 100): error_msg = "Max workers must be 1-100"
        elif len(scamalytics_api_key) < 5: error_msg = "API Key too short"
        elif not scamalytics_api_url.startswith("http"): error_msg = "API URL invalid"
        elif len(scamalytics_username) < 3: error_msg = "Username too short"
        if not error_msg:
            logger.info("Attempting settings update..."); success = True
            if not update_setting("MAX_PASTE", str(max_paste)): success = False
            if not update_setting("FRAUD_SCORE_LEVEL", str(fraud_score_level)): success = False
            if not update_setting("MAX_WORKERS", str(max_workers)): success = False
            if not update_setting("SCAMALYTICS_API_KEY", scamalytics_api_key): success = False
            if not update_setting("SCAMALYTICS_API_URL", scamalytics_api_url): success = False
            if not update_setting("SCAMALYTICS_USERNAME", scamalytics_username): success = False
            if success: logger.info("Settings updated."); flash("Settings updated successfully", "success"); current_settings = get_app_settings() # Refresh
            else: logger.error("Failed GSheet update."); error_msg = "Error saving settings."
        if error_msg:
             flash(error_msg, "danger")
             # Keep submitted values on error
             current_settings = { "MAX_PASTE": max_paste, "FRAUD_SCORE_LEVEL": fraud_score_level, "MAX_WORKERS": max_workers, "SCAMALYTICS_API_KEY": scamalytics_api_key, "SCAMALYTICS_API_URL": scamalytics_api_url, "SCAMALYTICS_USERNAME": scamalytics_username }
    return render_template("admin_settings.html", settings=current_settings, message=None)


# ... (admin_announcement, delete_used_ip_route, send_static, errorhandlers all remain the same) ...

# --- Main Execution ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)