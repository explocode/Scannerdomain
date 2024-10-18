import requests
import logging
import re

class Colors:
    INFO = '\033[94m'    
    WARNING = '\033[93m'  
    CRITICAL = '\033[91m' 
    RESET = '\033[0m'     

logging.basicConfig(filename='vulnerability_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  
        r'localhost|'  
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  
        r'?[A-F0-9]*:[A-F0-9:]+?)'  
        r'(?::\d+)?'  
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def check_sql_injection(url):
    payloads = ["' OR '1'='1", '" OR "1"="1', "' OR 'a'='a", '" OR "a"="a']
    for payload in payloads:
        full_url = f"{url}?test={payload}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            response = requests.get(full_url, headers=headers)
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                return True
        except requests.exceptions.RequestException as e:
            print(f"{Colors.CRITICAL}[ERROR] Error checking SQL injection: {e}{Colors.RESET}")
            logging.error(f"Error checking SQL injection: {e}")
    return False

def check_xss(url):
    payloads = ["<script>alert('XSS')</script>", "'; alert('XSS'); //", "<img src=x onerror=alert('XSS') />"]
    for payload in payloads:
        full_url = f"{url}?test={payload}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            response = requests.get(full_url, headers=headers)
            if payload in response.text:
                return True
        except requests.exceptions.RequestException as e:
            print(f"{Colors.CRITICAL}[ERROR] Error checking XSS: {e}{Colors.RESET}")
            logging.error(f"Error checking XSS: {e}")
    return False

def check_csrf(url):
    csrf_token = 'csrf_token'
    full_url = f"{url}/form"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(full_url, headers=headers)
        if csrf_token not in response.text:
            return True
    except requests.exceptions.RequestException as e:
        print(f"{Colors.CRITICAL}[ERROR] Error checking CSRF: {e}{Colors.RESET}")
        logging.error(f"Error checking CSRF: {e}")
    return False

def check_security_misconfiguration(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers)
        return response.status_code != 200
    except requests.exceptions.RequestException as e:
        print(f"{Colors.CRITICAL}[ERROR] Error checking security misconfiguration: {e}{Colors.RESET}")
        logging.error(f"Error checking security misconfiguration: {e}")
        return True

def check_sensitive_data_exposure(url):
    keywords = ["password", "secret", "apikey", "token", "credentials"]
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers)
        for keyword in keywords:
            if keyword in response.text:
                return True
    except requests.exceptions.RequestException as e:
        print(f"{Colors.CRITICAL}[ERROR] Error checking sensitive data exposure: {e}{Colors.RESET}")
        logging.error(f"Error checking sensitive data exposure: {e}")
    return False

def check_open_redirect(url):
    payload = "http://malicious.com"
    full_url = f"{url}?redirect={payload}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    try:
        response = requests.get(full_url, headers=headers)
        if response.url.startswith("http://malicious.com"):
            return True
    except requests.exceptions.RequestException as e:
        print(f"{Colors.CRITICAL}[ERROR] Error checking open redirect: {e}{Colors.RESET}")
        logging.error(f"Error checking open redirect: {e}")
    return False

def run_scanner(domain):
    print(f"{Colors.INFO}-----------\n[INFO] Running vulnerability checks on {domain}\n-----------{Colors.RESET}")
    
    if check_sql_injection(domain):
        print(f"{Colors.WARNING}[WARNING] Possible SQL Injection vulnerability detected.{Colors.RESET}")
        logging.warning(f"Possible SQL Injection vulnerability detected on {domain}.")
    else:
        print(f"{Colors.INFO}[INFO] No SQL Injection vulnerability detected.{Colors.RESET}")
    
    if check_xss(domain):
        print(f"{Colors.WARNING}[WARNING] Possible XSS vulnerability detected.{Colors.RESET}")
        logging.warning(f"Possible XSS vulnerability detected on {domain}.")
    else:
        print(f"{Colors.INFO}[INFO] No XSS vulnerability detected.{Colors.RESET}")
    
    if check_csrf(domain):
        print(f"{Colors.WARNING}[WARNING] Possible CSRF vulnerability detected.{Colors.RESET}")
        logging.warning(f"Possible CSRF vulnerability detected on {domain}.")
    else:
        print(f"{Colors.INFO}[INFO] No CSRF vulnerability detected.{Colors.RESET}")
    
    if check_security_misconfiguration(domain):
        print(f"{Colors.CRITICAL}[CRITICAL] Possible security misconfiguration detected.{Colors.RESET}")
        logging.critical(f"Possible security misconfiguration detected on {domain}.")
    else:
        print(f"{Colors.INFO}[INFO] No security misconfiguration detected.{Colors.RESET}")
    
    if check_sensitive_data_exposure(domain):
        print(f"{Colors.CRITICAL}[CRITICAL] Sensitive data exposure detected.{Colors.RESET}")
        logging.critical(f"Sensitive data exposure detected on {domain}.")
    else:
        print(f"{Colors.INFO}[INFO] No sensitive data exposure detected.{Colors.RESET}")
    
    if check_open_redirect(domain):
        print(f"{Colors.WARNING}[WARNING] Possible Open Redirect vulnerability detected.{Colors.RESET}")
        logging.warning(f"Possible Open Redirect vulnerability detected on {domain}.")
    else:
        print(f"{Colors.INFO}[INFO] No Open Redirect vulnerability detected.{Colors.RESET}")

if __name__ == "__main__":
    user_input = input("Please enter your domain (without http:// or https://) [default: www.cbi.ir]: ")
    domain = user_input.strip() or "www.cbi.ir"
    
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "https://" + domain

    if not is_valid_url(domain):
        print(f"{Colors.CRITICAL}[ERROR] Invalid URL format: {domain}{Colors.RESET}")
    else:
        run_scanner(domain)
