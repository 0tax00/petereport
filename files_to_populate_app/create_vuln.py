import requests
import json
import colorama
from colorama import Fore, Style

# Initialize colorama (especially important on Windows)
colorama.init(autoreset=True)

# =======================
# CONFIGURATION
# =======================
BASE_URL = "https://127.0.0.1"

LOGIN_URL = f"{BASE_URL}/pt/accounts/login/"
ADD_PRODUCT_URL = f"{BASE_URL}/pt/product/add/"
ADD_REPORT_URL = f"{BASE_URL}/pt/report/add/"
ADD_FINDING_BASE = f"{BASE_URL}/pt/finding/add"  # We'll append /<report_id>

USERNAME = "admin"
PASSWORD = "P3t3r3p0rt"

VULN_JSON = "add_vuln.json"

# If using a self-signed certificate locally,
# you can disable SSL verification (not recommended in production).
VERIFY_SSL = False

def banner():
    """
    Just a fancy ASCII banner for style.
    """
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print("********************************************")
    print("*             Automatic Vuln ADD           *")
    print("********************************************")
    print(f"{Style.RESET_ALL}")

def get_initial_csrf_token(session, url):
    """
    Performs a GET to the page to extract the 'csrftoken' cookie.
    """
    response = session.get(url, verify=VERIFY_SSL)
    response.raise_for_status()
    token = session.cookies.get("csrftoken", "")
    if not token:
        raise ValueError("Could not retrieve initial csrftoken.")
    return token

def login_django(session, login_url, username, password):
    """
    Logs in to Django by sending username/password + CSRF token.
    """
    csrf_token = get_initial_csrf_token(session, login_url)

    payload = {
        "csrfmiddlewaretoken": csrf_token,
        "username": username,
        "password": password
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": login_url,
    }

    r = session.post(login_url, data=payload, headers=headers, verify=VERIFY_SSL)
    r.raise_for_status()

    if "Por favor, entre com seu usuário e senha corretos" in r.text:
        raise ValueError("Login failed. Check your credentials.")

def create_product(session, name, customer, description):
    """
    Creates a product at /pt/product/add/ via multipart/form-data.
    """
    csrf_token = session.cookies.get("csrftoken", "")
    if not csrf_token:
        raise ValueError("No CSRF token found before creating product.")

    form_data = {
        "csrfmiddlewaretoken": csrf_token,
        "name": name,
        "customer": customer,
        "description": description
    }

    # Single "markdown-image-upload" field (empty)
    files_list = [
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
    ]

    headers = {
        "Referer": ADD_PRODUCT_URL
    }

    resp = session.post(
        ADD_PRODUCT_URL,
        data=form_data,
        files=files_list,
        headers=headers,
        verify=VERIFY_SSL
    )
    resp.raise_for_status()
    return resp

def create_report(session, product_id, report_id, title,
                  exec_summary, scope, outofscope,
                  methodology, recommendation, narrative,
                  report_date, audit):
    """
    Creates a report at /pt/report/add/ via multipart/form-data.
    """
    csrf_token = session.cookies.get("csrftoken", "")
    if not csrf_token:
        raise ValueError("No CSRF token found before creating report.")

    form_data = {
        "csrfmiddlewaretoken": csrf_token,
        "product": product_id,
        "report_id": report_id,
        "title": title,
        "executive_summary": exec_summary,
        "scope": scope,
        "outofscope": outofscope,
        "methodology": methodology,
        "recommendation": recommendation,
        "narrative": narrative,
        "report_date": report_date,
        "audit": audit
    }

    # 5 empty "markdown-image-upload" fields
    files_list = [
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
    ]

    headers = {
        "Referer": ADD_REPORT_URL
    }

    resp = session.post(
        ADD_REPORT_URL,
        data=form_data,
        files=files_list,
        headers=headers,
        verify=VERIFY_SSL
    )
    resp.raise_for_status()
    return resp

def create_finding(session, report_id, vuln_data):
    """
    Creates ONE vulnerability at /pt/finding/add/<report_id> via multipart/form-data.
    'vuln_data' must be a dict with all required fields.
    """
    csrf_token = session.cookies.get("csrftoken", "")
    if not csrf_token:
        raise ValueError("No CSRF token found before creating finding.")

    add_finding_url = f"{ADD_FINDING_BASE}/{report_id}"

    form_data = {
        "csrfmiddlewaretoken": csrf_token,
        "title": vuln_data.get("title", ""),
        "status": vuln_data.get("status", ""),
        "severity": vuln_data.get("severity", ""),
        "cvss_vector": vuln_data.get("cvss_vector", ""),
        "cvss_score": vuln_data.get("cvss_score", ""),
        "cwe": vuln_data.get("cwe", ""),
        "owasp": vuln_data.get("owasp", ""),
        "description": vuln_data.get("description", ""),
        "location": vuln_data.get("location", ""),
        "poc": vuln_data.get("poc", ""),
        "impact": vuln_data.get("impact", ""),
        "business_impact": vuln_data.get("business_impact", ""),
        "recommendation": vuln_data.get("recommendation", ""),
        "references": vuln_data.get("references", ""),
        "_finish": "Save"
    }

    # 6 empty "markdown-image-upload" fields
    files_list = [
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
    ]

    headers = {
        "Referer": add_finding_url
    }

    resp = session.post(
        add_finding_url,
        data=form_data,
        files=files_list,
        headers=headers,
        verify=VERIFY_SSL
    )
    resp.raise_for_status()
    return resp

def main():
    # Disable SSL self-signed warnings (optional)
    requests.packages.urllib3.disable_warnings()

    banner()

    with requests.Session() as session:
        # 1) LOGIN
        print(f"{Fore.BLUE}[+] Logging into Django...{Style.RESET_ALL}")
        login_django(session, LOGIN_URL, USERNAME, PASSWORD)
        print(f"{Fore.GREEN}[+] Login successful.{Style.RESET_ALL}")

        # 2) CREATE PRODUCT
        print(f"{Fore.BLUE}[+] Creating Product...{Style.RESET_ALL}")
        resp_product = create_product(
            session,
            name="test-product",
            customer="1",
            description="Automatically created by script"
        )
        print(f"{Fore.GREEN}    => Product created! (Status code: {resp_product.status_code}){Style.RESET_ALL}")

        # For demonstration, we assume the new product ID is 2 (or parse if needed)
        product_id = 1

        # 3) CREATE REPORT
        print(f"{Fore.BLUE}[+] Creating Report...{Style.RESET_ALL}")
        resp_report = create_report(
            session,
            product_id=product_id,  # '2'
            report_id="PEN-DOC-202501301019",
            title="Test Report",
            exec_summary="Automatically created by script",
            scope="Automatic Scope",
            outofscope="Automatic Out of Scope",
            methodology="Automatic Methodology",
            recommendation="Automatic Recommendation",
            narrative="Automatic Narrative",
            report_date="2025-01-30",
            audit="2025-01-30 - 2025-01-30"
        )
        print(f"{Fore.GREEN}    => Report created! (Status code: {resp_report.status_code}){Style.RESET_ALL}")

        # For demonstration, we assume the new report ID is 1 (or parse if needed)
        report_id = 1

        # 4) CREATE ONE OR MULTIPLE VULNERABILITIES
        print(f"{Fore.BLUE}[+] Reading vulnerability template: {VULN_JSON}{Style.RESET_ALL}")
        with open(VULN_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            data = [data]  # Single object -> list of one
        elif not isinstance(data, list):
            raise ValueError(f"Invalid format in {VULN_JSON}. Must be a dict or list.")

        for i, vuln_data in enumerate(data, start=1):
            print(f"{Fore.BLUE}[+] Creating Vulnerability #{i} for Report ID = {report_id}{Style.RESET_ALL}")
            try:
                resp_finding = create_finding(session, report_id, vuln_data)
                print(f"{Fore.GREEN}    => Vulnerability #{i} created! (Status code {resp_finding.status_code}){Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}    => ERROR creating Vulnerability #{i}: {e}{Style.RESET_ALL}")
                # Decide if you want to break or continue with the next vulnerability.

        print(f"{Fore.MAGENTA}[+] All done!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
