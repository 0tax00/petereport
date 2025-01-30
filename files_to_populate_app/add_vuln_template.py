import requests
import json
import colorama
from colorama import Fore, Style

# Initialize colorama (especially on Windows to enable ANSI escape codes)
colorama.init(autoreset=True)

# ==== GENERAL CONFIGURATION ====
BASE_URL = "https://127.0.0.1"
LOGIN_URL = f"{BASE_URL}/pt/accounts/login/"
ADD_FINDING_URL = f"{BASE_URL}/pt/template/add/"

USERNAME = "admin"
PASSWORD = "P3t3r3p0rt"
TEMPLATE_JSON = "add_vuln_template.json"

# Disable SSL verification if you're using a self-signed certificate locally
# (Not recommended in production)
VERIFY_SSL = False


def get_initial_csrf_token(session, url):
    """
    Performs a GET request to extract the 'csrftoken' cookie.
    """
    response = session.get(url, verify=VERIFY_SSL)
    response.raise_for_status()
    token = session.cookies.get("csrftoken", "")
    if not token:
        raise ValueError("Could not retrieve initial csrftoken.")
    return token


def login_django(session, login_url, username, password):
    """
    Logs into Django by sending username/password + CSRF token.
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

    response = session.post(login_url, data=payload, headers=headers, verify=VERIFY_SSL)
    response.raise_for_status()

    # Check if login was successful
    if "Por favor, entre com seu usuário e senha corretos" in response.text:
        raise ValueError("Login failed. Check your credentials.")


def send_finding_multipart(session, add_finding_url, vuln_data):
    """
    Sends ONE vulnerability via multipart/form-data to /pt/template/add/.
    'vuln_data' should be a dictionary with the required fields.
    """

    # 1) Get the current CSRF token
    csrf_token = session.cookies.get("csrftoken", "")
    if not csrf_token:
        raise ValueError("CSRF token not found in session before sending form data.")

    # 2) Build form data (matching your original request fields)
    form_data = {
        "csrfmiddlewaretoken": csrf_token,
        "title": vuln_data.get("title", ""),
        "severity": vuln_data.get("severity", ""),
        "cvss_vector": vuln_data.get("cvss_vector", ""),
        "cvss_score": vuln_data.get("cvss_score", ""),
        "cwe": vuln_data.get("cwe", ""),
        "owasp": vuln_data.get("owasp", ""),
        "description": vuln_data.get("description", ""),
        "location": vuln_data.get("location", ""),
        "impact": vuln_data.get("impact", ""),
        "business_impact": vuln_data.get("business_impact", ""),
        "recommendation": vuln_data.get("recommendation", ""),
        "references": vuln_data.get("references", ""),
        "_finish": "Save"
    }

    # 3) Build the list of empty "markdown-image-upload" fields
    files_list = [
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
        ("markdown-image-upload", ("", b"", "application/octet-stream")),
    ]

    # 4) Headers
    headers = {
        "Referer": add_finding_url
    }

    # 5) Send POST as multipart/form-data
    resp = session.post(
        add_finding_url,
        data=form_data,
        files=files_list,
        headers=headers,
        verify=VERIFY_SSL
    )
    return resp


def main():
    # Disable self-signed SSL warnings (optional)
    requests.packages.urllib3.disable_warnings()

    with requests.Session() as session:
        # Step 1: Login
        print(f"{Fore.CYAN}[+] Attempting to log in...{Style.RESET_ALL}")
        login_django(session, LOGIN_URL, USERNAME, PASSWORD)
        print(f"{Fore.GREEN}[+] Login successful.{Style.RESET_ALL}")

        # Step 2: Read template.json
        print(f"{Fore.CYAN}[+] Reading vulnerabilities from: {TEMPLATE_JSON}{Style.RESET_ALL}")
        with open(TEMPLATE_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)

        # If it's a single dictionary, make it a list of one item
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            raise ValueError(f"{TEMPLATE_JSON} must contain an object or a list of objects.")

        # Step 3: For each vulnerability in the list, send it
        for i, vuln_data in enumerate(data, start=1):
            title = vuln_data.get('title', 'Untitled')
            print(f"{Fore.BLUE}[+] Sending Vulnerability #{i} - Title: {title}{Style.RESET_ALL}")
            response = send_finding_multipart(session, ADD_FINDING_URL, vuln_data)

            if response.ok:
                print(f"{Fore.GREEN}    => SUCCESS! (status code {response.status_code}){Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}    => ERROR! (status code {response.status_code}){Style.RESET_ALL}")
                print(f"{Fore.RED}    => Server response: {response.text}{Style.RESET_ALL}")

    print(f"{Fore.MAGENTA}[+] Process completed!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
