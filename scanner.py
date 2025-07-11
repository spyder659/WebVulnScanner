import os
import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urljoin

# Ensure logs folder exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# Logging setup
logging.basicConfig(filename="logs/scan_log.txt", level=logging.INFO, format="%(message)s")

# Test payloads for XSS and SQLi
xss_test_script = "<script>alert('XSS')</script>"
sqli_test_payload = "' OR '1'='1"

# Scan input forms for vulnerabilities
def test_form_vulnerabilities(url):
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")
        forms = soup.find_all("form")

        for i, form in enumerate(forms, 1):
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            data = {}

            for inp in inputs:
                name = inp.get("name")
                if name:
                    data[name] = xss_test_script

            target_url = urljoin(url, action)
            if method == "post":
                response = requests.post(target_url, data=data)
            else:
                response = requests.get(target_url, params=data)

            if xss_test_script in response.text:
                logging.info(f"[!] XSS Vulnerability detected in form #{i} at {target_url}")
            else:
                logging.info(f"[-] XSS test clean in form #{i} at {target_url}")

            # SQLi test (basic)
            for inp in inputs:
                name = inp.get("name")
                if name:
                    data[name] = sqli_test_payload

            if method == "post":
                response = requests.post(target_url, data=data)
            else:
                response = requests.get(target_url, params=data)

            if "sql" in response.text.lower() or "error" in response.text.lower():
                logging.info(f"[!] SQLi Suspected in form #{i} at {target_url}")
            else:
                logging.info(f"[-] SQLi test clean in form #{i} at {target_url}")

    except Exception as e:
        logging.error(f"[!] Error testing form vulnerabilities: {e}")

# Crawl all links
def find_links(url):
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")
        anchors = soup.find_all("a")
        links = set()
        for a in anchors:
            href = a.get("href")
            if href and not href.startswith("#"):
                full_url = urljoin(url, href)
                links.add(full_url)
        logging.info(f"[+] Found {len(links)} links on {url}")
        for link in links:
            logging.info(f"    Link: {link}")
    except Exception as e:
        logging.error(f"[!] Error fetching links: {e}")

# Main function
def main():
    url = input("Enter URL to scan: ").strip()
    if not url.startswith("http"):
        url = "http://" + url
    logging.info(f"\n--- Starting Scan for: {url} ---")
    find_links(url)
    test_form_vulnerabilities(url)
    logging.info(f"--- Scan Complete for: {url} ---\n")
    print("Scan complete. Check logs/scan_log.txt for results.")

if __name__ == "__main__":
    main()
