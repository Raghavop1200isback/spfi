#!/usr/bin/env python3
import requests
import argparse

def check_spf(domain):
    url = 'https://www.kitterman.com/spf/getspf3.py'

    headers = {
        'Host': 'www.kitterman.com',
        'Connection': 'keep-alive',
        'Cache-Control': 'max-age=0',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'https://www.kitterman.com',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-User': '?1',
        'Sec-Fetch-Dest': 'document',
        'Referer': 'https://www.kitterman.com/spf/validate.html?',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Language': 'en-IN,en-US;q=0.9,en;q=0.8,hi;q=0.7,pt;q=0.6',
    }

    data = {
        'serial': 'fred12',
        'domain': domain
    }

    response = requests.post(url, headers=headers, data=data)

    if "No valid SPF record found." in response.text:
        with open("spf_vuln.txt", "a") as f:
            f.write(domain + '\n')
    else:
        with open("spf.txt", "a") as f:
            f.write(response.text + '\n')

def main():
    parser = argparse.ArgumentParser(description="Check SPF records for domains.")
    parser.add_argument("-l", "--list", help="File containing list of domains.")
    args = parser.parse_args()

    if args.list:
        with open(args.list, "r") as f:
            domains = f.readlines()
        for domain in domains:
            domain = domain.strip()
            check_spf(domain)
        print("SPF check completed.")
    else:
        print("Please provide a file containing a list of domains using the -l option.")

if __name__ == "__main__":
    main()
