"""
Extract emails from US domains via Common Crawl CDX index API.
No WET file downloads needed — uses HTTP range requests.
"""
import re
import json
import requests
import gzip
from io import BytesIO
from urllib.parse import urlencode
import time

EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
COMMON_CRAWL_BUCKET = "https://data.commoncrawl.org"

def query_index(domain, crawl="CC-MAIN-2025-06", pages=5):
    """Query Common Crawl CDX index for a domain."""
    urls = []
    for page in range(pages):
        params = {
            'url': f'*.{domain}/*',
            'output': 'json',
            'fl': 'url,filename,offset,length',
            'limit': '10000',
            'page': str(page),
        }
        resp = requests.get(
            f'https://index.commoncrawl.org/{crawl}-index',
            params=params,
            timeout=60
        )
        if resp.status_code != 200:
            break
        lines = resp.text.strip().split('\n')
        for line in lines:
            if not line:
                continue
            data = json.loads(line)
            urls.append(data)
        if len(lines) < 10000:
            break
        time.sleep(0.5)
    return urls

def fetch_text(filename, offset, length):
    """Fetch raw text from a WARC/WET file using HTTP range request."""
    url = f"{COMMON_CRAWL_BUCKET}/{filename}"
    headers = {'Range': f'bytes={offset}-{offset + length - 1}'}
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 206:
        try:
            return gzip.decompress(resp.content).decode('utf-8', errors='replace')
        except:
            return resp.content.decode('utf-8', errors='replace')
    return None

def extract_emails_from_index(domain, crawl="CC-MAIN-2025-06", max_results=50000):
    """Main function: query index + fetch text + extract emails."""
    emails = set()
    results = query_index(domain, crawl)
    print(f"Found {len(results)} pages for {domain}")
    
    for i, r in enumerate(results):
        text = fetch_text(r['filename'], int(r['offset']), int(r['length']))
        if text:
            found = EMAIL_REGEX.findall(text)
            for e in found:
                if e.split('@')[1].endswith('.us') or True:  # filter as needed
                    emails.add(e.lower())
        if len(emails) >= max_results:
            break
        if i % 10 == 0:
            print(f"  processed {i+1}/{len(results)} — {len(emails)} emails so far")
    
    return emails

# --- For bulk email harvesting: query US-centric domains ---
US_DOMAINS = [
    "craigslist.org", "yelp.com", "linkedin.com", 
    "facebook.com", "twitter.com", "instagram.com",
    "github.com", "stackoverflow.com", "reddit.com",
    "amazon.com", "ebay.com", "etsy.com",
    # plus use the Alexa top 1000 US domains list
]

if __name__ == "__main__":
    all_emails = set()
    for domain in US_DOMAINS[:3]:  # start small
        print(f"Querying {domain}...")
        emails = extract_emails_from_index(domain, "CC-MAIN-2026-10", 5000)
        all_emails.update(emails)
        print(f"  total: {len(all_emails)}")
    
    with open("emails.txt", "w") as f:
        for e in sorted(all_emails):
            f.write(e + "\n")
    print(f"Done — {len(all_emails)} emails saved to emails.txt")