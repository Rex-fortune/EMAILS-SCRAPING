#!/usr/bin/env python3
"""
US-email_extractor.py
Targets specific US-heavy domains via Common Crawl CDX Index API,
extracts only high-quality, US-relevant email addresses.

Usage:
    python3 us_email_extractor.py --target 200000 --output us_emails.txt
    python3 us_email_extractor.py --target 50000 --output emails.txt --domains us_edu_commercial.csv
"""

import requests
import gzip
import re
import json
import sys
import os
import time
import random
import argparse
from io import BytesIO
from urllib.parse import urlparse, urldefrag
from collections import defaultdict
from email.utils import parseaddr
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# === CONFIGURATION ===

CC_BASE = "https://data.commoncrawl.org/"
INDEX_API = "https://index.commoncrawl.org/CC-MAIN-2026-17-index"
MAX_WORKERS = 20  # parallel fetch threads

# US-heavy TLDs we want to include
US_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'us', 'io', 'co',
    'me', 'ly', 'app', 'dev', 'info', 'biz',
}

# These top-level + second-level combos are non-US
COUNTRY_BLOCK_TLDS = {
    # Russia/CIS
    'ru', 'su', 'by', 'kz', 'ua', 'uz', 'az', 'am', 'kg', 'tj', 'tm',
    # Japan
    'jp', 'or.jp', 'co.jp', 'ne.jp', 'ac.jp', 'go.jp', 'gr.jp',
    # China
    'cn', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    # Hungary
    'hu', '.hu',
    # Italy
    'it',
    # Poland
    'pl', 'com.pl',
    # Germany
    'de',
    # France
    'fr',
    # Spain
    'es',
    # Brazil
    'br', 'com.br',
    # India
    'in', 'co.in',
    # Netherlands
    'nl',
    # Others
    'cz', 'sk', 'ro', 'bg', 'rs', 'hr', 'si', 'lt', 'lv', 'ee',
    'uk', 'co.uk', 'ac.uk', 'org.uk', 'gov.uk',
    'au', 'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'nz', 'co.nz',
    'za', 'co.za',
    'ar', 'cl', 'co', 'mx', 'pe', 
    'kr', 'co.kr', 'or.kr',
    'tw', 'com.tw', 'edu.tw',
    'hk', 'com.hk',
    'sg', 'com.sg',
    'my', 'com.my',
    'ph', 'com.ph',
    'th', 'co.th',
    'id', 'co.id',
    'vn', 'com.vn',
    'eg', 'sa', 'ae', 'il', 'ir', 'pk', 'bd',
    'be', 'ch', 'at', 'se', 'no', 'dk', 'fi', 'pt', 'gr', 'ie',
}

# Free/temp/throwaway email domains (mostly non-US or low quality)
BANNED_DOMAINS = {
    'mail.ru', 'yandex.ru', 'yandex.com', 'rambler.ru', 'list.ru',
    'bk.ru', 'inbox.ru', 'freemail.hu', 'chello.hu', 't-online.de',
    'web.de', 'gmx.de', 'gmx.net', 'freenet.de', 'tiscali.it',
    'libero.it', 'virgilio.it', 'alice.it', 'tin.it',
    'seznam.cz', 'centrum.cz', 'atlas.cz', 'o2.pl',
    'wp.pl', 'interia.pl', 'onet.pl', 'poczta.onet.pl',
    'ukr.net', 'meta.ua', 'i.ua', 'bigmir.net',
    '163.com', '126.com', 'qq.com', 'sina.com', 'sina.cn',
    'sohu.com', 'tom.com', '21cn.com', 'china.com',
    'hanmail.net', 'nate.com', 'daum.net',
    'naver.com', 'yahoo.co.jp', 'yahoo.co.uk',
    'aol.com', 'hotmail.co.uk', 'hotmail.fr', 'hotmail.de',
    'orange.fr', 'wanadoo.fr', 'free.fr',
    'laposte.net', 'club-internet.fr',
    'tut.by', 'tut.ee', 'mail.ee',
    'protonmail.com', 'proton.me', 'protonmail.ch',
    'temp-mail.org', 'guerrillamail.com', 'mailinator.com',
    '10minutemail.com', 'trashmail.com', 'sharklasers.com',
    'yopmail.com', 'throwaway.email', 'tempmail.com',
    'cock.li', 'riseup.net',
    'dispostable.com', 'mailnator.com',
}

# === DOMAIN TARGET LIST ===
# US-heavy domains known to have high volumes of content and contact info
# These are from Common Crawl's top-500 + curated US domains
DEFAULT_TARGET_DOMAINS = """
# US Universities (.edu - excellent source of US emails)
harvard.edu,mit.edu,stanford.edu,berkeley.edu,yale.edu,columbia.edu,
cornell.edu,princeton.edu,upenn.edu,uchicago.edu,ucla.edu,
michigan.edu,washington.edu,utexas.edu,illinois.edu,wisc.edu,
nyu.edu,duke.edu,northwestern.edu,jhu.edu,gatech.edu,
cmu.edu,purdue.edu,osu.edu,umn.edu,tamu.edu,
msu.edu,psu.edu,uf.edu,usc.edu,asu.edu,
ncsu.edu,vt.edu,uiowa.edu,iu.edu,ku.edu,
uky.edu,lsu.edu,ou.edu,okstate.edu,clemson.edu,
auburn.edu,fsu.edu,ufl.edu,gmu.edu,

# US Government (.gov)
usa.gov,whitehouse.gov,state.gov,defense.gov,justice.gov,
commerce.gov,treasury.gov,energy.gov,ed.gov,nih.gov,
cdc.gov,fda.gov,usda.gov,nsf.gov,nasa.gov,
va.gov,dhs.gov,fbi.gov,cia.gov,epa.gov,
loc.gov,archives.gov,noaa.gov,usgs.gov,census.gov,
irs.gov,ssa.gov,hhs.gov,dol.gov,

# Major US Commercial Sites
linkedin.com,facebook.com,twitter.com,instagram.com,
yelp.com,craigslist.org,angieslist.com,bbb.org,
indeed.com,glassdoor.com,monster.com,careerbuilder.com,
zillow.com,realtor.com,redfin.com,apartments.com,
amazon.com,walmart.com,target.com,bestbuy.com,home depot.com,
lowes.com,costco.com,starbucks.com,mcdonalds.com,
chase.com,bankofamerica.com,wellsfargo.com,citi.com,
capitalone.com,americanexpress.com,discover.com,
united.com,delta.com,americanairlines.com,southwest.com,
marriott.com,hilton.com,hyatt.com,ihg.com,
att.com,verizon.com,t-mobile.com,sprint.com,
comcast.net,cox.net,spectrum.com,
"""

# === EMAIL VALIDATION ===

# Pre-compiled regex for local-part validation
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Machine-generated local part patterns
MACHINE_PATTERNS = [
    re.compile(r'^\d{8,}$'),                    # all digits, 8+ long (timestamps)
    re.compile(r'^\d{12,}$'),                   # epoch timestamps (13+ digits)
    re.compile(r'^[a-f0-9]{8,}$', re.I),        # hex-like (commit hashes)
    re.compile(r'^\d{4,}-\d{2,}-\d{2,}'),       # date pattern at start
    re.compile(r'^\d{5,}\.\d+'),                # number.number pattern (bounces)
    re.compile(r'(?:^|[.-_])\d{10,}'),          # any 10+ digit sequence
    re.compile(r'^(test|demo|admin|info|noreply|no-reply|donotreply|postmaster|webmaster|mailer-daemon|mdaemon|root|daemon|abuse|support|help|contact|feedback|notifications?|newsletter|alert|system|robot|spam|bounce|return)-?', re.I),
    re.compile(r'^(auto)mated?-?', re.I),
    re.compile(r'^\d{4,}[a-zA-Z]+'),            # starts with digits then letters (batch handles)
    re.compile(r'^[a-zA-Z]+\d{6,}$'),           # letters then 6+ digits
    re.compile(r'^\d+[a-zA-Z]+\d+$'),           # digits letters digits
    re.compile(r'[\d]{2,}x[\d]{2,}'),           # resolution patterns 1920x1080
    re.compile(r'^[_@]+'),                      # starts with special chars
    re.compile(r'[_@]+$'),                      # ends with special chars
    re.compile(r'^\.'),                         # leading dot
    re.compile(r'\.@'),                         # dot before @
    re.compile(r'\.\.'),                        # consecutive dots
    re.compile(r'^[^a-zA-Z0-9]'),               # starts with non-alphanum
    re.compile(r'[^a-zA-Z0-9]$'),               # ends with non-alphanum
    re.compile(r'^.{50,}'),                     # extremely long local parts
    re.compile(r'^[-_]'),                       # starts with hyphen/underscore
    re.compile(r'[-_]$'),                       # ends with hyphen/underscore
    re.compile(r'^user\d{4,}$', re.I),          # userNNNN pattern
    re.compile(r'^member\d{4,}$', re.I),        # memberNNNN pattern
    re.compile(r'^customer\d{4,}$', re.I),      # customerNNNN pattern
    re.compile(r'[\+\=]{3,}'),                  # 3+ special chars in a row
    re.compile(r'[\(\)\[\]\{\}<>]'),             # brackets in local part
    re.compile(r'^(f|m|u)\d{5,}'),              # f12345, m12345 (forum IDs)
]


def is_us_email(email):
    """
    Multi-layer aggressive filter for US-relevant email addresses.
    Returns True only for high-quality, likely US emails.
    """
    if not email:
        return False
    
    # Must match basic structural regex
    if not EMAIL_REGEX.match(email):
        return False
    
    # Parse properly
    real_name, real_addr = parseaddr(email)
    if not real_addr or '@' not in real_addr:
        return False
    
    if real_addr != email:
        return False  # parseaddr modified it = it was malformed
    
    local, domain = email.rsplit('@', 1)
    domain_lower = domain.lower()
    
    # === DOMAIN CHECKS ===
    
    # Block non-US country TLDs
    domain_parts = domain_lower.split('.')
    tld = domain_parts[-1]
    # Check for two-part TLDs like co.jp, com.cn, co.uk
    base_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) >= 2 else tld
    
    # Check if it matches any blocked TLD pattern
    if base_domain in COUNTRY_BLOCK_TLDS or tld in COUNTRY_BLOCK_TLDS:
        return False
    
    # Block known bad domains
    if base_domain in BANNED_DOMAINS or domain_lower in BANNED_DOMAINS:
        return False
    
    # Must end with a US-relevant TLD (com/org/net/edu/gov/mil/us/io)
    if tld not in US_TLDS:
        return False
    
    # === LOCAL PART CHECKS ===
    
    # Check machine-generated patterns
    for pattern in MACHINE_PATTERNS:
        if pattern.search(local):
            return False
    
    # Length sanity
    if len(local) < 3 or len(local) > 40:
        return False
    
    if len(email) > 80:
        return False
    
    # Check for phone-number-like local parts (contains 7+ consecutive digits)
    digit_count = sum(1 for c in local if c.isdigit())
    if digit_count >= 7 and digit_count / len(local) >= 0.5:
        return False
    
    # Local part should have at least 2 alphabetic characters
    alpha_count = sum(1 for c in local if c.isalpha())
    if alpha_count < 2:
        return False
    
    # Check for non-ASCII characters (internationalized emails)
    try:
        local.encode('ascii')
        domain_lower.encode('ascii')
    except UnicodeEncodeError:
        return False
    
    # Visual quality: suspicious patterns
    suspicious_suffixes = [
        '.copernicus.org.uk', '.interq.or.jp', '.lolipop.jp',
        '.sakura.ne.jp', '.x0.com', '.ddo.jp', '.ddo.biz',
        '.s55.com', '.rrr.jp', '.gogo.jp',
    ]
    for suffix in suspicious_suffixes:
        if domain_lower.endswith(suffix):
            return False
    
    return True


def extract_emails_from_html(html_text, source_url=None):
    """Extract clean emails from HTML text using aggressive filtering."""
    found_emails = set()
    
    # First pass: standard regex search
    candidates = set(re.findall(r'[a-zA-Z0-9][a-zA-Z0-9._%+\-]{0,62}[a-zA-Z0-9]@[a-zA-Z0-9][a-zA-Z0-9.\-]+[a-zA-Z]{2,}', str(html_text)))
    
    # Also catch obfuscated: name [at] domain [dot] com
    obfuscated = set(re.findall(r'([a-zA-Z0-9._%+\-]{3,64})\s*\[?at\]?\s*([a-zA-Z0-9.\-]{2,255})\s*\[?dot\]?\s*([a-zA-Z]{2,})', str(html_text), re.I))
    for local_part, domain_name, tld_part in obfuscated:
        candidates.add(f"{local_part.strip()}@{domain_name.strip()}.{tld_part.strip()}")
    
    for candidate in candidates:
        # Normalize and clean
        clean = candidate.strip().lower()
        # Filter
        if is_us_email(clean):
            found_emails.add(clean)
    
    return found_emails


def fetch_warc_page(page_info):
    """Fetch a single WARC record (the actual HTML of one page) by offset+length."""
    filename = page_info['filename']
    offset = int(page_info['offset'])
    length = int(page_info['length'])
    url = page_info['url']
    
    offset_end = offset + length - 1
    
    try:
        resp = requests.get(
            f"{CC_BASE}{filename}",
            headers={'Range': f'bytes={offset}-{offset_end}'},
            timeout=30
        )
        if resp.status_code != 206:
            return url, None
        
        # Decompress gzip
        try:
            with gzip.GzipFile(fileobj=BytesIO(resp.content)) as f:
                warc_data = f.read()
        except Exception:
            return url, None
        
        # Parse WARC to find the HTTP body
        warc_str = warc_data.decode('utf-8', errors='replace')
        # Split on double newline to separate headers from body
        if '\r\n\r\n' in warc_str:
            headers_part, body = warc_str.split('\r\n\r\n', 1)
        elif '\n\n' in warc_str:
            headers_part, body = warc_str.split('\n\n', 1)
        else:
            body = warc_str
        
        return url, body[:50000]  # cap at 50KB to avoid massive pages
    except Exception as e:
        return url, None


def query_domain_pages(domain, max_pages=10000):
    """
    Query CDX Index for all pages under a given domain with status 200.
    Returns list of page info dicts.
    """
    pages = []
    page_num = 0
    
    # Normalize domain - remove www. if present, or add *. prefix
    clean_domain = domain.strip().lower()
    if clean_domain.startswith('www.'):
        clean_domain = clean_domain[4:]
    
    # CDX API query
    params = {
        'url': f'*.{clean_domain}/*',
        'output': 'json',
        'fl': 'url,filename,offset,length,timestamp',
        'filter': 'status:200',
        'pageSize': 1000,
    }
    
    try:
        resp = requests.get(INDEX_API, params=params, timeout=30)
        if resp.status_code != 200:
            print(f"  [!] Index query failed for {domain}: HTTP {resp.status_code}")
            return []
        
        for line in resp.text.strip().split('\n'):
            if not line.strip():
                continue
            try:
                page = json.loads(line)
                # Deduplicate by URL (remove fragments/anchors)
                clean_url = urldefrag(page['url'])[0]
                page['url'] = clean_url
                pages.append(page)
            except json.JSONDecodeError:
                continue
        
        # Handle pagination - CDX API has 1000 result limit per page
        # For production, you'd paginate, but for now we sample
        random.shuffle(pages)
        pages = pages[:max_pages]
        
        print(f"  [+] Found {len(pages)} pages for {domain}")
        return pages
    
    except Exception as e:
        print(f"  [!] Error querying {domain}: {e}")
        return []


def process_domain(domain, max_pages_per_domain=500, emails_per_domain_target=1000):
    """Process a single domain: query index, fetch pages, extract emails."""
    print(f"\n{'='*60}")
    print(f"[*] Processing domain: {domain}")
    print(f"{'='*60}")
    
    # Step 1: Find pages
    pages = query_domain_pages(domain, max_pages_per_domain)
    if not pages:
        return set()
    
    # Step 2: Fetch WARC records and extract emails
    domain_emails = set()
    fetched = 0
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_warc_page, p): p for p in pages}
        
        for future in as_completed(futures):
            url, html_body = future.result()
            if html_body:
                fetched += 1
                emails = extract_emails_from_html(html_body, url)
                domain_emails.update(emails)
                
                if fetched % 50 == 0:
                    print(f"  [~] Fetched {fetched} pages, {len(domain_emails)} emails from {domain}")
                
                if len(domain_emails) >= emails_per_domain_target:
                    # Cancel remaining futures
                    for f in futures:
                        f.cancel()
                    break
    
    print(f"  [+] Domain {domain}: fetched {fetched} pages, extracted {len(domain_emails)} unique emails")
    return domain_emails


def main():
    parser = argparse.ArgumentParser(description='US Email Extractor from Common Crawl')
    parser.add_argument('--target', type=int, default=200000, help='Target number of emails')
    parser.add_argument('--output', default='us_emails.txt', help='Output file')
    parser.add_argument('--max-domains', type=int, default=100, help='Max domains to process')
    parser.add_argument('--pages-per-domain', type=int, default=300, help='Max pages to fetch per domain')
    parser.add_argument('--emails-per-domain', type=int, default=1500, help='Target emails per domain')
    args = parser.parse_args()
    
    # Parse target domains
    print("[*] Loading target US domains...")
    target_domains = []
    for line in DEFAULT_TARGET_DOMAINS.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        for domain in line.split(','):
            domain = domain.strip()
            if domain:
                target_domains.append(domain)
    
    print(f"[+] Loaded {len(target_domains)} target domains")
    
    all_emails = set()
    domains_processed = 0
    
    # Shuffle domains for variety
    random.shuffle(target_domains)
    
    for domain in target_domains[:args.max_domains]:
        if len(all_emails) >= args.target:
            break
        
        domain_emails = process_domain(
            domain,
            max_pages_per_domain=args.pages_per_domain,
            emails_per_domain_target=args.emails_per_domain
        )
        all_emails.update(domain_emails)
        domains_processed += 1
        
        # Write progress incrementally
        with open(args.output, 'w') as f:
            f.write('\n'.join(sorted(all_emails)))
            f.write('\n')
        
        print(f"\n[*] Progress: {len(all_emails)}/{args.target} emails from {domains_processed} domains")
        
        # Be polite to the CDX API - don't hammer it
        time.sleep(1)
    
    print(f"\n{'='*60}")
    print(f"[+] FINISHED: {len(all_emails)} emails collected from {domains_processed} domains")
    print(f"[+] Output saved to: {args.output}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()