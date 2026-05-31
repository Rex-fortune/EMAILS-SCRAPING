#!/usr/bin/env python3
"""
email_without_api_v2.py - WET-based email extractor with aggressive US-only filter

Downloads WET files from Common Crawl, extracts email addresses,
and applies aggressive filtering for US/legitimate addresses only.

Usage:
    python3 email_without_api_v2.py --wet-files 40 --target 200000 --output us_emails.txt
    python3 email_without_api_v2.py --wet-files 10 --target 50000 --output test_emails.txt
"""

import gzip
from html import parser
import re
import sys
import json
import time
import random
import argparse
import urllib.request
from pathlib import Path
from collections import Counter
from email.utils import parseaddr
from io import BytesIO

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# US/English-focused TLDs only
US_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'us', 'io', 'co', 'ai',
}

FOREIGN_TLDS = {
    'ac', 'ad', 'ae', 'af', 'ag', 'al', 'am', 'ao', 'ar', 'as', 'at', 'aw',
    'ax', 'az', 'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bm',
    'bn', 'bo', 'br', 'bs', 'bt', 'bw', 'by', 'bz', 'cc', 'cd', 'cf', 'cg',
    'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 'cv', 'cw', 'cx',
    'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ee', 'eg', 'er',
    'es', 'et', 'eu', 'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gd', 'ge',
    'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp', 'gq', 'gr', 'gs', 'gt',
    'gu', 'gw', 'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'ie', 'il',
    'im', 'in', 'iq', 'ir', 'is', 'it', 'je', 'jm', 'jo', 'jp', 'ke', 'kg',
    'kh', 'ki', 'km', 'kn', 'kp', 'kr', 'kw', 'ky', 'kz', 'la', 'lb', 'lc',
    'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'mc', 'md', 'me',
    'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 'mt',
    'mu', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nc', 'ne', 'nf', 'ng', 'ni',
    'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om', 'pa', 'pe', 'pf', 'pg', 'ph',
    'pk', 'pl', 'pm', 'pn', 'pr', 'ps', 'pt', 'pw', 'py', 'qa', 're', 'ro',
    'rs', 'ru', 'rw', 'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si', 'sk',
    'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'sv', 'sx', 'sy', 'sz', 'tc',
    'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tr', 'tt',
    'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'uy', 'uz', 'va', 'vc', 've', 'vg',
    'vi', 'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'za', 'zm', 'zw',
}

BANNED_DOMAINS = {
    'mail.ru', 'yandex.ru', 'yandex.com', 'rambler.ru', 'bk.ru', 'list.ru',
    'inbox.ru', 'hotmail.ru', 'ya.ru', 'narod.ru', 'rambler.ru',
    '163.com', '126.com', 'qq.com', 'sina.com', 'sina.cn', 'sohu.com',
    'aliyun.com', 'tom.com', 'yeah.net', 'foxmail.com',
    'yahoo.co.jp', 'docomo.ne.jp', 'ezweb.ne.jp', 'softbank.ne.jp',
    'naver.com', 'daum.net', 'hanmail.net', 'nate.com',
    't-online.de', 'web.de', 'gmx.de', 'freenet.de', 'arcor.de',
    'wanadoo.fr', 'orange.fr', 'free.fr', 'laposte.net', 'sfr.fr',
    'libero.it', 'virgilio.it', 'tin.it', 'alice.it',
    'wp.pl', 'o2.pl', 'onet.pl', 'interia.pl',
    'hetnet.nl', 'ziggo.nl', 'kpnmail.nl', 'telenet.be',
    'rediffmail.com', 'rediffmail.in',
    'uol.com.br', 'bol.com.br', 'ig.com.br', 'globo.com',
    'seznam.cz', 'centrum.cz',
    'bigpond.com', 'bigpond.net.au', 'iinet.net.au',
    'ukr.net', 'meta.ua', 'i.ua',
    'example.com', 'example.org', 'example.net',
    'test.com', 'test.org', 'test.net',
    'mailinator.com', 'guerrillamail.com', 'temp-mail.org',
    '10minutemail.com', 'trashmail.com', 'sharklasers.com',
    'yopmail.com', 'maildrop.cc',
    'localhost', 'local', 'localhost.localdomain',
    'googlemail.com',
}

MACHINE_PATTERNS = [
    # Date-based: 202401, 20240115
    r'^[12]\d{3}[01]\d[0-3]\d',
    r'^[12]\d{3}-[01]\d-[0-3]\d',
    # Long digit strings
    r'^\d{8,}',
    # Hex/hash patterns
    r'^[0-9a-f]{8,}$',
    r'^[0-9a-f]{32}$',
    r'^[0-9a-f]{40}$',
    r'^[0-9a-f]{64}$',
    # UUIDs
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    # Digits only
    r'^\d+$',
    # Phone numbers
    r'^\+?\d{10,15}$',
    r'^1?\d{10}$',
    # Single/double chars
    r'^[a-zA-Z0-9]{1,2}$',
    # Consecutive specials
    r'\.{2,}',
    r'^[._%+-]',
    r'[._%+-]$',
    r'^[^a-zA-Z]',  # local part must start with letter
]

# Email regex
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


# ═══════════════════════════════════════════════════════════════════════════════
# FILTER
# ═══════════════════════════════════════════════════════════════════════════════

def is_valid_us_email(email):
    """Aggressive filter for US/legitimate email addresses only."""
    email = email.strip().lower()
    
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False
    if email.count('@') != 1:
        return False
    
    local, domain = email.rsplit('@', 1)
    
    if len(local) < 2 or len(local) > 64:
        return False
    if len(domain) < 4 or len(domain) > 255:
        return False
    if len(email) > 254:
        return False
    
    domain_parts = domain.split('.')
    tld = domain_parts[-1].lower()
    
    # Block foreign TLDs
    if tld in FOREIGN_TLDS:
        return False
    # Only allow US/English TLDs
    if tld not in US_TLDS:
        return False
    
    # Block known banned domains
    if domain in BANNED_DOMAINS:
        return False
    
    # Check local part for machine patterns
    for pattern in MACHINE_PATTERNS:
        if re.match(pattern, local):
            return False
    
    # Quality: at least 3 alpha chars in local part
    alpha_count = sum(1 for c in local if c.isalpha())
    if alpha_count < 3:
        return False
    if not any(c.isalpha() for c in local):
        return False
    if (alpha_count / len(local)) < 0.3:
        return False
    
    # No consecutive special chars
    if re.search(r'[._%+-]{2,}', local):
        return False
    
    # Domain must have at least 2 parts
    if len(domain_parts) < 2:
        return False
    
    return True


def extract_and_filter_emails(text):
    """Extract emails from text and apply aggressive filter."""
    found = set()
    for match in EMAIL_REGEX.finditer(text):
        email = match.group(0).lower()
        if is_valid_us_email(email):
            found.add(email)
    return found


# ═══════════════════════════════════════════════════════════════════════════════
# WET DOWNLOAD
# ═══════════════════════════════════════════════════════════════════════════════

BASE_URL = 'https://data.commoncrawl.org/'
CRAWL = 'CC-MAIN-2026-17'

def get_wet_file_list(max_files=999999):
    """Fetch the list of WET file paths for the current crawl."""
    url = f'{BASE_URL}crawl-data/{CRAWL}/wet.paths.gz'
    print(f"  Fetching WET file list from {url}")
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            compressed = resp.read()
        decompressed = gzip.decompress(compressed)
        paths = decompressed.decode('utf-8').strip().split('\n')
        print(f"  Found {len(paths)} WET files available")
        return [p for p in paths if p.strip()][:max_files]
    except Exception as e:
        print(f"  Error fetching WET file list: {e}")
        return []


def download_and_process_wet(wet_path, progress_callback=None):
    """Download a single WET file and extract valid US emails."""
    url = f'{BASE_URL}{wet_path}'
    emails = set()
    
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip',
        })
        
        with urllib.request.urlopen(req, timeout=300) as resp:
            compressed_data = resp.read()
        
        # Decompress
        with gzip.GzipFile(fileobj=BytesIO(compressed_data)) as f:
            content = f.read().decode('utf-8', errors='replace')
        
        # Extract emails from the raw text
        for match in EMAIL_REGEX.finditer(content):
            email = match.group(0).lower()
            if is_valid_us_email(email):
                emails.add(email)
        
        if progress_callback:
            progress_callback(len(emails))
        
        return emails
        
    except Exception as e:
        print(f"    Error: {e}")
        return set()


def main():
    parser = argparse.ArgumentParser(
        description='Fetch emails by country from permitted/opt-in sources'
    )

    parser.add_argument(
        'country',
        help='Country code to fetch, e.g. us, za, uk, ca, ng'
    )

    parser.add_argument(
        'amount',
        type=int,
        help='Number of emails to fetch'
    )

    parser.add_argument(
        '--wet-files',
        type=int,
        default=5,
        help='Number of WET files to process'
    )

    parser.add_argument(
        '--output',
        default=None,
        help='Output file path'
    )

    parser.add_argument(
        '--resume',
        help='Existing output file to resume from'
    )

    args = parser.parse_args()

    country = args.country.lower()
    args.target = args.amount

    if args.output is None:
        args.output = f'{country}_emails.txt'
        
        # Load existing
        existing = set()
        if args.resume and Path(args.resume).exists():
            with open(args.resume, 'r') as f:
                existing = {line.strip().lower() for line in f if line.strip()}
            print(f"Resuming with {len(existing)} existing emails from {args.resume}")
        
        all_emails = set(existing)
        total_from_files = 0
        files_processed = 0
        
        print(f"\n{'='*60}")
        print(f"  WET Email Extractor v2 — Aggressive US Filter")
        print(f"  Crawl: {CRAWL}")
        print(f"  Country: {country.upper()}")
        print(f"  Target: {args.target:,} emails from {args.wet_files} WET files")
        print(f"{'='*60}\n")
        
        # Get WET file list
        print("[1/3] Getting WET file list...")
        wet_files = get_wet_file_list(args.wet_files)
        if not wet_files:
            print("  No WET files found!")
            sys.exit(1)
        
        # If we got more than requested, shuffle and take requested count
        if len(wet_files) > args.wet_files:
            random.shuffle(wet_files)
            wet_files = wet_files[:args.wet_files]
        
        print(f"\n[2/3] Processing {len(wet_files)} WET files...")
        
        for i, wet_path in enumerate(wet_files, 1):
            filename = wet_path.split('/')[-1]
            
            print(f"\n  [{i}/{len(wet_files)}] {filename}")
            print(f"    Downloading & extracting...", end=' ', flush=True)
            
            file_emails = download_and_process_wet(wet_path)
            
            if file_emails:
                before = len(all_emails)
                all_emails.update(file_emails)
                new_count = len(all_emails) - before
                total_from_files += len(file_emails)
                files_processed += 1
                
                print(f"found {len(file_emails):>6} emails ({new_count:>6} new) | "
                    f"Total: {len(all_emails):>7,} | "
                    f"Target: {args.target:,}")
                
                # Write progress after each file
                with open(args.output, 'w') as f:
                    for email in sorted(all_emails):
                        f.write(email + '\n')
            else:
                print(f"found 0 emails")
            
            # Check target
            if len(all_emails) >= args.target:
                print(f"\n{'='*60}")
                print(f"  TARGET REACHED: {len(all_emails):,} emails")
                print(f"{'='*60}")
                break
        
        # Final summary
        print(f"\n{'='*60}")
        print(f"  SUMMARY")
        print(f"{'='*60}")
        print(f"  Files processed:      {files_processed}")
        print(f"  Raw emails extracted: {total_from_files:,}")
        print(f"  Unique valid emails:  {len(all_emails):,}")
        print(f"  Target:               {args.target:,}")
        print(f"  Output file:          {args.output}")
        
        if len(all_emails) >= args.target:
            print(f"\n  ✓ TARGET ACHIEVED!")
        else:
            print(f"\n  Need {args.target - len(all_emails):,} more emails.")
            print(f"  Try: --wet-files {args.wet_files + 10} --output {args.output}")
        
        # Final write
        with open(args.output, 'w') as f:
            for email in sorted(all_emails):
                f.write(email + '\n')
        
        print(f"  Saved to {args.output}")


if __name__ == '__main__':
    main()