#!/usr/bin/env python3
"""
wet_email_harvester.py - Download Common Crawl WET files and extract US/legitimate emails.

Usage:
    # Post-process existing emails.txt (fast, cleans what you already have)
    python3 wet_email_harvester.py --post-process emails.txt --output us_emails.txt
    
    # Download new WET files with aggressive filtering (runs the full pipeline)
    python3 wet_email_harvester.py --method cloudfront --wet-files 50 --target 200000 --output us_emails.txt
    
    # Use multiple WET files and show stats without saving
    python3 wet_email_harvester.py --method cloudfront --wet-files 10 --stats-only
"""

import gzip
import json
import os
import random
import re
import sys
import time
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path
from typing import Set, Tuple, Optional

try:
    from warcio import ArchiveIterator
except ImportError:
    print("ERROR: warcio not installed. Run: pip install warcio")
    sys.exit(1)


# =============================================================================
# AGGRESSIVE EMAIL FILTER
# =============================================================================

# Blocked country TLDs - anything non-US focused
BLOCKED_COUNTRY_TLDS = {
    'ru', 'su', 'by', 'ua', 'kz', 'uz', 'pl', 'cz', 'sk', 'hu', 'ro', 'bg',
    'rs', 'hr', 'si', 'ba', 'mk', 'lt', 'lv', 'ee', 'ge', 'am', 'az', 'md',
    'cn', 'jp', 'kr', 'in', 'hk', 'tw', 'sg', 'my', 'th', 'vn', 'ph', 'id',
    'pk', 'bd', 'lk', 'np', 'kh', 'la', 'mm',
    'za', 'ng', 'ke', 'eg', 'ma', 'tn', 'dz', 'gh', 'cm', 'ci', 'sn', 'et',
    'il', 'ae', 'sa', 'qa', 'kw', 'om', 'bh', 'jo', 'lb', 'ir', 'iq', 'tr',
    'uk', 'gb', 'de', 'fr', 'it', 'es', 'pt', 'nl', 'be', 'ch', 'at', 'se',
    'dk', 'no', 'fi', 'ie', 'is', 'lu', 'mt', 'gr', 'cy',
    'br', 'mx', 'ar', 'cl', 'co', 'pe', 'ec', 've', 'uy', 'py', 'bo', 'cr',
    'pa', 'gt', 'do', 'cu',
    'au', 'nz',
}

# US-allowed TLDs (plus exceptions like .io for tech)
US_ALLOWED_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'mil', 'us'}

# Banned freemail/garbage domains
BANNED_DOMAINS = {
    # Russia/Eastern Europe
    'mail.ru', 'yandex.ru', 'rambler.ru', 'list.ru', 'bk.ru', 'inbox.ru',
    'ya.ru', 'ukr.net', 'meta.ua', 'i.ua',
    'freemail.hu', 'freemail.it', 'freemail.gr',
    # China
    '163.com', '126.com', 'qq.com', 'sina.com', 'sohu.com',
    'aliyun.com', 'yeah.net',
    # Japan
    'yahoo.co.jp', 'docomo.ne.jp', 'ezweb.ne.jp',
    # Germany
    'web.de', 'gmx.de', 't-online.de', 'freenet.de', 'arcor.de',
    # France
    'orange.fr', 'sfr.fr', 'free.fr', 'laposte.net',
    # Italy
    'tin.it', 'libero.it', 'virgilio.it', 'alice.it',
    # Spain
    'terra.es', 'ono.com',
    # Poland
    'wp.pl', 'o2.pl', 'interia.pl', 'onet.pl',
    # Netherlands
    'xs4all.nl', 'planet.nl', 'ziggo.nl',
    # Brazil
    'uol.com.br', 'bol.com.br', 'ig.com.br',
    # Generic freemail often abused
    'protonmail.com', 'proton.me', 'tutanota.com',
    'mail.com', 'inbox.com',
    'yandex.com',
    'hushmail.com',
    'example.com', 'test.com', 'domain.com',
    'noreply.com', 'no-reply.com', 'donotreply.com',
    'yourdomain.com', 'your-email.com', 'youremail.com',
    'emailprovider.com', 'myemail.com',
}

BANNED_DOMAIN_PATTERNS = [
    r'^\d+\.\d+\.\d+\.\d+$',
    r'^[a-zA-Z0-9]{40,}\.',
    r'^xn--',
    r'\.test$', r'\.local$', r'\.localhost$', r'\.invalid$', r'\.example$',
    r'^\d{10,}\.\w+$',
]


def split_email(email: str) -> Tuple[Optional[str], Optional[str]]:
    parts = email.split('@', 1)
    if len(parts) != 2:
        return None, None
    return parts[0].strip(), parts[1].strip()


def is_valid_local_part(local: str) -> bool:
    if not local:
        return False
    if len(local) > 64:
        return False
    # Must have at least 3 alphabetic chars
    if sum(1 for c in local if c.isalpha()) < 3:
        return False
    # No digits-only
    if local.isdigit():
        return False
    # No consecutive dots
    if '..' in local:
        return False
    # Cannot start/end with special chars
    if local[0] in '._-+' or local[-1] in '._-+':
        return False
    # No date patterns
    if re.search(r'(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])', local):
        return False
    # No phone numbers
    if re.search(r'^\d{3}[-_]?\d{3}[-_]?\d{4}$', local):
        return False
    # No pure garbage local parts
    if re.search(r'^(user|usr|test|temp|tmp|admin|info|contact|mail|noreply|no.reply|postmaster|webmaster|abuse|support|help|service|robot|spam|nospam|guest|demo|sample)(\d+|$)', local, re.IGNORECASE):
        return False
    # No UUID-looking
    if re.search(r'^[a-f0-9]{32}$', local, re.IGNORECASE):
        return False
    if re.search(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', local, re.IGNORECASE):
        return False
    # Must have at least one letter
    if not any(c.isalpha() for c in local):
        return False
    # Avoid hex-heavy local parts
    hex_chars = sum(1 for c in local if c in '0123456789abcdef')
    if len(local) >= 8 and hex_chars / len(local) > 0.85:
        return False
    return True


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    tld = parts[-1].lower()
    # Block country TLDs
    if tld in BLOCKED_COUNTRY_TLDS:
        return False
    # Only allow US-focused TLDs
    if tld not in US_ALLOWED_TLDS:
        return False
    # Check banned patterns
    for pattern in BANNED_DOMAIN_PATTERNS:
        if re.search(pattern, domain):
            return False
    # Second-level domain must have letters
    sld = parts[-2].lower() if len(parts) >= 2 else ''
    if not sld or not any(c.isalpha() for c in sld):
        return False
    # Check exact banned domains (registered domain = last 2 parts)
    reg_domain_2 = '.'.join(parts[-2:]).lower()
    if reg_domain_2 in BANNED_DOMAINS:
        return False
    if len(parts) >= 3:
        reg_domain_3 = '.'.join(parts[-3:]).lower()
        if reg_domain_3 in BANNED_DOMAINS:
            return False
    return True


def is_email_valid(email: str) -> Tuple[bool, str]:
    """Returns (is_valid, reason_if_invalid)."""
    email_lower = email.strip().lower()
    local, domain = split_email(email_lower)
    if not local or not domain:
        return False, "parse_failed"
    if not is_valid_domain(domain):
        return False, "domain"
    if not is_valid_local_part(local):
        return False, "local_part"
    return True, "ok"


# =============================================================================
# WET FILE DOWNLOADER
# =============================================================================

BASE_URL_CLOUDFRONT = "https://ds5q9oxwqwsfj.cloudfront.net/"
BASE_URL_DATA = "https://data.commoncrawl.org/"

# CC-MAIN-2026-17 is our target (April 2026 crawl)
CRAWL = "CC-MAIN-2026-17"
WET_PATHS_URL = f"{BASE_URL_DATA}crawl-data/{CRAWL}/wet.paths.gz"

EMAIL_RE = re.compile(
    r'[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}'
)


def fetch_wet_paths() -> list:
    """Fetch the list of WET file paths for this crawl."""
    print(f"Fetching WET file list from {WET_PATHS_URL}...")
    req = urllib.request.Request(WET_PATHS_URL)
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = gzip.decompress(resp.read())
    paths = data.decode('utf-8').strip().split('\n')
    print(f"Found {len(paths):,} WET files in crawl {CRAWL}")
    return paths


def download_wet_file(wet_path: str, base_url: str, timeout: int = 300) -> Optional[bytes]:
    """Download a single WET file, return raw bytes."""
    url = f"{base_url}{wet_path}"
    print(f"  Downloading: {wet_path.split('/')[-1][:60]}...", end=' ', flush=True)
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        print(f"{len(data)/1024/1024:.1f} MB")
        return data
    except Exception as e:
        print(f"FAILED: {e}")
        return None


def extract_emails_from_wet(wet_data: bytes) -> Set[str]:
    """Extract emails from WET file content, applying aggressive filter."""
    emails = set()
    stats = {'total_matches': 0, 'domain_rejected': 0, 'local_rejected': 0, 'kept': 0}
    
    try:
        stream = gzip.decompress(wet_data)
    except:
        stream = wet_data
    
    # Extract text content and find emails
    text = stream.decode('utf-8', errors='replace')
    
    # Find all email-like strings
    matches = EMAIL_RE.findall(text)
    stats['total_matches'] = len(matches)
    
    for match in matches:
        valid, reason = is_email_valid(match)
        if valid:
            emails.add(match.lower())
            stats['kept'] += 1
        elif reason == 'domain':
            stats['domain_rejected'] += 1
        else:
            stats['local_rejected'] += 1
    
    return emails, stats


def process_wet_file(wet_path: str, base_url: str, seen_emails: set, 
                     target: int, verbose: bool = False) -> Tuple[set, dict]:
    """Download and process a single WET file."""
    data = download_wet_file(wet_path, base_url)
    if data is None:
        return set(), {}
    
    new_emails, stats = extract_emails_from_wet(data)
    
    # Only keep emails we haven't seen before
    truly_new = new_emails - seen_emails
    
    if verbose:
        print(f"  Found {len(new_emails)} emails ({len(truly_new)} new) - "
              f"kept {stats['kept']}/{stats['total_matches']} raw matches")
    
    return truly_new, stats


def run_wet_pipeline(num_files: int, target: int, output_path: str, 
                     base_url: str, verbose: bool = False):
    """Main WET file processing pipeline."""
    
    # Get WET file list
    wet_paths = fetch_wet_paths()
    
    # Shuffle for diversity (different segments)
    random.shuffle(wet_paths)
    
    # Pick files
    paths_to_process = wet_paths[:num_files]
    print(f"\nWill process {len(paths_to_process)} WET files")
    
    all_emails = set()
    total_raw = 0
    total_kept = 0
    total_domain_rej = 0
    total_local_rej = 0
    completed_files = 0
    failed_files = 0
    
    start_time = time.time()
    
    for i, wet_path in enumerate(paths_to_process, 1):
        if len(all_emails) >= target:
            print(f"\nReached target of {target:,} emails after {i-1} files")
            break
        
        file_start = time.time()
        print(f"\n[{i}/{len(paths_to_process)}] Processing WET file...")
        
        new_emails, stats = process_wet_file(wet_path, base_url, all_emails, target, verbose)
        
        if new_emails:
            all_emails.update(new_emails)
            total_raw += stats.get('total_matches', 0)
            total_kept += stats.get('kept', 0)
            total_domain_rej += stats.get('domain_rejected', 0)
            total_local_rej += stats.get('local_rejected', 0)
            completed_files += 1
        else:
            failed_files += 1
        
        elapsed = time.time() - file_start
        rate = len(new_emails) / elapsed * 60 if elapsed > 0 else 0
        
        print(f"  → +{len(new_emails):,} new emails | "
              f"Total: {len(all_emails):,}/{target:,} | "
              f"Rate: {rate:.0f} emails/min | "
              f"Time: {elapsed:.0f}s")
    
    total_time = time.time() - start_time
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"COMPLETE")
    print(f"{'='*60}")
    print(f"  Files processed:       {completed_files} (success) / {failed_files} (failed)")
    print(f"  Total unique emails:   {len(all_emails):,}")
    print(f"  Raw regex matches:     {total_raw:,}")
    print(f"  After domain filter:   {total_raw - total_domain_rej:,} (removed {total_domain_rej:,})")
    print(f"  After local filter:    {total_kept:,} (removed {total_local_rej:,})")
    print(f"  Final unique:          {len(all_emails):,}")
    print(f"  Total time:            {total_time/60:.1f} min")
    print(f"  Average:               {total_kept/completed_files:.0f} emails/file (when successful)")
    print(f"  Effective rate:        {len(all_emails)/total_time*60:.0f} emails/min")
    
    # Save
    if output_path:
        print(f"\n  Writing {len(all_emails):,} emails to {output_path}...")
        with open(output_path, 'w') as f:
            for email in sorted(all_emails):
                f.write(email + '\n')
        print(f"  Done!")
    
    return all_emails


def post_process(input_path: str, output_path: str):
    """Post-process an existing email file with the aggressive filter."""
    print(f"Loading emails from {input_path}...")
    
    emails = set()
    with open(input_path, 'r') as f:
        for line in f:
            line = line.strip().lower()
            if line and '@' in line:
                emails.add(line)
    
    print(f"Loaded {len(emails):,} unique emails")
    
    # Apply filter
    results = {'ok': 0, 'domain': 0, 'local_part': 0, 'parse_failed': 0}
    filtered = []
    
    for email in sorted(emails):
        valid, reason = is_email_valid(email)
        results[reason] = results.get(reason, 0) + 1
        if valid:
            filtered.append(email)
    
    # Stats
    total = len(emails)
    kept = len(filtered)
    print(f"\n{'='*60}")
    print(f"FILTER RESULTS")
    print(f"{'='*60}")
    print(f"  Input:                  {total:>8,}")
    print(f"  Passed filter:          {kept:>8,} ({kept/max(total,1)*100:.1f}%)")
    print(f"  Removed:                {total - kept:>8,}")
    print(f"")
    print(f"  Rejection breakdown:")
    for reason in ['parse_failed', 'domain', 'local_part']:
        c = results.get(reason, 0)
        print(f"    - {reason:20s}: {c:>8,} ({c/max(total,1)*100:.1f}%)")
    
    # Save
    if output_path:
        print(f"\nWriting {kept:,} emails to {output_path}...")
        with open(output_path, 'w') as f:
            for email in filtered:
                f.write(email + '\n')
        print(f"Done!")
    
    # Show sample
    print(f"\n  Sample of kept emails:")
    for email in sorted(filtered)[:25]:
        print(f"    {email}")
    
    return filtered


def stats_only(num_files: int, base_url: str):
    """Run a stats-only pass on N WET files to estimate yield."""
    wet_paths = fetch_wet_paths()
    random.shuffle(wet_paths)
    paths = wet_paths[:num_files]
    
    print(f"\nAnalyzing {num_files} WET files for stats (no email saving)...")
    
    total_raw = 0
    total_kept = 0
    total_domain_rej = 0
    total_local_rej = 0
    total_urls_checked = 0
    file_yields = []
    
    start = time.time()
    
    for i, wet_path in enumerate(paths, 1):
        file_start = time.time()
        
        data = download_wet_file(wet_path, base_url)
        if data is None:
            continue
        
        emails, stats = extract_emails_from_wet(data)
        
        total_raw += stats['total_matches']
        total_kept += stats['kept']
        total_domain_rej += stats['domain_rejected']
        total_local_rej += stats['local_rejected']
        file_yields.append(stats['kept'])
        
        elapsed = time.time() - file_start
        print(f"  [{i}/{num_files}] {stats['kept']:>5} emails kept "
              f"({stats['domain_rejected']:>5} domain, {stats['local_rejected']:>5} local rej) "
              f"[{elapsed:.0f}s]")
    
    total_time = time.time() - start
    
    print(f"\n{'='*60}")
    print(f"STATS OVER {num_files} WET FILES")
    print(f"{'='*60}")
    print(f"  Total raw matches:      {total_raw:,}")
    print(f"  After domain filter:    {total_raw - total_domain_rej:,}")
    print(f"  After local filter:     {total_kept:,}")
    print(f"  Domain rejection rate:  {total_domain_rej/max(total_raw,1)*100:.1f}%")
    print(f"  Local part rejection:   {total_local_rej/max(total_raw-total_domain_rej,1)*100:.1f}%")
    print(f"  Overall filter rate:    {total_kept/max(total_raw,1)*100:.1f}%")
    print(f"")
    
    if file_yields:
        avg = sum(file_yields) / len(file_yields)
        print(f"  Average yield/file:     {avg:.0f} emails")
        print(f"  Min yield:              {min(file_yields):,}")
        print(f"  Max yield:              {max(file_yields):,}")
        print(f"  Time per file:          {total_time/len(file_yields):.0f}s avg")
        print(f"")
        
        # Estimate for 200K
        needed = int(200000 / avg) + 1
        time_needed = needed * (total_time / len(file_yields))
        print(f"  ESTIMATED FOR 200,000 EMAILS:")
        print(f"    Files needed:          ~{needed}")
        print(f"    Estimated time:        ~{time_needed/60:.0f} min ({time_needed/3600:.1f} hours)")


# =============================================================================
# MAIN
# =============================================================================

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Harvest US/legitimate emails from Common Crawl WET files'
    )
    
    # Mode selection
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--post-process', metavar='INPUT',
                          help='Post-process an existing email file with aggressive filter')
    mode_group.add_argument('--stats-only', action='store_true',
                          help='Only show stats for N WET files (no email saving)')
    
    # WET download options
    parser.add_argument('--wet-files', type=int, default=5,
                       help='Number of WET files to process (default: 5)')
    parser.add_argument('--target', type=int, default=200000,
                       help='Target number of emails (default: 200,000)')
    parser.add_argument('--output', '-o', default='',
                       help='Output file path')
    parser.add_argument('--method', choices=['cloudfront', 'data'], default='cloudfront',
                       help='Download method (default: cloudfront)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    base_url = BASE_URL_CLOUDFRONT if args.method == 'cloudfront' else BASE_URL_DATA
    
    if args.post_process:
        output = args.output or args.post_process + '.filtered'
        post_process(args.post_process, output)
    
    elif args.stats_only:
        stats_only(args.wet_files, base_url)
    
    else:
        output = args.output or f'us_emails_{CRAWL.lower()}.txt'
        run_wet_pipeline(args.wet_files, args.target, output, base_url, args.verbose)


if __name__ == '__main__':
    main()