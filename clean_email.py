#!/usr/bin/env python3
"""
clean_emails.py - Aggressive US-only email filter for pentesting

Post-processes a file of raw emails and filters to:
- US/English TLDs only (.com, .org, .net, .edu, .gov, .mil, .us)
- Rejects known foreign email domains
- Rejects machine-generated patterns
- Requires minimum quality standards
"""

import re
import sys
import argparse
from pathlib import Path
from collections import Counter

# ─── CONFIGURATION ───────────────────────────────────────────────────────────

# Only these TLDs pass — US/English focused
US_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'us',
    'io', 'co', 'ai',  # tech startup common
}

# Foreign TLDs — explicitly blocked even if they look valid
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

# Known non-US email domains — these are never legitimate US personal emails
BANNED_DOMAINS = {
    # Russian/CIS
    'mail.ru', 'yandex.ru', 'yandex.com', 'rambler.ru', 'bk.ru', 'list.ru',
    'inbox.ru', 'hotmail.ru', 'ya.ru', 'narod.ru', 'rambler.ru',
    # Chinese
    '163.com', '126.com', 'qq.com', 'sina.com', 'sina.cn', 'sohu.com',
    'aliyun.com', 'tom.com', 'yeah.net', '21cn.com', '189.cn', '139.com',
    'wo.cn', 'foxmail.com', 'chinamail.com',
    # Japanese
    'yahoo.co.jp', 'docomo.ne.jp', 'ezweb.ne.jp', 'softbank.ne.jp', 'i.softbank.jp',
    'au.com', 'nifty.com', 'infoseek.jp', 'livedoor.com',
    # Korean
    'naver.com', 'daum.net', 'hanmail.net', 'nate.com', 'korea.com',
    'dreamwiz.com', 'chol.com', 'empal.com', 'paran.com',
    # German
    't-online.de', 'web.de', 'gmx.de', 'freenet.de', 'arcor.de',
    '1und1.de', 'online.de', 'mailbox.org',
    # French
    'wanadoo.fr', 'orange.fr', 'free.fr', 'laposte.net', 'sfr.fr',
    'neuf.fr', 'club-internet.fr', 'cegetel.net',
    # Italian
    'libero.it', 'virgilio.it', 'tin.it', 'alice.it', 'tele2.it',
    # Polish
    'wp.pl', 'o2.pl', 'onet.pl', 'interia.pl', 'poczta.onet.pl',
    # Dutch/Belgian
    'hetnet.nl', 'ziggo.nl', 'kpnmail.nl', 'telenet.be', 'skynet.be',
    # Scandinavian
    'telia.com', 'telenor.no', 'getmail.no', 'spray.se', 'passagen.se',
    # Indian
    'rediffmail.com', 'rediffmail.in', 'indiatimes.com',
    # Brazilian
    'uol.com.br', 'bol.com.br', 'ig.com.br', 'globo.com', 'terra.com.br',
    'hotmail.com.br', 'yahoo.com.br',
    # Spanish
    'ya.com', 'telefonica.net', 'eresmas.com',
    # Generic non-US
    'seznam.cz', 'centrum.cz', 'atlas.cz', 'post.cz',
    'bigpond.com', 'bigpond.net.au', 'iinet.net.au', 'optusnet.com.au',
    'xtra.co.nz', 'clear.net.nz',
    'mail.com.tr', 'superonline.com',
    'abv.bg', 'mail.bg',
    'iol.pt', 'sapo.pt', 'clix.pt',
    'gmx.net', 'gmx.at', 'gmx.ch',
    'bluewin.ch', 'sunrise.ch',
    'aol.jp', 'excite.co.jp',
    'ukr.net', 'meta.ua', 'i.ua',
    'mail.md',
    'inbox.lv',
    'yahoo.de', 'yahoo.fr', 'yahoo.it', 'yahoo.es', 'yahoo.co.uk',
    'yahoo.co.jp', 'yahoo.com.au', 'yahoo.ca', 'yahoo.cn',
    'googlemail.com',
}

# Domains that are machine-generated / disposable / test
BANNED_PATTERN_DOMAINS = {
    'example.com', 'example.org', 'example.net', 'domain.com',
    'test.com', 'test.org', 'test.net', 'testing.com', 'testing.org',
    'mailinator.com', 'guerrillamail.com', 'temp-mail.org',
    '10minutemail.com', 'throwaway.email', 'trashmail.com',
    'sharklasers.com', 'maildrop.cc', 'yopmail.com',
    'localhost', 'local', 'localhost.localdomain',
}

# Local part patterns that indicate machine-generated addresses
MACHINE_PATTERNS = [
    # Timestamps: 202401, 2024-01-15, 20240115123045
    r'^[12]\d{3}[01]\d[0-3]\d',
    r'^[12]\d{3}-[01]\d-[0-3]\d',
    r'^\d{8,}',                    # 8+ digits (Unix timestamps, date-based)
    # Hex hashes
    r'^[0-9a-f]{8,}$',            # hex strings 8+ chars
    r'^[0-9a-f]{32}$',            # MD5
    r'^[0-9a-f]{40}$',           # SHA1
    r'^[0-9a-f]{64}$',           # SHA256
    # UUIDs
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    # Base64-like (alphanumeric with +/ and ending in =)
    r'^[A-Za-z0-9+/]{20,}=?=?$',
    # Numbers only
    r'^\d+$',
    # Phone number patterns
    r'^\+?\d{10,15}$',
    r'^1?\d{10}$',
    # Single chars or single letter+number
    r'^[a-zA-Z0-9]{1,2}$',
    # Consecutive dots or leading/trailing special chars
    r'\.\.',                       # consecutive dots
    r'^\.',                        # leading dot
    r'\.$',                        # trailing dot
    r'^-|-$',                      # leading/trailing hyphen
    r'^_|_$',                      # leading/trailing underscore
]

def is_valid_us_email(email):
    """Check if an email passes ALL quality filters for US/legitimate addresses."""
    email = email.strip().lower()
    
    # Basic format check
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        return False
    
    # Must have exactly one @
    if email.count('@') != 1:
        return False
    
    local, domain = email.rsplit('@', 1)
    
    # Length checks
    if len(local) < 2 or len(local) > 64:
        return False
    if len(domain) < 4 or len(domain) > 255:
        return False
    if len(email) > 254:
        return False
    
    # Extract TLD
    domain_parts = domain.split('.')
    tld = domain_parts[-1].lower()
    
    # Block foreign TLDs
    if tld in FOREIGN_TLDS:
        return False
    
    # Only allow US/English TLDs
    if tld not in US_TLDS:
        return False
    
    # Block known foreign email domains
    if domain.lower() in BANNED_DOMAINS:
        return False
    
    # Block machine-generated domain patterns
    if domain.lower() in BANNED_PATTERN_DOMAINS:
        return False
    
    # Check local part for machine-generated patterns
    for pattern in MACHINE_PATTERNS:
        if re.match(pattern, local):
            return False
    
    # Local part quality checks
    # Must have at least 3 alphabetic characters
    alpha_count = sum(1 for c in local if c.isalpha())
    if alpha_count < 3:
        return False
    
    # Must have at least one alphabetic character (not just numbers/symbols)
    if not any(c.isalpha() for c in local):
        return False
    
    # Ratio of letters to total length (must be at least 30% alphabetic)
    if len(local) > 0 and (alpha_count / len(local)) < 0.3:
        return False
    
    # No consecutive special characters
    if re.search(r'[._%+-]{2,}', local):
        return False
    
    # Local part can't start or end with special chars
    if local[0] in '._%+-' or local[-1] in '._%+-':
        return False
    
    # Domain should have at least two parts (name.tld)
    if len(domain_parts) < 2:
        return False
    
    return True


def main():
    parser = argparse.ArgumentParser(
        description='Clean and filter emails to US-only legitimate addresses'
    )
    parser.add_argument('input', help='Input file with raw emails')
    parser.add_argument('-o', '--output', default='emails_us_clean.txt',
                       help='Output file for filtered emails')
    parser.add_argument('--stats', action='store_true',
                       help='Show detailed filtering statistics')
    parser.add_argument('--sample', type=int, default=0,
                       help='Show a sample of rejected emails with reasons')
    args = parser.parse_args()
    
    if not Path(args.input).exists():
        print(f"Error: Input file '{args.input}' not found")
        sys.exit(1)
    
    print(f"Reading emails from {args.input}...")
    with open(args.input, 'r', errors='ignore') as f:
        raw_emails = [line.strip() for line in f if line.strip()]
    
    print(f"Loaded {len(raw_emails)} raw emails")
    
    # Track rejection reasons
    reasons = Counter()
    valid = []
    
    for email in raw_emails:
        email_lower = email.strip().lower()
        
        # Check filter
        if not is_valid_us_email(email_lower):
            # Determine why (for stats)
            if '@' not in email_lower or email_lower.count('@') != 1:
                reasons['no_single_at_sign'] += 1
            else:
                try:
                    local, domain = email_lower.rsplit('@', 1)
                    
                    # Check TLD
                    domain_parts = domain.split('.')
                    tld = domain_parts[-1].lower()
                    
                    if tld in FOREIGN_TLDS:
                        reasons[f'tld_blocked_{tld}'] += 1
                    elif tld not in US_TLDS:
                        reasons[f'tld_not_us_{tld}'] += 1
                    elif domain in BANNED_DOMAINS:
                        reasons[f'banned_domain'] += 1
                    elif any(re.match(p, local) for p in MACHINE_PATTERNS):
                        reasons['machine_generated_local'] += 1
                    elif sum(1 for c in local if c.isalpha()) < 3:
                        reasons['too_few_alpha_chars'] += 1
                    else:
                        reasons['other_filter_fail'] += 1
                except:
                    reasons['parse_error'] += 1
            continue
        
        valid.append(email_lower)
    
    # Deduplicate
    valid = list(dict.fromkeys(valid))
    
    print(f"\nResults:")
    print(f"  Total raw emails:     {len(raw_emails):>8}")
    print(f"  Valid US emails:      {len(valid):>8}")
    print(f"  Filtered out:         {len(raw_emails) - len(valid):>8}")
    print(f"  Retention rate:       {len(valid)/len(raw_emails)*100:.1f}%" if len(raw_emails) > 0 else "  N/A")
    
    # Write output
    with open(args.output, 'w') as f:
        for email in sorted(valid):
            f.write(email + '\n')
    
    print(f"\nSaved {len(valid)} valid US emails to {args.output}")
    
    if args.stats and reasons:
        print(f"\nRejection breakdown (top 20):")
        for reason, count in reasons.most_common(20):
            print(f"  {reason:40s} {count:>8}")


if __name__ == '__main__':
    main()