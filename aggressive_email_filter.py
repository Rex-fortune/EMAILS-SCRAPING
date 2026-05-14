#!/usr/bin/env python3
"""
aggressive_email_filter.py - Post-process extracted emails to keep only US/legitimate ones.

Run this against your existing emails.txt from the WET extraction.

Usage:
    python3 aggressive_email_filter.py input.txt output.txt
"""

import re
import sys
from pathlib import Path

# ========== CONFIGURATION ==========

# Country TLDs to BLOCK entirely (non-US content)
BLOCKED_COUNTRY_TLDS = {
    # Eastern Europe / Russia
    'ru', 'su', 'by', 'ua', 'kz', 'uz', 'pl', 'cz', 'sk', 'hu', 'ro', 'bg',
    'rs', 'hr', 'si', 'ba', 'mk', 'lt', 'lv', 'ee', 'ge', 'am', 'az', 'md',
    # Asia
    'cn', 'jp', 'kr', 'in', 'hk', 'tw', 'sg', 'my', 'th', 'vn', 'ph', 'id',
    'pk', 'bd', 'lk', 'np', 'kh', 'la', 'mm',
    # Africa
    'za', 'ng', 'ke', 'eg', 'ma', 'tn', 'dz', 'gh', 'cm', 'ci', 'sn', 'et',
    # Middle East
    'il', 'ae', 'sa', 'qa', 'kw', 'om', 'bh', 'jo', 'lb', 'ir', 'iq', 'tr',
    # Western Europe (non-US)
    'uk', 'gb', 'de', 'fr', 'it', 'es', 'pt', 'nl', 'be', 'ch', 'at', 'se',
    'dk', 'no', 'fi', 'ie', 'is', 'lu', 'mt', 'gr', 'cy',
    # Latin America
    'br', 'mx', 'ar', 'cl', 'co', 'pe', 'ec', 've', 'uy', 'py', 'bo', 'cr',
    'pa', 'gt', 'do', 'cu',
    # Oceania
    'au', 'nz',
    # Other
    'us',  # We'll handle .us differently - keep for now, filter separately
}

# Banned email domains (non-US freemail services, known garbage domains)
BANNED_DOMAINS = {
    # Russian/Eastern European
    'mail.ru', 'yandex.ru', 'rambler.ru', 'list.ru', 'bk.ru', 'inbox.ru',
    'ya.ru', 'gmail.ru', 'yandex.ua', 'ukr.net', 'meta.ua', 'i.ua',
    'freemail.hu', 'freemail.it', 'freemail.gr',
    # Chinese
    '163.com', '126.com', 'qq.com', 'sina.com', 'sina.cn', 'sohu.com',
    'aliyun.com', 'yeah.net', 'outlook.cn', 'hotmail.cn',
    # Japanese
    'yahoo.co.jp', 'docomo.ne.jp', 'ezweb.ne.jp', 'softbank.ne.jp',
    # German
    'web.de', 'gmx.de', 't-online.de', 'freenet.de', 'arcor.de',
    'online.de', 'email.de', 'posteo.de',
    # French
    'orange.fr', 'sfr.fr', 'free.fr', 'laposte.net', 'club-internet.fr',
    'wanadoo.fr', 'hotmail.fr', 'gmail.fr', 'yahoo.fr',
    # Italian
    'tin.it', 'libero.it', 'virgilio.it', 'alice.it', 'email.it',
    'yahoo.it', 'hotmail.it',
    # Spanish
    'yahoo.es', 'hotmail.es', 'terra.es', 'ono.com',
    # Polish
    'wp.pl', 'o2.pl', 'interia.pl', 'onet.pl',
    # Dutch
    'xs4all.nl', 'planet.nl', 'ziggo.nl', 'hetnet.nl', 'home.nl',
    # Brazilian
    'uol.com.br', 'bol.com.br', 'ig.com.br', 'globo.com', 'terra.com.br',
    'yahoo.com.br', 'hotmail.com.br',
    # Other known freemail/garbage
    'protonmail.com', 'proton.me', 'tutanota.com', 'gmx.com', 'gmx.net',
    'mail.com', 'email.com', 'inbox.com', 'outlook.com', 'hotmail.com',
    'zoho.com', 'yandex.com', 'fastmail.com', 'hushmail.com',
    'aol.com', 'aim.com', 'icloud.com', 'me.com', 'mac.com',
    'live.com', 'live.fr', 'live.it', 'live.de', 'live.co.uk',
    'msn.com', 'passport.com',
    # Common forum/spam domains
    'example.com', 'test.com', 'domain.com', 'email.com',
    'admin.com', 'info.com', 'mail.com', 'contact.com',
    'noreply.com', 'no-reply.com', 'donotreply.com',
    # Machine-generated
    'yourdomain.com', 'your-email.com', 'youremail.com',
    'emailprovider.com', 'myemail.com',
    # Sketchy TLDs often abused
    'mail.tk', 'mail.ml', 'mail.ga', 'mail.cf',
}

# US-allowed TLDs - only these for "US presence"
US_ALLOWED_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'mil'}

# Domain patterns that are clearly machine-generated/bad
BANNED_DOMAIN_PATTERNS = [
    r'^\d+\.\d+\.\d+\.\d+$',           # IP addresses
    r'^[a-zA-Z0-9]{30,}\.',             # Very long gibberish domains
    r'^\d{8,}\.',                        # Numeric-suffixed domains
    r'^xn--',                            # IDN domains
    r'\.test$',                          # test domains
    r'\.local$',                         # local domains
    r'\.localhost$',
    r'\.invalid$',
    r'\.example$',
    r'\.arpa$',
    r'\d{10,}\.\w+$',                   # Domains with long number sequences
]

def load_emails(filepath):
    """Load emails from a file, one per line."""
    seen = set()
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip().lower()
            if line and '@' in line and line not in seen:
                seen.add(line)
    return seen

def split_email(email):
    """Split email into local part and domain."""
    parts = email.split('@', 1)
    if len(parts) != 2:
        return None, None
    return parts[0].strip(), parts[1].strip()

def is_valid_local_part(local):
    """Check if the local part looks like a real person's email."""
    if not local:
        return False
    
    # Must have at least 3 alphabetic characters
    alpha_count = sum(1 for c in local if c.isalpha())
    if alpha_count < 3:
        return False
    
    # No digits-only local parts
    if local.isdigit():
        return False
    
    # No hex-looking local parts (mostly hex chars)
    hex_chars = sum(1 for c in local if c in '0123456789abcdef')
    if len(local) >= 8 and hex_chars / len(local) > 0.8:
        return False
    
    # No consecutive dots
    if '..' in local:
        return False
    
    # Cannot start or end with special chars
    if local[0] in '._-+' or local[-1] in '._-+':
        return False
    
    # No timestamp-like patterns (e.g., 20230101, 2024, 2025)
    if re.search(r'(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])', local):
        return False
    
    # No phone-number-like local parts
    if re.search(r'^\d{3}[-_]?\d{3}[-_]?\d{4}$', local):
        return False
    
    # No purely machine-generated patterns
    if re.search(r'^(user|usr|test|temp|tmp|admin|info|contact|mail|noreply|no.reply|postmaster|webmaster|abuse|support|help|info|service|robot|spam|nospam|guest|demo|sample)(\d+|$)', local, re.IGNORECASE):
        return False
    
    # Must have at least one letter in the local part
    if not any(c.isalpha() for c in local):
        return False
    
    # Avoid local parts that look like UUIDs or hashes
    if re.search(r'^[a-f0-9]{32}$', local, re.IGNORECASE):
        return False
    if re.search(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', local, re.IGNORECASE):
        return False
    
    return True

def is_valid_domain(domain):
    """Check if domain looks like a real US-oriented domain."""
    if not domain:
        return False
    
    # Get TLD (last part of domain)
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    
    tld = parts[-1].lower()
    
    # Block specific country TLDs
    if tld in BLOCKED_COUNTRY_TLDS:
        return False
    
    # For US presence, only allow these TLDs
    if tld not in US_ALLOWED_TLDS:
        # Exception: .us is allowed too
        if tld != 'us':
            return False
    
    # Check against banned domain patterns
    for pattern in BANNED_DOMAIN_PATTERNS:
        if re.search(pattern, domain):
            return False
    
    # Domain must have at least one dot (subdomain or domain.tld)
    if len(parts) < 2:
        return False
    
    # Second-level domain should have letters
    sld = parts[-2].lower() if len(parts) >= 2 else ''
    if not sld or not any(c.isalpha() for c in sld):
        return False
    
    # Check exact banned domains
    # Extract the registered domain (last 2-3 parts)
    if len(parts) >= 3:
        reg_domain = '.'.join(parts[-3:]).lower()
        if reg_domain in BANNED_DOMAINS:
            return False
    
    reg_domain = '.'.join(parts[-2:]).lower()
    if reg_domain in BANNED_DOMAINS:
        return False
    
    return True

def filter_emails(emails):
    """Main filtering pipeline."""
    filtered = []
    rejected = {'country_tld': 0, 'banned_domain': 0, 'bad_local': 0, 'bad_domain': 0, 'duplicate': 0}
    
    for email in sorted(emails):
        email_lower = email.strip().lower()
        local, domain = split_email(email_lower)
        
        if not local or not domain:
            continue
        
        # 1. Check domain validity first (fastest rejection)
        if not is_valid_domain(domain):
            # Determine specific reason
            parts = domain.split('.')
            tld = parts[-1] if len(parts) > 1 else ''
            if tld in BLOCKED_COUNTRY_TLDS:
                rejected['country_tld'] += 1
            else:
                rejected['bad_domain'] += 1
            continue
        
        # 2. Check local part quality
        if not is_valid_local_part(local):
            rejected['bad_local'] += 1
            continue
        
        filtered.append(email_lower)
    
    return filtered, rejected

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input_file> <output_file>")
        print(f"       {sys.argv[0]} --stats <input_file>")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    
    print(f"Loading emails from {input_path}...")
    emails = load_emails(input_path)
    print(f"Loaded {len(emails):,} unique emails")
    
    print("Filtering...")
    filtered, rejected = filter_emails(emails)
    
    total = len(emails)
    kept = len(filtered)
    pct = (kept / total * 100) if total > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"RESULTS:")
    print(f"{'='*60}")
    print(f"  Input emails:           {total:>8,}")
    print(f"  After filtering:        {kept:>8,} ({pct:.1f}%)")
    print(f"  Removed:                {total - kept:>8,}")
    print(f"\n  REJECTION BREAKDOWN:")
    for reason, count in rejected.items():
        pct_r = (count / max(total, 1) * 100)
        print(f"    - {reason:20s}: {count:>8,} ({pct_r:.1f}%)")
    
    print(f"\nWriting to {output_path}...")
    with open(output_path, 'w') as f:
        for email in filtered:
            f.write(email + '\n')
    
    print(f"Done! {kept:,} emails saved to {output_path}")
    
    # Show sample
    print(f"\n  SAMPLE (first 20):")
    for i, email in enumerate(sorted(filtered)[:20]):
        print(f"    {i+1:>3}. {email}")

if __name__ == '__main__':
    main()