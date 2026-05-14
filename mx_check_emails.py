import re
import dns.resolver
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from threading import Lock

parser = argparse.ArgumentParser(description="Strict Email Cleaner + MX Validator")

parser.add_argument("-input", required=True)
parser.add_argument("-output", default="cleaned_emails.txt")
parser.add_argument("-rejected", default="rejected_emails.txt")
parser.add_argument("-domains", default="domain_summary.txt")
parser.add_argument("-threads", type=int, default=10)

args = parser.parse_args()

# STRICT: line must be only one clean email
email_regex = re.compile(
    r"^(?!.*\.\.)[a-zA-Z0-9][a-zA-Z0-9._%+\-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,24}$"
)

blocked_domains = {
    "example.com", "test.com", "abc.com", "domain.com", "company.com",
    "your-company.com", "xxx.com", "site.com", "email.com", "mail.com",
    "yopmail.com", "tempmail.com", "10minutemail.com", "guerrillamail.com",
    "mailinator.com", "trashmail.com", "throwawaymail.com"
}

blocked_tlds = {
    "xyz", "top", "click", "work", "cam", "rest", "bar", "monster",
    "quest", "loan", "win", "bid", "date", "download", "stream"
}

role_prefixes = {
    "info", "support", "admin", "sales", "contact", "office", "hello",
    "webmaster", "postmaster", "abuse", "noreply", "no-reply",
    "newsletter", "marketing", "service", "customerservice", "help",
    "team", "mail", "email", "privacy", "security", "billing"
}

fake_locals = {
    "test", "testing", "demo", "fake", "user", "admin", "sample",
    "example", "abc", "abcd", "abcdef", "asdf", "qwerty", "null"
}

mx_cache = {}
mx_lock = Lock()

def reject(email, reason, raw):
    return email, "rejected", reason, raw

def valid_domain(domain):
    if ".." in domain:
        return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if not label:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if len(label) > 63:
            return False

    return True

def has_mx_record(domain):
    with mx_lock:
        if domain in mx_cache:
            return mx_cache[domain]

    try:
        records = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx_hosts = [str(r.exchange).rstrip(".").lower() for r in records]

        # Reject NULL MX: means domain does not accept email
        if len(mx_hosts) == 1 and mx_hosts[0] == "":
            result = False
        else:
            result = len(mx_hosts) > 0

    except Exception:
        result = False

    with mx_lock:
        mx_cache[domain] = result

    return result

def process_line(line):
    raw = line.strip()

    # No mercy: don't extract from messy text
    email = raw.lower()

    if not email:
        return reject(raw, "empty_line", raw)

    if not email_regex.match(email):
        return reject(email, "invalid_format", raw)

    local, domain = email.split("@", 1)

    if not valid_domain(domain):
        return reject(email, "bad_domain_format", raw)

    if domain in blocked_domains:
        return reject(email, "blocked_domain", raw)

    tld = domain.rsplit(".", 1)[-1]
    if tld in blocked_tlds:
        return reject(email, "blocked_tld", raw)

    if local in fake_locals:
        return reject(email, "fake_local_part", raw)

    if local in role_prefixes:
        return reject(email, "role_based_email", raw)

    if len(local) < 3:
        return reject(email, "local_too_short", raw)

    if local.isdigit():
        return reject(email, "local_only_numbers", raw)

    if any(x in local for x in ["test", "fake", "xxx", "spam", "demo"]):
        return reject(email, "suspicious_local", raw)

    if not has_mx_record(domain):
        return reject(email, "no_mx_record", raw)

    return email, "accepted", "valid", raw


with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

accepted = set()
rejected = []
domain_counter = Counter()

stats = Counter()
stats["total"] = len(lines)

with ThreadPoolExecutor(max_workers=args.threads) as executor:
    futures = [executor.submit(process_line, line) for line in lines]

    for future in as_completed(futures):
        email, status, reason, raw = future.result()

        if status == "accepted":
            if email in accepted:
                stats["duplicates"] += 1
            else:
                accepted.add(email)
                domain_counter[email.split("@", 1)[1]] += 1
                stats["accepted"] += 1
        else:
            stats["rejected"] += 1
            stats[reason] += 1
            rejected.append((email, reason, raw))

with open(args.output, "w", encoding="utf-8") as f:
    for email in sorted(accepted):
        f.write(email + "\n")

with open(args.rejected, "w", encoding="utf-8") as f:
    for email, reason, raw in rejected:
        f.write(f"{email} | {reason} | raw={raw}\n")

with open(args.domains, "w", encoding="utf-8") as f:
    for domain, count in domain_counter.most_common():
        f.write(f"{domain}: {count}\n")

print("\n===== RESULTS =====")
print(f"Total lines: {stats['total']}")
print(f"Accepted/saved: {stats['accepted']}")
print(f"Rejected: {stats['rejected']}")
print(f"Duplicates skipped: {stats['duplicates']}")

print("\n--- Rejection Breakdown ---")
for key, value in stats.items():
    if key not in ["total", "accepted", "rejected", "duplicates"]:
        print(f"{key}: {value}")

print(f"\nSaved valid emails to: {args.output}")
print(f"Rejected log saved to: {args.rejected}")
print(f"Domain summary saved to: {args.domains}")