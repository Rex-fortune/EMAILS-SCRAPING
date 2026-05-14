import re
import dns.resolver
import smtplib
import socket
import argparse
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

parser = argparse.ArgumentParser(description="Email Cleaner + MX + SMTP Validator")

parser.add_argument("-input", required=True, help="Input email list")
parser.add_argument("-output", default="smtp_cleaned_emails.txt", help="Valid emails txt output")
parser.add_argument("-csv", default="sendgrid_ready.csv", help="SendGrid CSV output")
parser.add_argument("-rejected", default="rejected_emails.txt", help="Rejected emails output")
parser.add_argument("-from_email", required=True, help="SMTP FROM email")
parser.add_argument("-helo", required=True, help="SMTP HELO domain")
parser.add_argument("-threads", type=int, default=10, help="Number of threads")
parser.add_argument("-smtp", action="store_true", help="Enable SMTP mailbox check")

args = parser.parse_args()

email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
extract_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]+')

blocked_domains = {
    "example.com", "test.com", "abc.com", "domain.com",
    "xxx.com", "company.com", "your-company.com"
}

risky_prefixes = {
    "admin", "info", "support", "sales", "contact", "office",
    "hello", "service", "customerservice", "webmaster", "noreply",
    "no-reply", "abuse", "postmaster"
}

mx_cache = {}

def get_mx(domain):
    if domain in mx_cache:
        return mx_cache[domain]

    try:
        records = dns.resolver.resolve(domain, "MX")
        mx_hosts = sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in records],
            key=lambda x: x[0]
        )
        mx_cache[domain] = mx_hosts
        return mx_hosts
    except Exception:
        mx_cache[domain] = []
        return []

def smtp_check(email, mx_hosts):
    for _, mx_host in mx_hosts[:2]:
        try:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx_host, 25)
            server.helo(args.helo)
            server.mail(args.from_email)
            code, _ = server.rcpt(email)
            server.quit()

            if code in [250, 251, 450, 451, 452]:
                return True

        except (smtplib.SMTPException, socket.timeout, OSError):
            continue

    return False

def score_email(email):
    local, domain = email.split("@", 1)
    score = 100
    reasons = []

    if domain in blocked_domains:
        return 0, "blocked_domain"

    if local in risky_prefixes:
        score -= 25
        reasons.append("role_based")

    if len(local) <= 2:
        score -= 20
        reasons.append("short_local")

    if any(x in email for x in ["test", "fake", "example", "xxx"]):
        score -= 50
        reasons.append("test_pattern")

    if domain.endswith(".ru") or domain.endswith(".cn"):
        score -= 10
        reasons.append("higher_risk_tld")

    if score >= 80:
        risk = "low"
    elif score >= 50:
        risk = "medium"
    else:
        risk = "high"

    return score, risk + (";" + ",".join(reasons) if reasons else "")

def process_line(line):
    raw = line.strip()

    match = extract_regex.search(raw)
    if not match:
        return None, "rejected", "no_email_found", raw, 0

    email = match.group().lower()

    if not email_regex.match(email):
        return email, "rejected", "invalid_format", raw, 0

    local, domain = email.split("@", 1)

    if domain in blocked_domains or email in ["abc@abc.com", "test@test.com"]:
        return email, "rejected", "fake_or_blocked", raw, 0

    mx_hosts = get_mx(domain)
    if not mx_hosts:
        return email, "rejected", "no_mx_record", raw, 0

    score, risk = score_email(email)

    if score < 50:
        return email, "rejected", f"high_risk:{risk}", raw, score

    if args.smtp:
        if not smtp_check(email, mx_hosts):
            return email, "rejected", "smtp_failed", raw, score

    return email, "accepted", risk, raw, score

with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

accepted = {}
rejected = []
stats = {
    "total": len(lines),
    "accepted": 0,
    "rejected": 0,
    "duplicates": 0,
    "no_email_found": 0,
    "invalid_format": 0,
    "fake_or_blocked": 0,
    "no_mx_record": 0,
    "smtp_failed": 0,
    "high_risk": 0,
}

with ThreadPoolExecutor(max_workers=args.threads) as executor:
    futures = [executor.submit(process_line, line) for line in lines]

    for future in as_completed(futures):
        email, status, reason, raw, score = future.result()

        if status == "accepted":
            if email in accepted:
                stats["duplicates"] += 1
            else:
                accepted[email] = {
                    "email": email,
                    "risk": reason,
                    "score": score
                }
                stats["accepted"] += 1
        else:
            stats["rejected"] += 1
            rejected.append((email or raw, reason, score))

            if reason in stats:
                stats[reason] += 1
            elif reason.startswith("high_risk"):
                stats["high_risk"] += 1

with open(args.output, "w", encoding="utf-8") as f:
    for email in sorted(accepted):
        f.write(email + "\n")

with open(args.csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["email", "risk", "score"])
    for email in sorted(accepted):
        item = accepted[email]
        writer.writerow([item["email"], item["risk"], item["score"]])

with open(args.rejected, "w", encoding="utf-8") as f:
    for email, reason, score in rejected:
        f.write(f"{email} | {reason} | score={score}\n")

print("\n===== RESULTS =====")
print(f"Total lines: {stats['total']}")
print(f"Accepted/saved: {stats['accepted']}")
print(f"Rejected: {stats['rejected']}")
print(f"Duplicates skipped: {stats['duplicates']}")

print("\n--- Rejection Breakdown ---")
print(f"No email found: {stats['no_email_found']}")
print(f"Invalid format: {stats['invalid_format']}")
print(f"Fake/blocked: {stats['fake_or_blocked']}")
print(f"No MX record: {stats['no_mx_record']}")
print(f"SMTP failed: {stats['smtp_failed']}")
print(f"High risk: {stats['high_risk']}")

print(f"\nTXT saved to: {args.output}")
print(f"SendGrid CSV saved to: {args.csv}")
print(f"Rejected log saved to: {args.rejected}")