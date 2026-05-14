#!/usr/bin/env python3
"""
mail_validator.py — High-concurrency SMTP email validator for pentesting.

Validates email addresses by:
  1. Checking syntax
  2. Resolving MX records
  3. Performing SMTP handshake (RCPT TO) against the target MX

Outputs two CSVs:
  - valid.csv   — addresses that passed SMTP check (250 OK)
  - invalid.csv — addresses that failed or errored

Usage:
  python mail_validator.py --list targets.txt --workers 50 --timeout 10 --output validated
  python mail_validator.py --list targets.txt --sendgrid --skip-smtp   # just syntax+MX check
"""

import argparse
import csv
import re
import socket
import smtplib
import sys
import time
import concurrent.futures
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Tuple

import dns.resolver
import dns.exception

# ──────────────────────────────────────────────
#  Config
# ──────────────────────────────────────────────
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
SENDER_DOMAIN = "mailcheck.example.com"   # used for HELO + MAIL FROM
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 2

# ──────────────────────────────────────────────
#  Data
# ──────────────────────────────────────────────
@dataclass
class ValidationResult:
    email: str
    syntax_valid: bool = False
    domain: str = ""
    mx_host: str = ""
    mx_resolved: bool = False
    smtp_connected: bool = False
    smtp_response_code: int = 0
    smtp_response_text: str = ""
    valid: bool = False
    error: str = ""
    response_time_ms: float = 0.0

    def to_csv_row(self):
        return {
            "email":          self.email,
            "valid":          "YES" if self.valid else "NO",
            "syntax_ok":      "YES" if self.syntax_valid else "NO",
            "mx_resolved":    "YES" if self.mx_resolved else "NO",
            "mx_host":        self.mx_host,
            "smtp_code":      self.smtp_response_code,
            "smtp_response":  self.smtp_response_text[:120],
            "response_ms":    f"{self.response_time_ms:.1f}",
            "error":          self.error,
        }


# ──────────────────────────────────────────────
#  Core validation
# ──────────────────────────────────────────────
def resolve_mx(domain: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[bool, str]:
    """Resolve MX record for domain. Returns (success, mx_host)."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, 'MX')
        # Pick lowest-priority MX
        sorted_mx = sorted(answers, key=lambda r: r.preference)
        mx = str(sorted_mx[0].exchange).rstrip('.')
        return True, mx
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.LifetimeTimeout, dns.exception.Timeout,
            dns.resolver.NoNameservers) as e:
        return False, str(e)


def smtp_check(email: str, mx_host: str, timeout: int = DEFAULT_TIMEOUT,
               from_addr: str = f"noreply@{SENDER_DOMAIN}") -> Tuple[int, str, float]:
    """
    Connect to MX, HELO, MAIL FROM, RCPT TO, QUIT.
    Returns (smtp_code, response_text, elapsed_ms).
    """
    start = time.perf_counter()
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            smtp.ehlo_or_helo_if_needed()
            smtp.mail(from_addr)
            code, msg = smtp.rcpt(email)
            elapsed = (time.perf_counter() - start) * 1000
            return code, msg.decode('utf-8', errors='replace').strip(), elapsed
    except smtplib.SMTPConnectError as e:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, f"SMTPConnectError: {e}", elapsed
    except smtplib.SMTPServerDisconnected as e:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, f"Disconnected: {e}", elapsed
    except socket.timeout:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, "Timeout", elapsed
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, f"ConnectionError: {e}", elapsed
    except smtplib.SMTPException as e:
        elapsed = (time.perf_counter() - start) * 1000
        return 0, f"SMTPException: {e}", elapsed


def validate_one(email: str, timeout: int = DEFAULT_TIMEOUT,
                 skip_smtp: bool = False) -> ValidationResult:
    """Full validation pipeline for a single email."""
    res = ValidationResult(email=email)

    # 1. Syntax check
    if not EMAIL_REGEX.match(email):
        res.error = "Invalid syntax"
        return res
    res.syntax_valid = True
    domain = email.split('@')[1]
    res.domain = domain

    # 2. MX lookup
    mx_ok, mx_host = resolve_mx(domain, timeout)
    res.mx_resolved = mx_ok
    if not mx_ok:
        res.error = f"MX lookup failed: {mx_host}"
        return res
    res.mx_host = mx_host

    if skip_smtp:
        res.valid = True
        return res

    # 3. SMTP RCPT TO check
    for attempt in range(MAX_RETRIES):
        code, text, elapsed = smtp_check(email, mx_host, timeout)
        res.smtp_connected = code != 0
        res.smtp_response_code = code
        res.smtp_response_text = text
        res.response_time_ms = elapsed

        if code == 0:
            # Connection-level error — retry
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)
                continue
            res.error = text
            return res
        else:
            break

    # Interpret SMTP response
    # 250 = OK, 251 = user not local (will forward), 252 = cannot VRFY but will accept
    if code in (250, 251, 252):
        res.valid = True
    elif code in (550, 551, 553, 554):
        res.valid = False
    elif 400 <= code < 500:
        # Temporary failure — gray area
        res.valid = False
        res.error = f"Temp-fail ({code})"
    else:
        res.valid = False
        res.error = f"Unexpected code ({code})"

    return res


# ──────────────────────────────────────────────
#  Batch processing
# ──────────────────────────────────────────────
def load_emails(filepath: str) -> List[str]:
    """Load emails from text file (one per line) or CSV with 'email' column."""
    emails = []
    if filepath.endswith('.csv'):
        import csv as csv_lib
        with open(filepath, 'r') as f:
            for row in csv_lib.DictReader(f):
                if 'email' in row:
                    emails.append(row['email'].strip())
    else:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    emails.append(line)
    return emails


def batch_validate(emails: List[str], workers: int = 50,
                   timeout: int = DEFAULT_TIMEOUT,
                   skip_smtp: bool = False) -> List[ValidationResult]:
    """Validate all emails using a thread pool."""
    results: List[ValidationResult] = []
    total = len(emails)
    done = 0
    start_time = time.time()

    print(f"[*] Validating {total} emails with {workers} workers...")
    print(f"[*] Timeout: {timeout}s | Skip SMTP: {skip_smtp}")
    print("-" * 70)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(validate_one, email, timeout, skip_smtp): email
            for email in emails
        }

        for future in concurrent.futures.as_completed(future_map):
            done += 1
            email = future_map[future]
            try:
                result = future.result()
                results.append(result)

                # Print progress line
                status = "✓" if result.valid else "✗"
                detail = result.mx_host if result.mx_resolved else "NO-MX"
                if result.smtp_response_code:
                    detail = f"{result.smtp_response_code}"
                elapsed = time.time() - start_time
                pct = done / total * 100
                print(f"\r  [{done:>6}/{total}] {pct:>5.1f}% | "
                      f"{status} {email:<40s} | {detail:<25s} | "
                      f"{elapsed:>6.1f}s", end="", flush=True)

            except Exception as e:
                results.append(ValidationResult(
                    email=email, error=f"ThreadError: {e}"
                ))

    print()
    print("-" * 70)
    return results


# ──────────────────────────────────────────────
#  Output
# ──────────────────────────────────────────────
def write_results(results: List[ValidationResult], prefix: str = "validated"):
    """Write valid.csv and invalid.csv."""
    valid_rows = []
    invalid_rows = []
    for r in results:
        if r.valid:
            valid_rows.append(r.to_csv_row())
        else:
            invalid_rows.append(r.to_csv_row())

    fields = ["email", "valid", "syntax_ok", "mx_resolved", "mx_host",
              "smtp_code", "smtp_response", "response_ms", "error"]

    # Valid
    with open(f"{prefix}_valid.csv", 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(valid_rows)
    print(f"[+] Valid emails:   {len(valid_rows):>6} → {prefix}_valid.csv")

    # Invalid
    with open(f"{prefix}_invalid.csv", 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(invalid_rows)
    print(f"[+] Invalid/errors: {len(invalid_rows):>6} → {prefix}_invalid.csv")

    # Summary by error type
    error_counts = {}
    for r in results:
        if not r.valid:
            err = r.error or f"SMTP_{r.smtp_response_code}"
            error_counts[err] = error_counts.get(err, 0) + 1

    if error_counts:
        print("\n[!] Failure breakdown:")
        for err, count in sorted(error_counts.items(), key=lambda x: -x[1]):
            print(f"    {count:>6} → {err}")

    return valid_rows


# ──────────────────────────────────────────────
#  SendGrid output helper
# ──────────────────────────────────────────────
def write_sendgrid_input(valid_rows: List[dict], prefix: str = "validated"):
    """Write a clean CSV for SendGrid (just emails + a 'first_name' col)."""
    path = f"{prefix}_for_sendgrid.csv"
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["email", "first_name", "company"])
        for row in valid_rows:
            # Extract possible name from email prefix
            local = row["email"].split('@')[0]
            name = local.replace('.', ' ').replace('_', ' ').replace('-', ' ').title().split()[0] if local else ""
            w.writerow([row["email"], name, ""])
    print(f"[+] SendGrid-ready: {len(valid_rows):>6} → {path}")


# ──────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="SMTP Email Validator — Check which emails exist via MX + RCPT TO"
    )
    parser.add_argument('--list', '-l', required=True,
                        help='File with emails (one per line, or CSV with "email" column)')
    parser.add_argument('--workers', '-w', type=int, default=50,
                        help='Concurrent workers (default: 50)')
    parser.add_argument('--timeout', '-t', type=int, default=DEFAULT_TIMEOUT,
                        help=f'SMTP timeout in seconds (default: {DEFAULT_TIMEOUT})')
    parser.add_argument('--output', '-o', default='validated',
                        help='Output file prefix (default: validated)')
    parser.add_argument('--skip-smtp', action='store_true',
                        help='Skip SMTP handshake — only check syntax + MX')
    parser.add_argument('--sendgrid', action='store_true',
                        help='Also generate a clean CSV ready for SendGrid import')

    args = parser.parse_args()

    print(f"[*] Mail Validator — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Loading emails from: {args.list}")

    emails = load_emails(args.list)
    if not emails:
        print("[!] No emails loaded.")
        sys.exit(1)

    print(f"[*] Found {len(emails)} addresses")

    results = batch_validate(emails, workers=args.workers,
                             timeout=args.timeout,
                             skip_smtp=args.skip_smtp)

    valid_rows = write_results(results, prefix=args.output)

    if args.sendgrid:
        write_sendgrid_input(valid_rows, prefix=args.output)

    # Summary
    total = len(results)
    valid_count = sum(1 for r in results if r.valid)
    invalid_count = total - valid_count
    mx_ok = sum(1 for r in results if r.mx_resolved)
    print(f"\n{'='*70}")
    print(f"  Total:    {total:>6}")
    print(f"  Valid:    {valid_count:>6}  ({valid_count/total*100:>5.1f}%)")
    print(f"  Invalid:  {invalid_count:>6}  ({invalid_count/total*100:>5.1f}%)")
    print(f"  MX found: {mx_ok:>6}  ({mx_ok/total*100:>5.1f}%)")
    print(f"{'='*70}")


if __name__ == '__main__':
    main()