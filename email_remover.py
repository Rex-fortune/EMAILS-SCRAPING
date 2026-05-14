import argparse
import csv
import re

parser = argparse.ArgumentParser(description="Remove emails from TXT list using TXT/CSV remove files")

parser.add_argument("-input", required=True, help="Main email txt file")
parser.add_argument("-remove", nargs="+", required=True, help="One or more txt/csv files containing emails to remove")
parser.add_argument("-output", default="cleaned_emails.txt", help="Output txt file")

args = parser.parse_args()

email_regex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

remove_set = set()

def extract_emails_from_file(filepath):
    found = set()

    if filepath.lower().endswith(".csv"):
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                for cell in row:
                    matches = email_regex.findall(cell)
                    for email in matches:
                        found.add(email.lower())

    else:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                matches = email_regex.findall(line)
                for email in matches:
                    found.add(email.lower())

    return found

for file in args.remove:
    emails = extract_emails_from_file(file)
    remove_set.update(emails)
    print(f"Loaded {len(emails)} emails from {file}")

kept = 0
removed = 0

with open(args.input, "r", encoding="utf-8", errors="ignore") as infile, \
     open(args.output, "w", encoding="utf-8") as outfile:

    for line in infile:
        email = line.strip().lower()

        if not email:
            continue

        if email in remove_set:
            removed += 1
            continue

        outfile.write(email + "\n")
        kept += 1

print("\n===== DONE =====")
print(f"Emails to remove loaded: {len(remove_set)}")
print(f"Removed: {removed}")
print(f"Kept: {kept}")
print(f"Saved to: {args.output}")