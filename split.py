import argparse
import os

parser = argparse.ArgumentParser(description="Split email list into multiple files")

parser.add_argument("-input", required=True, help="Input file (emails.txt)")
parser.add_argument("-parts", type=int, help="Number of output files")
parser.add_argument("-size", type=int, help="Number of emails per file")
parser.add_argument("-out", default="output", help="Output folder")

args = parser.parse_args()

input_file = args.input
num_parts = args.parts
chunk_size = args.size
output_dir = args.out

# Read emails
with open(input_file, "r", encoding="utf-8") as f:
    emails = [line.strip() for line in f if line.strip()]

total = len(emails)

# Create output folder
os.makedirs(output_dir, exist_ok=True)

# Decide splitting method
if num_parts:
    chunk_size = total // num_parts + (total % num_parts > 0)

elif chunk_size:
    num_parts = (total // chunk_size) + (total % chunk_size > 0)

else:
    raise ValueError("You must specify either -parts or -size")

# Split and write files
for i in range(num_parts):
    start = i * chunk_size
    end = start + chunk_size
    chunk = emails[start:end]

    if not chunk:
        break

    filename = os.path.join(output_dir, f"emails_part_{i+1}.txt")
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(chunk))

    print(f"Saved {len(chunk)} emails → {filename}")

print(f"\nDone: {total} emails split into {i+1} files.")