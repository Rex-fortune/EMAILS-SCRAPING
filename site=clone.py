#!/usr/bin/env python3
"""
SEDFA Site Cloner - Authorized Penetration Testing Tool
Clones https://www.sedfa.org.za completely (HTML, images, PDFs, CSS, JS)
Usage: python3 clone_sedfa.py
"""

import os
import re
import sys
import time
import hashlib
import urllib.parse
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from html.parser import HTMLParser

# ============================================================
# CONFIGURATION
# ============================================================
BASE_URL = "https://www.onesedfa.org.za/en-za/"
OUTPUT_DIR = "onesedfa-clone"
DELAY = 0.5  # seconds between requests (be polite)
MAX_RETRIES = 3
TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# Known pages from the site (auto-discovered + manual)
DISCOVERED_PAGES = set()
VISITED_PAGES = set()
DOWNLOADED_FILES = set()
FAILED_FILES = set()

# Pages discovered from our reconnaissance
SEED_PAGES = [
    "/",
    "/index.html",
    "/financial-support.html",
    "/business-development.html",
    "/cooperative-support.html",
    "/asset-finance.html",
    "/term-loan.html",
    "/bridging-loan.html",
    "/wholesale-lending.html",
    "/youth-challenge-fund.html",
    "/sems.html",
    "/technology-programme.html",
    "/pitch-funding-programme.html",
    "/tenders.html",
    "/careers.html",
    "/rfq.html",
    "/get-in-touch.html",
    "/login.html",
    "/register.html",
]

# Asset extensions to always download
ASSET_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.ico',
                    '.css', '.js', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                    '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm'}


# ============================================================
# FETCHER
# ============================================================
def fetch_url(url):
    """Fetch a URL with retries and proper headers."""
    for attempt in range(MAX_RETRIES):
        try:
            # Sanitize URL — encode spaces and other unsafe characters
            parsed = urllib.parse.urlparse(url)
            # Re-encode the path to handle spaces and special chars
            clean_path = urllib.parse.quote(parsed.path, safe='/:@!$&\'()*+,;=-._~')
            clean_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                clean_path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            
            req = Request(clean_url, headers={
                'User-Agent': USER_AGENT,
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
            })
            resp = urlopen(req, timeout=TIMEOUT)
            content = resp.read()
            content_type = resp.headers.get('Content-Type', '').lower()
            return content, content_type
        except HTTPError as e:
            if e.code == 404:
                return None, 'text/html'
            print(f"  [WARN] HTTP {e.code} for {url} (attempt {attempt+1}/{MAX_RETRIES})")
            time.sleep(DELAY)
        except (URLError, TimeoutError, ConnectionError) as e:
            print(f"  [WARN] {type(e).__name__} for {url} (attempt {attempt+1}/{MAX_RETRIES})")
            time.sleep(DELAY * 2)
        except Exception as e:
            print(f"  [WARN] {type(e).__name__} for {url}: {e} (attempt {attempt+1}/{MAX_RETRIES})")
            time.sleep(DELAY)
    return None, 'text/html'

# ============================================================
# HTML PARSER for LINK EXTRACTION
# ============================================================
class LinkExtractor(HTMLParser):
    """Extract all src, href, and srcset from HTML."""
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.pages = set()
        self.assets = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        base = self.base_url

        # Links to other pages
        if tag == 'a' and 'href' in attrs:
            href = attrs['href']
            full = urllib.parse.urljoin(base, href)
            parsed = urllib.parse.urlparse(full)
            # Only internal links
            if parsed.netloc == urllib.parse.urlparse(BASE_URL).netloc or parsed.netloc == '':
                # Remove fragment
                clean = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, parsed.query, ''
                ))
                ext = os.path.splitext(parsed.path)[1].lower()
                if not ext or ext == '.html' or ext == '.htm' or parsed.path.endswith('/'):
                    self.pages.add(clean)
                else:
                    self.assets.add(clean)

        # Images
        if tag == 'img' and 'src' in attrs:
            self.assets.add(urllib.parse.urljoin(base, attrs['src']))
        if tag == 'img' and 'srcset' in attrs:
            for part in attrs['srcset'].split(','):
                src = part.strip().split(' ')[0]
                self.assets.add(urllib.parse.urljoin(base, src))

        # CSS, JS, favicon, etc.
        if tag == 'link':
            if 'href' in attrs:
                rel = attrs.get('rel', '')
                self.assets.add(urllib.parse.urljoin(base, attrs['href']))
        if tag == 'script' and 'src' in attrs:
            self.assets.add(urllib.parse.urljoin(base, attrs['src']))
        if tag == 'source' and 'src' in attrs:
            self.assets.add(urllib.parse.urljoin(base, attrs['src']))
        if tag == 'iframe' and 'src' in attrs:
            self.assets.add(urllib.parse.urljoin(base, attrs['src']))

        # Inline style background images
        if tag == 'div' and 'style' in attrs:
            urls = re.findall(r'url\(["\']?([^"\'\)]+)["\']?\)', attrs['style'])
            for u in urls:
                self.assets.add(urllib.parse.urljoin(base, u))

    def handle_data(self, data):
        pass


def extract_links(html_content, base_url):
    """Extract all links from HTML."""
    parser = LinkExtractor(base_url)
    try:
        parser.feed(html_content.decode('utf-8', errors='replace'))
    except Exception:
        try:
            parser.feed(html_content.decode('latin-1'))
        except Exception as e:
            print(f"  [ERROR] Parsing HTML: {e}")
    return parser.pages, parser.assets


def extract_css_urls(css_content, base_url):
    """Extract URLs from CSS (url(), @import, etc.)."""
    urls = set()
    css_text = css_content.decode('utf-8', errors='replace')

    # url() patterns
    for match in re.finditer(r'url\(["\']?([^"\'\)]+)["\']?\)', css_text):
        urls.add(urllib.parse.urljoin(base_url, match.group(1)))

    # @import patterns
    for match in re.finditer(r'@import\s+["\']([^"\']+)["\']', css_text):
        urls.add(urllib.parse.urljoin(base_url, match.group(1)))

    return urls


# ============================================================
# FILE SAVER
# ============================================================
def save_file(url, content, output_dir):
    """Save fetched content to the proper local path, preserving directory structure."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path

    # Default to index.html for root
    if path == '' or path.endswith('/'):
        path = os.path.join(path, 'index.html')

    # Build local path and clean it
    local_path = os.path.join(output_dir, path.lstrip('/'))
    local_path = urllib.parse.unquote(local_path)
    # Remove query params from filename
    if '?' in local_path:
        local_path = local_path.split('?')[0]
    # Replace spaces with hyphens in filenames to avoid issues
    # local_path = local_path.replace(' ', '-')  # uncomment to replace spaces

    # Ensure local_path is not empty and has a directory
    local_path = os.path.normpath(local_path)
    dir_path = os.path.dirname(local_path)

    # Guard: if dir_path is empty, use output_dir as fallback
    if not dir_path:
        dir_path = output_dir
        local_path = os.path.join(output_dir, os.path.basename(local_path))

    # Ensure directory exists
    os.makedirs(dir_path, exist_ok=True)

    # Write file
    try:
        if isinstance(content, str):
            content = content.encode('utf-8')
        with open(local_path, 'wb') as f:
            f.write(content)
        return local_path
    except Exception as e:
        print(f"  [ERROR] Saving {local_path}: {e}")
        return None

def get_local_path(url, output_dir):
    """Convert a URL to its local file path."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path
    if path == '' or path.endswith('/'):
        path = os.path.join(path, 'index.html')
    local_path = os.path.join(output_dir, path.lstrip('/'))
    local_path = urllib.parse.unquote(local_path)
    if '?' in local_path:
        local_path = local_path.split('?')[0]
    return os.path.normpath(local_path)


# ============================================================
# REWRITE HTML TO USE LOCAL PATHS
# ============================================================
def rewrite_html(content, url, output_dir):
    """Rewrite HTML content to replace remote URLs with local paths."""
    text = content.decode('utf-8', errors='replace')
    parsed_base = urllib.parse.urlparse(url)
    base_domain = parsed_base.netloc

    def to_local_path(url_value):
        """Convert a URL to a local relative path."""
        full_url = urllib.parse.urljoin(url, url_value)
        parsed = urllib.parse.urlparse(full_url)

        # Skip external absolute URLs
        if parsed.netloc and parsed.netloc != urllib.parse.urlparse(BASE_URL).netloc:
            return None

        local = get_local_path(full_url, '')
        # Make relative to current page
        current_path = get_local_path(url, '')
        current_dir = os.path.dirname(current_path)
        if current_dir == '' or current_dir == '/':
            current_dir = ''

        try:
            rel = os.path.relpath(local.lstrip('/'), current_dir.lstrip('/'))
        except ValueError:
            rel = local

        # Ensure relative paths start with ./ or ../
        if not rel.startswith('.') and not rel.startswith('/'):
            rel = './' + rel

        return rel

    def replace_srcset(match):
        prefix = match.group(1)
        url_value = match.group(2)
        suffix = match.group(3)
        parts = []
        for part in url_value.split(','):
            part = part.strip()
            if part:
                sub_parts = part.split(' ')
                if sub_parts:
                    new_url = to_local_path(sub_parts[0])
                    if new_url:
                        sub_parts[0] = new_url
                    parts.append(' '.join(sub_parts))
        return prefix + ', '.join(parts) + suffix

    def replace_single(match):
        prefix = match.group(1)
        url_value = match.group(2)
        suffix = match.group(3)
        new_url = to_local_path(url_value)
        if new_url:
            return prefix + new_url + suffix
        return match.group(0)

    # srcset (comma-separated URLs)
    text = re.sub(r'(srcset=["\'])([^"\']+)(["\'])', replace_srcset, text)

    # Single URL attributes
    for attr in ['src', 'href', 'data-src', 'poster']:
        text = re.sub(
            r'(' + attr + r'=["\'])([^"\']+)(["\'])',
            replace_single, text
        )

    # CSS url() references
    text = re.sub(
        r'(url\(["\']?)([^"\'\)]+)(["\']?\))',
        replace_single, text
    )

    return text.encode('utf-8')


# ============================================================
# MAIN CLONING LOGIC
# ============================================================
def clone_site():
    print("=" * 60)
    print("  SEDFA Site Cloner - Authorized Pentest Tool")
    print(f"  Source: {BASE_URL}")
    print(f"  Output: {OUTPUT_DIR}/")
    print("=" * 60)

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Initialize with seed pages
    all_pages = set()
    for page in SEED_PAGES:
        full_url = urllib.parse.urljoin(BASE_URL, page)
        all_pages.add(full_url)

    # Track all discovered assets
    all_assets = set()

    # ==============================
    # PHASE 1: Crawl all HTML pages
    # ==============================
    print("\n[PHASE 1] Crawling HTML pages...")
    to_visit = all_pages.copy()
    visited = set()

    while to_visit:
        page_url = to_visit.pop()
        if page_url in visited:
            continue
        visited.add(page_url)

        # Skip non-HTML pages
        parsed = urllib.parse.urlparse(page_url)
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext and ext not in ('', '.html', '.htm'):
            continue

        print(f"  Crawling: {page_url}")
        content, content_type = fetch_url(page_url)
        if content is None:
            print(f"    [SKIP] Could not fetch")
            continue

        # Save the page
        saved = save_file(page_url, content, OUTPUT_DIR)
        if saved:
            print(f"    [SAVED] {saved}")

        # Extract links
        if 'text/html' in content_type:
            pages, assets = extract_links(content, page_url)
            for p in pages:
                if p not in visited:
                    all_pages.add(p)
                    to_visit.add(p)
            all_assets.update(assets)

        # Be polite
        time.sleep(DELAY)

    print(f"\n  Discovered {len(visited)} pages, {len(all_assets)} assets")

    # ==============================
    # PHASE 2: Download all assets
    # ==============================
    print("\n[PHASE 2] Downloading assets (images, CSS, JS, PDFs)...")

    # Also scan downloaded HTML for additional inline assets
    for root, dirs, files in os.walk(OUTPUT_DIR):
        for fname in files:
            if fname.endswith('.html'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        html_content = f.read()
                    # Build the original URL for this page
                    rel_path = os.path.relpath(fpath, OUTPUT_DIR).replace('\\', '/')
                    page_url = urllib.parse.urljoin(BASE_URL, '/' + rel_path)
                    _, page_assets = extract_links(html_content, page_url)
                    all_assets.update(page_assets)
                except Exception as e:
                    print(f"  [WARN] Scanning {fpath}: {e}")

    # Also scan CSS for background images
    for root, dirs, files in os.walk(OUTPUT_DIR):
        for fname in files:
            if fname.endswith('.css'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        css_content = f.read()
                    rel_path = os.path.relpath(fpath, OUTPUT_DIR).replace('\\', '/')
                    css_url = urllib.parse.urljoin(BASE_URL, '/' + rel_path)
                    css_assets = extract_css_urls(css_content, css_url)
                    all_assets.update(css_assets)
                except Exception as e:
                    pass

    # Filter and download unique assets
    unique_assets = set()
    for asset_url in all_assets:
        parsed = urllib.parse.urlparse(asset_url)
        # Only download same-domain or empty-netloc assets
        if parsed.netloc and parsed.netloc != urllib.parse.urlparse(BASE_URL).netloc:
            continue
        # Skip anchors and javascript:
        if not parsed.path or parsed.path.startswith('#') or parsed.path.startswith('javascript:'):
            continue
        # Check if it's actually an asset file
        ext = os.path.splitext(parsed.path)[1].lower()
        if ext in ASSET_EXTENSIONS or not ext:
            unique_assets.add(asset_url)

    # Remove duplicates
    total_assets = len(unique_assets)
    downloaded = 0

    for i, asset_url in enumerate(sorted(unique_assets)):
        # Skip already downloaded (check local path)
        local_path = get_local_path(asset_url, OUTPUT_DIR)
        if os.path.exists(local_path):
            downloaded += 1
            continue

        print(f"  [{i+1}/{total_assets}] Asset: {asset_url}")
        content, content_type = fetch_url(asset_url)
        if content:
            saved = save_file(asset_url, content, OUTPUT_DIR)
            if saved:
                downloaded += 1
                print(f"    [SAVED] {saved}")
            else:
                FAILED_FILES.add(asset_url)
        else:
            print(f"    [FAILED] Could not download")
            FAILED_FILES.add(asset_url)

        time.sleep(DELAY)

    print(f"\n  Downloaded {downloaded}/{total_assets} assets")

    # ==============================
    # PHASE 3: Rewrite HTML for local browsing
    # ==============================
    print("\n[PHASE 3] Rewriting HTML to use local paths...")
    rewritten = 0
    for root, dirs, files in os.walk(OUTPUT_DIR):
        for fname in files:
            if fname.endswith('.html'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        content = f.read()
                    rel_path = os.path.relpath(fpath, OUTPUT_DIR).replace('\\', '/')
                    page_url = urllib.parse.urljoin(BASE_URL, '/' + rel_path)
                    new_content = rewrite_html(content, page_url, OUTPUT_DIR)
                    with open(fpath, 'wb') as f:
                        f.write(new_content)
                    rewritten += 1
                except Exception as e:
                    print(f"  [WARN] Rewriting {fpath}: {e}")

    print(f"  Rewrote {rewritten} HTML files")

    # ==============================
    # SUMMARY
    # ==============================
    print("\n" + "=" * 60)
    print("  CLONE COMPLETE")
    print("=" * 60)
    print(f"  Output directory: {os.path.abspath(OUTPUT_DIR)}")
    print(f"  Pages cloned:    {len(visited)}")
    print(f"  Assets downloaded: {downloaded}")
    print(f"  Failed downloads: {len(FAILED_FILES)}")
    print()
    print("  To view: Open index.html in your browser")
    print("  Or run:  python3 -m http.server 8080 -d sedfa-clone/")
    print()

    # Log failed files
    if FAILED_FILES:
        log_path = os.path.join(OUTPUT_DIR, '_failed_downloads.txt')
        with open(log_path, 'w') as f:
            for url in sorted(FAILED_FILES):
                f.write(url + '\n')
        print(f"  Failed URLs logged to: {log_path}")
    print()


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == '__main__':
    try:
        clone_site()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Cloning stopped by user.")
        print(f"Partial output in: {os.path.abspath(OUTPUT_DIR)}")
        sys.exit(1)