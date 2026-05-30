#!/usr/bin/env python3
"""
OneSEDFA Site Cloner - Authorized Penetration Testing Tool
Clones https://www.onesedfa.org.za/en-za/ (React SPA on Azure Static Web Apps)
Usage: python3 clone_onesedfa.py
"""

import os
import re
import sys
import time
import subprocess
import urllib.parse
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

# ============================================================
# CONFIGURATION
# ============================================================
BASE_URL = "https://www.onesedfa.org.za"
OUTPUT_DIR = "onesedfa-clone"
DELAY = 0.3
MAX_RETRIES = 3
TIMEOUT = 30
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# Known assets discovered from the homepage
KNOWN_ASSETS = [
    "/assets/hero-entrepreneurs-1718w-sklPPnOT.jpg",
    "/assets/logo-DaRjssx1.png",
]

# SPA routes — Azure SWA serves index.html for all of these
SPA_ROUTES = [
    "/en-za/",
    "/en-za/index.html",
]

FAILED_FILES = []


def fetch_url(url):
    """Fetch a URL with retries and URL encoding."""
    for attempt in range(MAX_RETRIES):
        try:
            # URL-encode the path to handle any special chars
            parsed = urllib.parse.urlparse(url)
            clean_path = urllib.parse.quote(parsed.path, safe='/:@!$&\'()*+,;=-._~%')
            clean_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, clean_path,
                parsed.params, parsed.query, parsed.fragment
            ))

            req = Request(clean_url, headers={
                'User-Agent': USER_AGENT,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
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
            print(f"  [WARN] {type(e).__name__}: {e} (attempt {attempt+1}/{MAX_RETRIES})")
            time.sleep(DELAY)
    return None, 'text/html'


def save_file(url, content, output_dir):
    """Save fetched content preserving path structure."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path
    
    if path == '' or path.endswith('/'):
        path = os.path.join(path, 'index.html')
    
    local_path = os.path.join(output_dir, path.lstrip('/'))
    local_path = urllib.parse.unquote(local_path)
    if '?' in local_path:
        local_path = local_path.split('?')[0]
    local_path = os.path.normpath(local_path)
    
    dir_path = os.path.dirname(local_path)
    if not dir_path:
        dir_path = output_dir
        local_path = os.path.join(output_dir, os.path.basename(local_path))
    
    os.makedirs(dir_path, exist_ok=True)
    
    try:
        if isinstance(content, str):
            content = content.encode('utf-8')
        with open(local_path, 'wb') as f:
            f.write(content)
        return local_path
    except Exception as e:
        print(f"  [ERROR] Saving {local_path}: {e}")
        return None


def extract_html_source(url):
    """
    For SPA sites (React/Angular/Vue), we need the raw HTML source 
    before JavaScript renders it. Use curl/wget as subprocess to get 
    the actual server-rendered response.
    """
    try:
        result = subprocess.run(
            ['curl', '-s', '-L', '-A', USER_AGENT, url],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout.encode('utf-8')
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    # Fallback: try wget
    try:
        result = subprocess.run(
            ['wget', '-q', '-O', '-', '--user-agent=' + USER_AGENT, url],
            capture_output=True, timeout=30
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    # Final fallback: use urlopen
    content, _ = fetch_url(url)
    return content


def extract_assets_from_html(html_content, base_url):
    """Extract JS, CSS, images, fonts from raw HTML source."""
    assets = set()
    if not html_content:
        return assets
    
    text = html_content.decode('utf-8', errors='replace')
    
    # <script src="...">
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    # <link href="..."> (CSS, favicon, preload, etc)
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    # <img src="...">
    for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\']', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    # <img srcset="...">
    for m in re.finditer(r'<img[^>]+srcset=["\']([^"\']+)["\']', text):
        for part in m.group(1).split(','):
            src = part.strip().split(' ')[0]
            if src:
                full = urllib.parse.urljoin(base_url, src)
                assets.add(full)
    
    # <source src="...">
    for m in re.finditer(r'<source[^>]+src=["\']([^"\']+)["\']', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    # <source srcset="...">
    for m in re.finditer(r'<source[^>]+srcset=["\']([^"\']+)["\']', text):
        for part in m.group(1).split(','):
            src = part.strip().split(' ')[0]
            if src:
                full = urllib.parse.urljoin(base_url, src)
                assets.add(full)
    
    # inline style: url(...)
    for m in re.finditer(r'url\(["\']?([^"\'\)]+)["\']?\)', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    # <meta property="og:image" content="...">
    for m in re.finditer(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    # favicon <link rel="icon" ...>
    for m in re.finditer(r'<link[^>]+rel=["\'](?:icon|apple-touch-icon|shortcut icon)["\'][^>]+href=["\']([^"\']+)["\']', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    return assets


def extract_assets_from_css(css_content, base_url):
    """Extract URLs from CSS."""
    assets = set()
    if not css_content:
        return assets
    
    text = css_content.decode('utf-8', errors='replace')
    
    # url() references
    for m in re.finditer(r'url\(["\']?([^"\'\)]+)["\']?\)', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        # Filter out data URIs
        if not full.startswith('data:'):
            assets.add(full)
    
    # @import
    for m in re.finditer(r'@import\s+["\']([^"\']+)["\']', text):
        full = urllib.parse.urljoin(base_url, m.group(1))
        assets.add(full)
    
    return assets


def clone_site():
    print("=" * 60)
    print("  OneSEDFA Site Cloner - Authorized Pentest Tool")
    print(f"  Source: {BASE_URL}")
    print(f"  Output: {OUTPUT_DIR}/")
    print("  [SPA Mode] Single Page Application (React on Azure SWA)")
    print("=" * 60)
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # ==============================
    # PHASE 1: Fetch the raw index.html
    # ==============================
    print("\n[PHASE 1] Fetching SPA entry point (index.html)...")
    
    index_url = BASE_URL + "/en-za/"
    print(f"  Fetching: {index_url}")
    
    # Try to get raw HTML source (before JS rendering)
    html_content = extract_html_source(index_url)
    
    if not html_content:
        print("  [ERROR] Could not fetch the homepage!")
        sys.exit(1)
    
    # Save index.html
    saved = save_file(index_url, html_content, OUTPUT_DIR)
    if saved:
        print(f"  [SAVED] {saved} ({len(html_content)} bytes)")
    
    # Also save a copy at the root level for convenience
    root_index = os.path.join(OUTPUT_DIR, 'index.html')
    if saved and saved != root_index:
        with open(root_index, 'wb') as f:
            f.write(html_content)
        print(f"  [SAVED] {root_index}")
    
    # Also create the SPA fallback — copy of index.html for routes
    # Azure SWA: all routes serve the same index.html
    print("\n  Creating SPA route fallbacks...")
    for route in SPA_ROUTES:
        if route != "/en-za/":
            route_path = os.path.join(OUTPUT_DIR, route.lstrip('/'))
            os.makedirs(os.path.dirname(route_path), exist_ok=True)
            # Don't overwrite the actual fetched page
            if not os.path.exists(route_path):
                with open(route_path, 'wb') as f:
                    f.write(html_content)
    
    # ==============================
    # PHASE 2: Extract all asset references from HTML
    # ==============================
    print("\n[PHASE 2] Extracting asset references from HTML...")
    
    all_assets = extract_assets_from_html(html_content, index_url)
    
    # Add known assets manually
    for asset_path in KNOWN_ASSETS:
        all_assets.add(BASE_URL + asset_path)
    
    print(f"  Found {len(all_assets)} asset references")
    
    # ==============================
    # PHASE 3: Download all assets
    # ==============================
    print("\n[PHASE 3] Downloading assets...")
    
    # Filter to same-domain only
    site_domain = urllib.parse.urlparse(BASE_URL).netloc
    our_assets = set()
    for a in all_assets:
        parsed = urllib.parse.urlparse(a)
        if parsed.netloc == site_domain or parsed.netloc == '':
            our_assets.add(a)
    
    # Also include common Azure SWA CDN assets for the page to render
    # These are served from Azure's CDN
    cdn_assets = {a for a in all_assets if 'appservice.azureedge.net' in a}
    our_assets.update(cdn_assets)
    
    total = len(our_assets)
    downloaded = 0
    
    for i, asset_url in enumerate(sorted(our_assets), 1):
        local_path = None
        
        # Check if already downloaded
        parsed = urllib.parse.urlparse(asset_url)
        path = parsed.path
        if path.endswith('/'):
            path = path + 'index.html'
        check_path = os.path.join(OUTPUT_DIR, path.lstrip('/'))
        check_path = urllib.parse.unquote(check_path)
        if os.path.exists(check_path):
            downloaded += 1
            continue
        
        print(f"  [{i}/{total}] {os.path.basename(parsed.path)}")
        content, content_type = fetch_url(asset_url)
        if content:
            saved = save_file(asset_url, content, OUTPUT_DIR)
            if saved:
                downloaded += 1
                print(f"    [SAVED] {saved}")
            else:
                FAILED_FILES.append(asset_url)
        else:
            FAILED_FILES.append(asset_url)
            print(f"    [FAILED] Could not download")
        
        time.sleep(DELAY)
    
    # ==============================
    # PHASE 4: Scan downloaded CSS for more assets
    # ==============================
    print("\n[PHASE 4] Scanning CSS for additional assets...")
    css_assets_found = set()
    
    for root, dirs, files in os.walk(OUTPUT_DIR):
        for fname in files:
            if fname.endswith('.css'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        css_content = f.read()
                    rel_path = os.path.relpath(fpath, OUTPUT_DIR).replace('\\', '/')
                    css_url = urllib.parse.urljoin(BASE_URL, '/' + rel_path)
                    css_assets = extract_assets_from_css(css_content, css_url)
                    
                    # Filter to same-domain
                    for a in css_assets:
                        parsed = urllib.parse.urlparse(a)
                        if parsed.netloc == site_domain or parsed.netloc == '':
                            css_assets_found.add(a)
                except Exception:
                    pass
    
    print(f"  Found {len(css_assets_found)} additional assets from CSS")
    
    # Download CSS-discovered assets
    for i, asset_url in enumerate(sorted(css_assets_found), 1):
        local_path = None
        parsed = urllib.parse.urlparse(asset_url)
        path = parsed.path
        check_path = os.path.join(OUTPUT_DIR, path.lstrip('/'))
        check_path = urllib.parse.unquote(check_path)
        if os.path.exists(check_path):
            continue
        
        print(f"  [{i}] CSS asset: {os.path.basename(parsed.path)}")
        content, content_type = fetch_url(asset_url)
        if content:
            saved = save_file(asset_url, content, OUTPUT_DIR)
            if saved:
                downloaded += 1
            else:
                FAILED_FILES.append(asset_url)
        else:
            FAILED_FILES.append(asset_url)
        
        time.sleep(DELAY)
    
    # ==============================
    # PHASE 5: Rewrite HTML for local browsing
    # ==============================
    print("\n[PHASE 5] Rewriting HTML for local browsing...")
    
    for root, dirs, files in os.walk(OUTPUT_DIR):
        for fname in files:
            if fname.endswith('.html'):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        content = f.read()
                    
                    text = content.decode('utf-8', errors='replace')
                    
                    # Replace absolute asset URLs with local relative paths
                    # assets/ → relative path
                    rel_path = os.path.relpath(fpath, OUTPUT_DIR).replace('\\', '/')
                    depth = rel_path.count('/')
                    
                    prefix = ''
                    if depth > 0:
                        prefix = '../' * depth
                    
                    # Replace https://www.onesedfa.org.za/assets/ with local path
                    text = text.replace(
                        'https://www.onesedfa.org.za/assets/',
                        prefix + 'assets/'
                    )
                    text = text.replace(
                        'https://www.onesedfa.org.za/',
                        prefix
                    )
                    
                    # Also fix Azure CDN URLs (keep as-is since they're external)
                    # The app service CDN icons are decorative — they'll still work online
                    
                    with open(fpath, 'wb') as f:
                        f.write(text.encode('utf-8'))
                    
                except Exception as e:
                    print(f"  [WARN] Rewriting {fpath}: {e}")
    
    print(f"  Rewrote HTML files")
    
    # ==============================
    # SUMMARY
    # ==============================
    print("\n" + "=" * 60)
    print("  CLONE COMPLETE")
    print("=" * 60)
    print(f"  Output directory: {os.path.abspath(OUTPUT_DIR)}")
    print(f"  Assets downloaded: {downloaded}")
    print(f"  Failed downloads: {len(FAILED_FILES)}")
    print()
    print("  NOTE: This is a Single Page Application (React).")
    print("  To view it properly, serve with a local HTTP server:")
    print()
    print("    python3 -m http.server 8080 -d onesedfa-clone/")
    print()
    print("  Then open http://localhost:8080/en-za/")
    print()
    print("  The SPA routes (women-fund, construction-fund, etc.)")
    print("  work via JavaScript routing and won't render by")
    print("  double-clicking index.html — you need the HTTP server.")
    print()
    
    if FAILED_FILES:
        log_path = os.path.join(OUTPUT_DIR, '_failed_downloads.txt')
        with open(log_path, 'w') as f:
            for url in sorted(FAILED_FILES):
                f.write(url + '\n')
        print(f"  Failed URLs logged to: {log_path}")
    print()


if __name__ == '__main__':
    try:
        clone_site()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Stopped by user.")
        sys.exit(1)