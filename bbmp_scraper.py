"""
BBMP E-Aasthi Property Scraper
--------------------------------
Flow:
1. Open browser, load search page
2. Select district + ULB, enter owner name, click search
3. Collect all asset numbers across all pages
4. For each asset: click → handle payment alert → get PDF URL → download
5. Skip already-downloaded PDFs (resumable)
"""

import time
import os
import re
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Config ────────────────────────────────────────────────────────────────────
OUTPUT_DIR   = "./pdfs"
BASE_URL     = "https://bbmpeaasthi.karnataka.gov.in/office/frmSearchProperties.aspx"
PDF_BASE     = "https://bbmpeaasthi.karnataka.gov.in/office/"
OWNER_NAME   = "A P ಕೃ"
DISTRICT_VAL = "999"   # Bangalore City
ULB_VAL      = "558"   # Bangalore North

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ── Driver setup ─────────────────────────────────────────────────────────────

def setup_driver():
    options = webdriver.ChromeOptions()
    options.add_argument("--ignore-certificate-errors")
    options.add_argument("--disable-web-security")
    # options.add_argument("--headless")  # uncomment to run without browser window
    return webdriver.Chrome(options=options)


# ── Search & navigation ───────────────────────────────────────────────────────

def wait_for_grid(driver, timeout=15):
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "table[id*='GridView4']"))
    )


def do_search(driver, owner=OWNER_NAME):
    """Full search: load page → select district → select ULB → enter name → click search."""
    driver.get(BASE_URL)
    wait = WebDriverWait(driver, 15)

    # Select district — triggers ULB dropdown to populate
    district_dd = wait.until(EC.presence_of_element_located(
        (By.ID, "ctl00_ContentPlaceHolder1_ddlDISTRICTCODE")
    ))
    Select(district_dd).select_by_value(DISTRICT_VAL)

    # Wait for ULB to populate
    wait.until(lambda d: len(Select(
        d.find_element(By.ID, "ctl00_ContentPlaceHolder1_ddlULBCODE")
    ).options) > 1)

    Select(driver.find_element(
        By.ID, "ctl00_ContentPlaceHolder1_ddlULBCODE")
    ).select_by_value(ULB_VAL)

    # Enter owner name
    owner_field = driver.find_element(By.ID, "ctl00_ContentPlaceHolder1_CtrlOwner")
    owner_field.clear()
    owner_field.send_keys(owner)

    # Click search
    driver.find_element(By.ID, "ctl00_ContentPlaceHolder1_BtnSearch").click()
    wait_for_grid(driver)


def get_total_pages(driver):
    try:
        pager = driver.find_elements(By.CSS_SELECTOR, "tr.PagerStyle td a")
        nums = [int(a.text) for a in pager if a.text.strip().isdigit()]
        if not nums:
            all_links = driver.find_elements(
                By.CSS_SELECTOR, "table[id*='GridView4'] tr:last-child a"
            )
            nums = [int(a.text) for a in all_links
                    if a.text.strip().isdigit() and int(a.text) < 100]
        return max(nums) if nums else 1
    except:
        return 1


def navigate_to_page(driver, page_num):
    wait = WebDriverWait(driver, 15)
    pager_links = driver.find_elements(By.CSS_SELECTOR, "tr.PagerStyle td a")
    if not pager_links:
        pager_links = driver.find_elements(
            By.CSS_SELECTOR, "table[id*='GridView4'] tr:last-child a"
        )
    for link in pager_links:
        if link.text.strip() == str(page_num):
            driver.execute_script("arguments[0].scrollIntoView(true);", link)
            time.sleep(0.3)
            driver.execute_script("arguments[0].click();", link)
            wait_for_grid(driver)
            time.sleep(0.5)
            return
    print(f"  Page {page_num} link not found")


# ── Asset extraction ──────────────────────────────────────────────────────────

def extract_assets_from_page(driver):
    """Only grab links that contain lblPROPERTYID — excludes pagination links."""
    assets = []
    grid = driver.find_element(By.CSS_SELECTOR, "table[id*='GridView4']")
    links = grid.find_elements(By.TAG_NAME, "a")
    for link in links:
        href = link.get_attribute("href") or ""
        if "lblPROPERTYID" not in href:
            continue
        match = re.search(r"__doPostBack\('(.+?)','(.*?)'\)", href)
        if match:
            assets.append({
                "asset_number": link.text.strip(),
                "event_target": match.group(1),
                "event_arg":    match.group(2),
            })
    return assets


# ── PDF handling ──────────────────────────────────────────────────────────────

def get_pdf_url_for_asset(driver, asset):
    """
    Click asset via postback.
    Returns PDF URL string, or None if payment required / not found.
    """
    wait = WebDriverWait(driver, 15)

    driver.execute_script(
        f"__doPostBack('{asset['event_target']}', '{asset['event_arg']}')"
    )

    # Handle payment alert before anything else
    try:
        WebDriverWait(driver, 3).until(EC.alert_is_present())
        alert = driver.switch_to.alert
        alert.dismiss()  # Cancel — don't go to payment page
        print(f"  ⚠ Requires payment (Rs 125) — skipped")
        return None
    except:
        pass  # no alert, continue

    wait.until(EC.url_contains("frmForm3_2View"))
    time.sleep(2)

    match = re.search(r'TempFiles/[^"\'<>\s]+\.pdf', driver.page_source)
    if match:
        return PDF_BASE + match.group(0)

    return None


def build_requests_session(driver):
    """Copy browser cookies into requests session for PDF download."""
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    for cookie in driver.get_cookies():
        s.cookies.set(cookie["name"], cookie["value"])
    return s


def download_pdf(session, asset_number, pdf_url):
    r = session.get(pdf_url, verify=False)
    if "application/pdf" in r.headers.get("Content-Type", "") and len(r.content) > 5000:
        path = os.path.join(OUTPUT_DIR, f"{asset_number}.pdf")
        with open(path, "wb") as f:
            f.write(r.content)
        print(f"  ✓ {asset_number}.pdf  [password: {asset_number}]")
        return True
    print(f"  ✗ {asset_number}: bad response ({r.headers.get('Content-Type')})")
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    driver = setup_driver()
    failed = []
    paid_skip = []

    try:
        # ── Phase 1: Collect all asset numbers ───────────────────────────────
        print("\n=== Phase 1: Collecting assets ===")
        do_search(driver)

        total_pages = get_total_pages(driver)
        print(f"Total pages: {total_pages}")

        all_assets = []
        all_assets.extend(extract_assets_from_page(driver))
        print(f"  Page 1: {len(all_assets)} assets")

        for page in range(2, total_pages + 1):
            navigate_to_page(driver, page)
            page_assets = extract_assets_from_page(driver)
            all_assets.extend(page_assets)
            print(f"  Page {page}: {len(page_assets)} assets")

        print(f"\nTotal: {len(all_assets)} assets")

        # ── Phase 2: Download PDFs ────────────────────────────────────────────
        print("\n=== Phase 2: Downloading PDFs ===")
        requests_session = build_requests_session(driver)

        # Single search to start — stay on results page
        do_search(driver)
        current_page = 1

        for i, asset in enumerate(all_assets):
            needed_page = (i // 25) + 1
            print(f"[{i+1}/{len(all_assets)}] {asset['asset_number']}...")

            # Skip if already downloaded
            if any(asset['asset_number'] in fname for fname in os.listdir(OUTPUT_DIR)):
                print(f"  ⏭ Already exists, skipping")
                # Make sure we're on the right page for next asset
                if needed_page != current_page:
                    if "frmSearchProperties" not in driver.current_url:
                        do_search(driver)
                    navigate_to_page(driver, needed_page)
                    current_page = needed_page
                continue

            for attempt in range(1, 4):
                try:
                    # Navigate back to search results if we left
                    if "frmSearchProperties" in driver.current_url:
                        if needed_page != current_page:
                            navigate_to_page(driver, needed_page)
                            current_page = needed_page
                    else:
                        driver.back()
                        WebDriverWait(driver, 10).until(
                            EC.presence_of_element_located(
                                (By.CSS_SELECTOR, "table[id*='GridView4']")
                            )
                        )
                        if needed_page != current_page:
                            navigate_to_page(driver, needed_page)
                            current_page = needed_page

                    pdf_url = get_pdf_url_for_asset(driver, asset)

                    if pdf_url is None:
                        # Payment required — already printed, don't retry
                        paid_skip.append(asset["asset_number"])
                        break

                    requests_session = build_requests_session(driver)
                    success = download_pdf(requests_session, asset["asset_number"], pdf_url)
                    if success:
                        break

                except Exception as e:
                    print(f"  ✗ Error attempt {attempt}: {e}")
                    time.sleep(attempt * 2)
                    # Full reset on error
                    do_search(driver)
                    if needed_page > 1:
                        navigate_to_page(driver, needed_page)
                    current_page = needed_page
            else:
                failed.append(asset["asset_number"])
                print(f"  ✗✗ GAVE UP on {asset['asset_number']}")

            time.sleep(0.5)

    finally:
        driver.quit()

    # ── Summary ───────────────────────────────────────────────────────────────
    total = len(all_assets)
    skipped_existing = total - len(failed) - len(paid_skip) - \
                       sum(1 for a in all_assets if not os.path.exists(
                           os.path.join(OUTPUT_DIR, f"{a['asset_number']}.pdf")))
    downloaded = len([a for a in all_assets
                      if os.path.exists(os.path.join(OUTPUT_DIR, f"{a['asset_number']}.pdf"))])

    print(f"\n=== Done ===")
    print(f"✓ Downloaded : {downloaded}")
    print(f"⏭ Skipped   : {len(paid_skip)} (payment required)")
    print(f"✗ Failed     : {len(failed)}")

    if paid_skip:
        paid_path = os.path.join(OUTPUT_DIR, "payment_required.txt")
        with open(paid_path, "w") as f:
            f.write("\n".join(paid_skip))
        print(f"\nPayment-required list → {paid_path}")

    if failed:
        failed_path = os.path.join(OUTPUT_DIR, "failed_assets.txt")
        with open(failed_path, "w") as f:
            f.write("\n".join(failed))
        print(f"Failed list → {failed_path}")


if __name__ == "__main__":
    main()
