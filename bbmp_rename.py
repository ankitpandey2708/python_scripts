import os
import re
import pdfplumber

# ============ CONFIGURE THESE ============
FOLDER_PATH = "./pdfs"
DRY_RUN = False  # Set to False to actually rename files
# =========================================


def extract_block_and_flat(pdf_path: str) -> tuple[str | None, str | None]:
    """Extract Block letter and Flat number from a property PDF."""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            full_text = ""
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    full_text += text + "\n"

        if not full_text:
            return None, None

        # Clean out (cid:XXXX) font encoding artifacts that contain digits
        clean_text = re.sub(r'\(cid:\d+\)', '', full_text)

        # --- Extract BLOCK letter ---
        # Try "Block A" or "BLOCK A" (letter right after BLOCK)
        block_match = re.search(r"\bBlock\s+([A-Z])\b", clean_text, re.IGNORECASE)

        # --- Extract Flat number (could be numeric like 206 or alphanumeric like G03) ---
        # Try same line: "Flat No 206" or "Flat No G03"
        flat_match = re.search(r"Flat\s*No\.?\s*([A-Z]?\d+)", clean_text, re.IGNORECASE)
        if not flat_match:
            # Flat No on one line, number on next (with possible Kannada/junk text in between)
            flat_match = re.search(
                r"Flat\s*No\.?\s*\n[^\n]*?([A-Z]?\d{2,4})\b", clean_text, re.IGNORECASE
            )
        if not flat_match:
            # Broader search near "Flat No"
            flat_match = re.search(
                r"Flat\s*No\.?[\s\S]{0,40}?\b([A-Z]?\d{2,4})\b", clean_text, re.IGNORECASE
            )

        block = block_match.group(1).upper() if block_match else None
        flat_no = flat_match.group(1) if flat_match else None

        # Convert ground floor: G03 → 003, G12 → 012
        if flat_no and flat_no[0].upper() == "G":
            flat_no = "0" + flat_no[1:]

        return block, flat_no

    except Exception as e:
        print(f"  ⚠ Error reading {os.path.basename(pdf_path)}: {e}")
        return None, None


def main():
    if not os.path.isdir(FOLDER_PATH):
        print(f"❌ Folder not found: {FOLDER_PATH}")
        return

    pdf_files = [f for f in os.listdir(FOLDER_PATH) if f.lower().endswith(".pdf")]

    if not pdf_files:
        print(f"No PDF files found in {FOLDER_PATH}")
        return

    print(f"Found {len(pdf_files)} PDF files in {FOLDER_PATH}")
    print(f"Mode: {'DRY RUN (preview only)' if DRY_RUN else '🔴 LIVE - will rename files'}\n")

    renamed = 0
    skipped = 0
    errors = 0

    for filename in sorted(pdf_files):
        filepath = os.path.join(FOLDER_PATH, filename)
        base_name = os.path.splitext(filename)[0]

        # Skip already-renamed files (contain underscore)
        if "_" in base_name:
            print(f"  ⏭ {filename} → skipped (already renamed)")
            skipped += 1
            continue

        block, flat_no = extract_block_and_flat(filepath)

        if block and flat_no:
            base_name = os.path.splitext(filename)[0]
            new_name = f"{block}{flat_no}_{base_name}.pdf"
            new_path = os.path.join(FOLDER_PATH, new_name)

            # Handle duplicates
            if os.path.exists(new_path) and new_path != filepath:
                counter = 2
                while os.path.exists(new_path):
                    new_name = f"{block}{flat_no}_{counter}.pdf"
                    new_path = os.path.join(FOLDER_PATH, new_name)
                    counter += 1

            if filename == new_name:
                print(f"  ⏭ {filename} → already named correctly")
                skipped += 1
                continue

            print(f"  ✅ {filename} → {new_name}")

            if not DRY_RUN:
                os.rename(filepath, new_path)

            renamed += 1
        else:
            missing = []
            if not block:
                missing.append("Block")
            if not flat_no:
                missing.append("Flat No")
            print(f"  ⏭ {filename} → skipped (couldn't find: {', '.join(missing)})")
            skipped += 1

    print(f"\n{'=' * 40}")
    print(f"Renamed: {renamed} | Skipped: {skipped} | Errors: {errors}")
    if DRY_RUN and renamed > 0:
        print(f"\n👆 This was a DRY RUN. Set DRY_RUN = False in the script to actually rename.")


if __name__ == "__main__":
    main()
