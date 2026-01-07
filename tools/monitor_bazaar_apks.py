import polars as pl
import requests
from datetime import datetime
from pathlib import Path
import io
import click
from pathvalidate import sanitize_filename

@click.command()
def monitor_bazaar_apks():
    """
    Downloads the latest samples from MalwareBazaar, filters for APKs,
    and organizes them by time and family signature.
    """
    # 1. Download CSV
    url = "https://bazaar.abuse.ch/export/csv/recent/"
    print(f"Downloading from {url}...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        print("Download complete.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        return

    # Save raw downloaded content
    raw_dir = Path("research/monitor/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = raw_dir / f"{timestamp}.csv"
    
    print(f"Saving raw downloaded content to {raw_path}")
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(response.text)

    # 2. Pre-process CSV content to handle commented header
    lines = response.text.splitlines()
    if len(lines) < 9:
        print("Downloaded CSV is empty or too short.")
        return

    # The header is on line 8 (0-indexed) and is commented.
    header_line = lines[8].lstrip("# ")
    data_lines = lines[9:]

    # Check if data is empty. The file might just contain headers.
    if not data_lines:
        print("No data rows in the downloaded CSV.")
        return

    csv_content = "\n".join([header_line] + data_lines)

    # 3. Read with polars
    try:
        df = pl.read_csv(io.StringIO(csv_content))
    except Exception as e:
        print(f"Error reading CSV with polars: {e}")
        return

    # 4. Filter for APKs
    apk_df = df.filter(pl.col("file_type_guess").str.contains("apk", literal=True))

    if apk_df.is_empty():
        print("No new APKs found.")
        return

    print(f"Found {len(apk_df)} new APKs.")

    # 4. Save by time
    bytime_dir = Path("research/monitor/bytime")
    bytime_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    bytime_path = bytime_dir / f"{timestamp}.csv"
    
    print(f"Saving all found APKs to {bytime_path}")
    apk_df.write_csv(bytime_path)

    # 5. Group by signature and append
    byfamily_dir = Path("research/monitor/byfamily")
    byfamily_dir.mkdir(parents=True, exist_ok=True)

    # Coalesce null signatures to "n/a" and strip quotes before grouping
    apk_df = apk_df.with_columns(
        pl.col("signature").fill_null("n/a").str.strip_chars('" ')
    )

    grouped = apk_df.group_by("signature")

    print(f"Grouping by signature and appending to files in {byfamily_dir}...")
    for (signature,), group_df in grouped:
        safe_signature = sanitize_filename(signature)
        family_csv_path = byfamily_dir / f"{safe_signature}.csv"
        
        print(f"Processing signature: {signature} ({len(group_df)} samples) -> {family_csv_path}")

        try:
            if family_csv_path.exists():
                # Append without header
                with family_csv_path.open("ab") as f:
                    group_df.write_csv(f, include_header=False)
            else:
                # Write with header
                group_df.write_csv(family_csv_path, include_header=True)
        except Exception as e:
            print(f"Error writing to {family_csv_path}: {e}")
            
    print("Done.")

if __name__ == "__main__":
    monitor_bazaar_apks()
