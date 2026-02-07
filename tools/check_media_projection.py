import click
import polars as pl
from pathlib import Path
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
except ImportError as e:
    logging.error(f"androguard is not installed or import failed: {e}")
    logging.error("Please install it using 'uv add androguard' or 'pip install androguard'")
    sys.exit(1)

def check_media_projection_import(apk_path: Path) -> bool:
    """
    Checks if the APK at the given path imports (references) the MediaProjectionManager class.
    """
    try:
        # Suppress Androguard's noisy logging if needed, or just let it be.
        # Androguard can be verbose.
        
        a = APK(str(apk_path))
        target_type = "Landroid/media/projection/MediaProjectionManager;"
        
        for dex_bytes in a.get_all_dex():
            d = DEX(dex_bytes)
            # Check if the target type is in the list of strings in this DEX file
            # get_types() is missing in newer Androguard, but get_strings() returns all strings including types.
            if target_type in d.get_strings():
                return True
                
        return False
    except Exception as e:
        logging.warning(f"Error analyzing {apk_path}: {e}")
        return False

@click.command()
@click.argument("input_csv", type=click.Path(exists=True, path_type=Path))
@click.option("--output_csv", "-o", type=click.Path(path_type=Path), default=Path("media_projection_results.csv"), help="Output CSV file path.")
@click.option("--apk_dir", "-d", type=click.Path(path_type=Path), default=Path("/mnt/storage/data/apks"), help="Directory containing APK files. Defaults to /mnt/storage/data/apks")
def main(input_csv: Path, output_csv: Path, apk_dir: Path):
    """
    Scans APKs listed in INPUT_CSV to check for 'android.media.projection.MediaProjectionManager' usage.
    
    The INPUT_CSV must contain a 'sha256' column.
    """
    
    # Read the input CSV
    try:
        df = pl.read_csv(input_csv)
    except Exception as e:
        logging.error(f"Failed to read CSV {input_csv}: {e}")
        sys.exit(1)

    if "sha256" not in df.columns:
        logging.error(f"Input CSV {input_csv} does not have a 'sha256' column.")
        sys.exit(1)
        
    sha256s = df["sha256"].to_list()
    results = []
    
    logging.info(f"Starting analysis of {len(sha256s)} APKs found in CSV.")
    logging.info(f"Looking for APKs in: {apk_dir}")
    
    processed_count = 0
    
    for sha256 in sha256s:
        apk_path = apk_dir / f"{sha256}.apk"
        
        # Check if file exists (try without extension if .apk missing)
        if not apk_path.exists():
             if (apk_dir / sha256).exists():
                 apk_path = apk_dir / sha256
             else:
                 results.append({
                     "sha256": sha256,
                     "has_media_projection": None,
                     "error": "File not found"
                 })
                 continue
                 
        has_mp = check_media_projection_import(apk_path)
        results.append({
            "sha256": sha256,
            "has_media_projection": has_mp,
            "error": None
        })
        
        processed_count += 1
        if processed_count % 100 == 0:
            logging.info(f"Processed {processed_count}/{len(sha256s)} APKs...")

    # Create DataFrame and save
    result_df = pl.DataFrame(results)
    try:
        result_df.write_csv(output_csv)
        logging.info(f"Analysis complete. Results written to {output_csv}")
    except Exception as e:
        logging.error(f"Failed to write results to {output_csv}: {e}")

if __name__ == "__main__":
    main()
