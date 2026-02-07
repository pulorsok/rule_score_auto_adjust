import argparse
import csv
import os
import sys
from pathlib import Path
from tqdm import tqdm

# Ensure we can import from data_preprocess
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from data_preprocess.virus_total import get_threat_label
except ImportError:
    # Fallback if running from root
    sys.path.append(os.getcwd())
    from data_preprocess.virus_total import get_threat_label

def is_sha256(s):
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def process_single_hash(sha256):
    labels = get_threat_label(sha256)
    return {
        "sha256": sha256,
        **labels
    }

def process_csv(input_path, output_path, column_name):
    results = []
    
    # Read input
    print(f"Reading from {input_path}...")
    try:
        with open(input_path, 'r', encoding='utf-8-sig') as f: # utf-8-sig to handle BOM
            reader = csv.DictReader(f)
            
            # Check if column exists, if not, try case insensitive search
            target_col = column_name
            if column_name not in reader.fieldnames:
                # Try finding a column that matches case-insensitive
                found = False
                for col in reader.fieldnames:
                    if col.lower() == column_name.lower():
                        target_col = col
                        found = True
                        break
                
                if not found:
                    # If strictly 'sha256' was requested but not found, check if there is only one column and it looks like a hash? 
                    # Or just try 'SHA256' or 'hash'
                    possible_cols = [c for c in reader.fieldnames if 'sha256' in c.lower() or 'hash' in c.lower()]
                    if possible_cols:
                        print(f"Warning: Column '{column_name}' not found. Using '{possible_cols[0]}' instead.")
                        target_col = possible_cols[0]
                    else:
                        print(f"Error: Column '{column_name}' not found in {input_path}")
                        print(f"Available columns: {reader.fieldnames}")
                        return

            rows = list(reader)
            
            print(f"Processing {len(rows)} items from {input_path}...")
            
            for row in tqdm(rows):
                sha256 = row.get(target_col, "").strip()
                if not sha256:
                    continue
                    
                print("Processing SHA256:", sha256)
                labels = get_threat_label(sha256)
                results.append({
                    "sha256": sha256,
                    **labels
                })

    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    # Write output
    if not results:
        print("No results to write.")
        return

    fieldnames = ["sha256", "major_threat_label", "middle_threat_label", "minor_threat_label"]
    
    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        
        print(f"Results written to {output_path}")
    except Exception as e:
        print(f"Error writing output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Get VirusTotal labels for SHA256 hashes.")
    parser.add_argument("target", help="SHA256 hash or path to CSV file")
    parser.add_argument("-o", "--output", help="Output CSV file path. Defaults to [input_filename]_labeled.csv or vt_label_output.csv", default=None)
    parser.add_argument("-c", "--column", help="Column name containing SHA256 hashes in the input CSV", default="sha256")
    
    args = parser.parse_args()
    
    target = args.target.strip()
    
    if os.path.isfile(target):
        # It's a file
        if args.output is None:
            input_path = Path(target)
            output_path = input_path.with_name(f"{input_path.stem}_labeled.csv")
        else:
            output_path = args.output
            
        process_csv(target, output_path, args.column)
        
    elif is_sha256(target):
        # It's a hash
        result = process_single_hash(target)
        print("Result:")
        print(f"SHA256: {result['sha256']}")
        print(f"Major Label: {result['major_threat_label']}")
        print(f"Middle Label: {result['middle_threat_label']}")
        print(f"Minor Label: {result['minor_threat_label']}")
        
        if args.output:
            with open(args.output, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=result.keys())
                writer.writeheader()
                writer.writerow(result)
            print(f"Result written to {args.output}")

    else:
        print(f"Error: '{target}' is neither a valid file nor a valid SHA256 hash.")

if __name__ == "__main__":
    main()
