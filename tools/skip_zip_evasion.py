# Credit to https://shindan.io/blog/godfather-part-1-a-multistage-dropper

import zipfile
from io import BytesIO
import sys
import os

def detricks_apk(apk_path, output_path):
    new_apk = BytesIO()

    with zipfile.ZipFile(apk_path, 'r') as zin:
        with zipfile.ZipFile(new_apk, 'w', zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                item.flag_bits = 0
                item.extra = b''

                data = zin.read(item.filename)
                zout.writestr(item, data)

    with open(output_path, 'wb') as f:
        f.write(new_apk.getvalue())

    print(f"-> New APK written to: {output_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python normalize_apk.py tricked_sampke.apk")
        sys.exit(1)

    input_apk = sys.argv[1]
    output_apk = f"normalized_{os.path.basename(input_apk)}"

    detricks_apk(input_apk, output_apk)
