import os
from pathlib import Path
import click
import polars as pl
from tqdm import tqdm
import data_preprocess.apk as apk_lib
import dotenv

dotenv.load_dotenv()


@click.command()
@click.option(
    "--apk_list",
    "-a",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    multiple=True,
    help="List of APKs to process.",
)
def download_apk_from_list(apk_list: list[Path]) -> None:
    """
    Process a list of APKs and save them to the folder specified by the environment variable APK_FOLDER.

    Example usage:
    uv run tools/download_apk.py -a data/lists/family/droidkungfu_test.csv
    """

    sha256s = pl.concat([pl.read_csv(list_path, columns=["sha256"]) for list_path in apk_list], how="vertical")

    for sha256 in tqdm(sha256s.to_series(), desc="Downloading APKs"):
        apk_lib.download(sha256, use_cache=True, dry_run=False)

    print(f"Downloaded {len(sha256s)} APKs to {os.getenv("APK_FOLDER")}")


if __name__ == "__main__":
    download_apk_from_list()
