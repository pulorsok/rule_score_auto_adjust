import click
import polars as pl
import requests
from pathlib import Path
import enum
import os
from diskcache import FanoutCache
import dotenv

dotenv.load_dotenv()

cache = FanoutCache(f"{os.getenv("CACHE_FOLDER")}/apk_download_cache")


class APK_DOWNLOAD_STATUS(enum.Enum):
    SUCCESS = 0
    FAILED = 1
    NOT_TRIED = 2


APK_SCHEMA = {
    "sha256": pl.String,
    "is_malicious": pl.Int32,
}


def read_csv(apk_list: str) -> pl.DataFrame:
    return pl.read_csv(
        apk_list,
        schema_overrides=APK_SCHEMA,
        has_header=True,
        columns=list(APK_SCHEMA.keys()),
    )


def write_csv(apk_list: pl.DataFrame, output_path: str) -> Path:
    apk_list.write_csv(output_path, has_header=True)
    return Path(output_path).resolve()


_PROJECT_ROOT = Path(__file__).parent.parent

def _get_path(sha256: str) -> Path:
    folder = os.getenv("APK_FOLDER") or str(_PROJECT_ROOT / "data" / "apks")
    return (Path(folder) / f"{sha256}.apk").resolve()


def __download(
    sha256: str,
    apiKey: str,
    output_path: Path,
    force: bool = False,
) -> Path:
    url = f"https://androzoo.uni.lu/api/download?sha256={sha256}&apikey={apiKey}"

    if output_path.exists() and not force:
        return output_path.resolve()

    try:
        response = requests.get(url, timeout=300)
        response.raise_for_status()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(response.content)

        return output_path.resolve()
    except Exception as e:
        if output_path.exists():
            output_path.unlink()
        raise Exception(f"Failed to download apk {sha256}: {str(e)}")


def download(sha256: str, use_cache: bool = True, dry_run: bool = False) -> Path | None:
    if sha256 not in cache or not use_cache:
        apk_path = _get_path(sha256)
        if apk_path.exists():
            # Migrating: Check if apk exists in the apk folder
            # print(f"Find {sha256} exists. Add it into cache")
            cache.set(sha256, APK_DOWNLOAD_STATUS.SUCCESS)
        elif not dry_run:
            # Download APK
            try:
                # print(f"Downloading {sha256}")
                __download(
                    sha256,
                    apiKey=os.getenv("ANDROZOO_API_KEY", "NOT_DEFINED"),
                    output_path=_get_path(sha256),
                    force=use_cache,
                )
                cache.set(sha256, APK_DOWNLOAD_STATUS.SUCCESS)
            except Exception as e:
                print(f"Error downloading {sha256}: {e}")
                cache.set(sha256, APK_DOWNLOAD_STATUS.FAILED)
    else:
        # print(f"{sha256} is in cache")
        pass

    match cache[sha256]:
        case APK_DOWNLOAD_STATUS.SUCCESS:
            return _get_path(sha256)
        case APK_DOWNLOAD_STATUS.FAILED:
            return None
        case APK_DOWNLOAD_STATUS.NOT_TRIED:
            return None

    return None


@click.command()
@click.argument("sha256", type=str)
@click.option("--use-cache/--no-cache", is_flag=True, default=False, help="Ignore cache and force download.")
def entry_point(sha256: str, use_cache: bool) -> None:
    """
    Download an APK by its SHA256 hash.
    """
    
    filepath = download(
        sha256,
        use_cache=use_cache
    )

    if filepath:
        click.echo(f"APK downloaded successfully: {filepath}")
    else:
        click.echo("Failed to download APK.")


if __name__ == "__main__":
    entry_point()
