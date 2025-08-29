from pathlib import Path
import click
import polars as pl
import data_preprocess.virus_total as vt


def map_elements_with_progress_bar(series, func, *args, **kwargs):
    """
    A wrapper for map_elements that shows a progress bar.
    """
    with click.progressbar(length=len(series), label="Processing") as bar:
        return series.map_elements(
            lambda x: (func(x, *args, **kwargs), bar.update(1)),
            return_dtype=series.dtype,
        )


@click.command()
@click.option("--apk_list", "-a", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path))
@click.option("--family", "-f", type=str)
@click.option("--output_path", "-o", type=click.Path(path_type=Path))
@click.option("--virus_total_api_key", "-k", type=str, envvar="VIRUS_TOTAL_API_KEY", help="VirusTotal API key")
def collect_apk_by_family(apk_list: Path, family: str, output_path: Path, virus_total_api_key: str):
    """
    Collect APKs by family from a given list.

    Example usage:
    uv run tools/collect_apk_by_family.py -a data/lists/maliciousAPKs_test.csv -f droidkungfu -o data/lists/family/droidkungfu_test.csv
    """

    sha256s = pl.read_csv(apk_list, columns=["sha256"])

    with click.progressbar(length=len(sha256s), label="Get threat labels") as bar:
        sha256_with_family = sha256s.with_columns(
            pl.col("sha256")
            .map_elements(
                lambda x: (vt.get_threat_label(x, virus_total_api_key), bar.update(1))[0],
                return_dtype=pl.Struct(
                    {
                        "major_threat_label": pl.String(),
                        "middle_threat_label": pl.String(),
                        "minor_threat_label": pl.String(),
                    }
                ),
            )
            .alias("threat_labels")
        ).unnest("threat_labels")

    # Replace kungfu with droidkungfu because they are the same family
    sha256_with_family = sha256_with_family.with_columns(
        pl.col("middle_threat_label").str.replace("^kungfu$", "droidkungfu")
    )

    # Show the family distribution
    family_distribution = sha256_with_family["middle_threat_label"].value_counts()
    print("Family distribution:")
    print(family_distribution.head())

    # Filter by family
    target_dataset = sha256_with_family.filter(pl.col("middle_threat_label").eq(family))
    
    # Add is_malicious column
    target_dataset = target_dataset.with_columns(pl.lit(1).alias("is_malicious"))

    print(f"Number of APKs in family {family}: {len(target_dataset)}")
    target_dataset.write_csv(output_path)


if __name__ == "__main__":
    collect_apk_by_family()
