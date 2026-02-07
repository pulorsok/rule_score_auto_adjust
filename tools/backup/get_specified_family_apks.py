from pathlib import Path
from prefect import flow, task
import polars as pl
import re
import tqdm
import click

import data_preprocess.apk as apk_lib
import data_preprocess.virus_total as vt
import os
import dotenv
dotenv.load_dotenv()

DATASET_PATHS = ["data/lists/maliciousAPKs_top_0.4_vt_scan_date.csv"]


@task
def read_apk_list(paths: list[str]) -> pl.DataFrame:
    df = pl.concat((apk_lib.read_csv(p) for p in paths)).unique(
        "sha256", keep="any"
    )
    print(df.schema)
    return df


@task
def get_threat_labels_from_virus_total(dataset: pl.DataFrame) -> pl.DataFrame:
    def get_threat_label(sha256: str) -> dict[str, str]:
        try:
            report, _ = vt.get_virus_total_report(sha256)
            label = (
                report.get("data", {})
                .get("attributes", {})
                .get("popular_threat_classification", {})
                .get("suggested_threat_label", "./")
            )
            parts = re.split("[./]", label)
            major = parts[0] if len(parts) > 0 else ""
            middle = parts[1] if len(parts) > 1 else ""
            minor = parts[2] if len(parts) > 2 else ""

            return {
                "major_threat_label": major,
                "middle_threat_label": middle,
                "minor_threat_label": minor,
            }
        except Exception as e:
            print(f"Error on {sha256}: {e}")
            return {
                "major_threat_label": "",
                "middle_threat_label": "",
                "minor_threat_label": "",
            }

    ThreatLabels = pl.Struct(
        {
            "major_threat_label": pl.String(),
            "middle_threat_label": pl.String(),
            "minor_threat_label": pl.String(),
        }
    )

    with tqdm.tqdm(
        desc="Getting Threat Label", total=len(dataset)
    ) as progress:

        def wrapper(sha256):
            result = get_threat_label(sha256)
            progress.update()
            return result

        enriched = dataset.with_columns(
            pl.col("sha256")
            .map_elements(
                wrapper, return_dtype=ThreatLabels, strategy="threading"
            )
            .alias("threat_labels")
        ).unnest("threat_labels")

    return enriched


@task
def normalize_labels(dataset: pl.DataFrame) -> pl.DataFrame:
    return dataset.with_columns(
        pl.col("middle_threat_label").str.replace("^kungfu$", "droidkungfu")
    )


@task
def show_threat_label_step(dataset: pl.DataFrame) -> None:
    print(dataset.head(5))

    print("major_threat_label:")
    print(
        dataset["major_threat_label"]
        .value_counts()
        .sort(by="count", descending=True)
    )

    print("middle_threat_label:")
    print(
        dataset["middle_threat_label"]
        .value_counts()
        .sort(by="count", descending=True)
    )


@task
def ask_for_malicious_family_to_extract() -> str:
    target = click.prompt(
        "Enter target middle threat label", default="droidkungfu"
    )
    return target

@task
def filter_by_target_label(
    dataset: pl.DataFrame, target_family: str
) -> pl.DataFrame:
    target_df = dataset.filter(pl.col("middle_threat_label") == target_family)
    print(f"Num of apk: {len(target_df)}")
    return target_df

@task
def write_apk_dataset(
    dataset: pl.DataFrame, target_path: str
) -> Path:
    dataset.write_csv(target_path)

@flow
def get_specified_family_apks(dataset_paths: list[str], target_family: str):
    dataset = read_apk_list(dataset_paths)
    dataset_with_label = get_threat_labels_from_virus_total(dataset)
    dataset_with_label = normalize_labels(dataset_with_label)
    
    target_dataset = filter_by_target_label(dataset_with_label, target_family)
    output_path = (Path(os.getenv("APK_LIST_FOLDER", "")) / "family" / target_family).with_suffix("csv")
    
    write_apk_dataset(target_dataset, output_path)
    
    return  target_dataset, output_path


if __name__ == "__main__":
    target_df, _ = get_specified_family_apks(DATASET_PATHS, "droidkungfu")
    print(target_df)
