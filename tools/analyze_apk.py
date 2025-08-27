import click
import polars as pl
import data_preprocess.apk as apk_lib
import data_preprocess.rule as rule_lib
import data_preprocess.analysis_result as analysis_result_lib
import ray
import ray.data
import resource
from pathlib import Path
import pandas as pd
from typing import Dict, Any
import functools


def get_apk_path(row: Dict[str, Any]) -> Dict[str, Any]:
    # Get the APK path from the sha256, do not download it
    path = apk_lib.download(row["sha256"], use_cache=True, dry_run=True)
    row["apk_path"] = str(path) if path else None
    return row


def analyze_apk(row: Dict[str, Any], rules: list[Path]) -> list[Dict[str, Any]]:
    results = analysis_result_lib.analyze_rules(
        row["sha256"], Path(row["apk_path"]), rules
    )
    
    def get_new_row(row, rule_name: str, confidence: int) -> Dict[str, Any]:
        new_row = row.copy()
        new_row["rule_name"] = rule_name
        new_row["confidence"] = confidence
        return new_row
    
    return [
        get_new_row(row, rule_name, confidence)
        for rule_name, confidence in results.items()
    ]


def analyze_apks(sha256s: list[str], rules: list[Path], output_csv: Path):
    ray.init()

    sha256s_pl = pd.DataFrame({"sha256": sha256s})
    sha256s_pl = sha256s_pl.assign(
        size=sha256s_pl["sha256"].apply(lambda x: apk_lib._get_path(x).stat().st_size)
    )
    sha256s_pl = sha256s_pl.sort_values("size")
    
    # Drop size column as it is not needed anymore
    sha256s_pl = sha256s_pl.drop(columns=["size"])

    dataset = ray.data.from_pandas(sha256s_pl, override_num_blocks=len(sha256s_pl))
    dataset = dataset.map(get_apk_path)

    dataset = dataset.filter(lambda row: row["apk_path"] is not None)

    partial_analyze_apk = functools.partial(analyze_apk, rules=rules)
    dataset = dataset.flat_map(partial_analyze_apk)
    
    # Write dataset to CSV
    dataset.write_csv(str(output_csv))

    # success_sha256s = dataset["sha256"].to_list()
    # print(f"Complete analysis {len(sha256s)} APKs on {len(rules)} rules")
    # print(f"with {len(success_sha256s)} success")

    # failed_sha256s = list(set(sha256s) - set(success_sha256s))
    # failed_out_file = "failed_apks.csv"
    # pl.DataFrame(failed_sha256s, schema=["sha256"]).write_csv(failed_out_file, include_header=True)

    # if failed_sha256s:
    #     print(
    #         f"and {len(failed_sha256s)} failed due to out of memory, "
    #         f"please refer to {failed_out_file}"
    #     )

    ray.shutdown()


@click.command()
@click.option(
    "--apk_list",
    "-a",
    type=click.Path(exists=True, path_type=Path),
    multiple=True,
    help="List of APKs to analyze.",
)
@click.option(
    "--rule_folder",
    "-r",
    type=click.Path(exists=True, file_okay=False, readable=True, path_type=Path),
    multiple=True,
    help="Folder containing rules to use for analysis.",
)
@click.option(
    "--output_csv",
    "-o",
    type=click.Path(file_okay=False, path_type=Path),
    required=True,
    default=Path("analysis_results"),
    help="Output folder to show analysis results.",
)
def analyze_apk_parallelly(apk_list: list[Path], rule_folder: list[Path], output_csv: Path):
    """Analyze APKs from a list using rules from a specified folder.

    Example usage:
    uv run tools/analyze_apk.py -a data/lists/family/droidkungfu_test.csv -a data/lists/benignAPKs_top_0.4_vt_scan_date.csv -r data/test_rules
    """
    mem_bytes = 22 * 1024 * 1024 * 1024  # 20 GB
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))

    # Flatten the list of APKs and rules
    sha256s = (
        pl.concat(
            [pl.read_csv(str(apk_list_path), columns=["sha256"]) for apk_list_path in apk_list],
            how="vertical",
        )
        .to_series()
        .to_list()
    )
    rules = [rule for folder in rule_folder for rule in folder.rglob("*.json") if rule.is_file()]

    print(f"Analyzing {len(sha256s)} APKs with {len(rules)} rules")
    analyze_apks(sha256s, rules, output_csv)


if __name__ == "__main__":
    analyze_apk_parallelly()

    # PATH_TO_DATASET = [
    #     "data/lists/family/droidkungfu.csv",
    #     "data/lists/family/basebridge.csv",
    #     "data/lists/family/golddream.csv",
    #     "data/lists/benignAPKs_top_0.4_vt_scan_date.csv",
    # ]

    # PATH_TO_RULE_LIST = [
    #     "/mnt/storage/data/rule_to_release/default_rules.csv",
    #     "/mnt/storage/data/rule_to_release/golddream/rule_added.csv",
    # ]

    # entry_point(
    #     dataset_paths=[Path(path) for path in PATH_TO_DATASET],
    #     rule_list_paths=[Path(path) for path in PATH_TO_RULE_LIST],
    # )
