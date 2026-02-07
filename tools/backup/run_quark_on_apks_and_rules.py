# %%
# 載入 APK 清單
import os
from typing import Any
import polars as pl
import data_preprocess.apk as apk_lib

DATASET_PATHS = ["data/lists/maliciousAPKs_top_0.4_vt_scan_date.csv"]

dataset = pl.concat((apk_lib.read_csv(ds) for ds in DATASET_PATHS)).unique(
    "sha256", keep="any"
)
print(dataset.schema)
# 對於每個樣本，透過 VT 取得其 threat_label，並進一步拆解成 major, middle, minor
import data_preprocess.virus_total as vt
import tqdm
import re


with tqdm.tqdm(desc="Getting Threat Label", total=len(dataset)) as progress:
    ThreatLabels = pl.Struct(
        {
            "major_threat_label": pl.String(),
            "middle_threat_label": pl.String(),
            "minor_threat_label": pl.String(),
        }
    )

    def get_threat_label(sha256: str) -> dict[str, str]:
        try:
            report, status = vt.get_virus_total_report(sha256)

            threat_label = (
                report.get("data", {})
                .get("attributes", {})
                .get("popular_threat_classification", {})
                .get("suggested_threat_label", "./")
            )

            parts = re.split("[./]", threat_label)
            major = parts[0] if len(parts) > 0 else ""
            middle = parts[1] if len(parts) > 1 else ""
            minor = parts[2] if len(parts) > 2 else ""

            return {
                "major_threat_label": major,
                "middle_threat_label": middle,
                "minor_threat_label": minor,
            }

        except BaseException as e:
            print(f"Error on {sha256}: {e}")
            return {
                "major_threat_label": "",
                "middle_threat_label": "",
                "minor_threat_label": "",
            }
        finally:
            progress.update()

    dataset = dataset.with_columns(
        pl.col("sha256")
        .map_elements(get_threat_label, return_dtype=ThreatLabels, strategy="threading")
        .alias("threat_labels")
    ).unnest("threat_labels")


dataset = dataset.with_columns(
    pl.col("middle_threat_label").str.replace("^kungfu$", "droidkungfu")
)

print(dataset.head(5))

print("major_threat_label:")
print(dataset["major_threat_label"].value_counts().sort(by="count", descending=True))

print("middle_threat_label:")
print(dataset["middle_threat_label"].value_counts().sort(by="count", descending=True))

# %%
# 挑選一個惡意程式家族來跑 Quark 分析
import click

target_middle_threat_label = click.prompt(
    "Enter target middle threat label",
    type=str,
    default="droidkungfu",
    show_default=True,
)

# 篩選出屬於此家族的樣本
target_dataset = dataset.filter(
    pl.col("middle_threat_label").eq(target_middle_threat_label)
)

print(target_dataset.head(5))
print(f"Num of apk: {len(target_dataset)}")

# %%
# 跑 Quark 分析
import json
from quark.report import Report
import diskcache
from typing import Any
import os

cache = diskcache.FanoutCache(f"{os.getenv("CACHE_FOLDER")}/quark_analysis_cache")

@cache.memoize()
def run_quark_analysis(sha256:str) -> dict[str, Any]:
    report = Report()
    apk_path = apk_lib.download(sha256, dry_run=True)
    
    report.analysis(
        apk=apk_path,
        rule="/mnt/storage/quark-rules/rules"
    )
    
    json_report = report.get_report(
        "json"
    )
    return json_report

def get_thread_label(sha256) -> str:
    json_report = run_quark_analysis(sha256)
    return json_report["threat_level"]
    
target_dataset = target_dataset.with_columns(
    pl.col("sha256").map_elements(get_thread_label, return_dtype=pl.String(), strategy="threading").alias("threat_level")
).with_columns(
    pl.col("threat_level").eq("High Risk").alias("actual_result")
)

target_dataset
# %%
from sklearn.metrics import accuracy_score

actual = target_dataset["actual_result"].to_list()
expected = [True] *  len(target_dataset["actual_result"])

accuracy = accuracy_score(expected, actual)
print(f"Accuracy of Quark analysis is {accuracy:.2%}")
# %%
