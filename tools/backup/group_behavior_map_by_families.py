from pathlib import Path
import re
import polars as pl
import data_preprocess.virus_total as vt
import data_preprocess.apk as apk_lib

ThreatLabels = pl.Struct(
    {
        "major_threat_label": pl.String(),
        "middle_threat_label": pl.String(),
        "minor_threat_label": pl.String(),
    }
)


def get_threat_labels(sha256: str) -> dict[str, str]:
    try:
        report, _ = vt.get_virus_total_report(sha256)

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


def group_behavior_map_by_source(
    behavior_map_folder: Path, source_lists: list[Path]
):
    source_dfs = [
        apk_lib.read_csv(str(source))
        .select("sha256")
        .with_columns(pl.lit(source.stem).alias("source"))
        for source in source_lists
    ]
    source_df = (
        pl.concat(source_dfs, how="vertical").unique("sha256", keep="none")
    ).select("sha256", "source")

    target_path_dict: dict[str, Path] = {
        sha256: behavior_map_folder / src
        for sha256, src in source_df.iter_rows()
    }

    for dot_path in behavior_map_folder.glob("*.dot"):
        sha256 = dot_path.stem
        if sha256 not in target_path_dict:
            continue

        target_path_dict[sha256].mkdir(exist_ok=True)

        if dot_path.exists():
            print(f"Moving DOT  {dot_path}\t to {target_path_dict[sha256]}")
            dot_path.rename(target_path_dict[sha256] / dot_path.name)

        json_path = dot_path.with_suffix(".json")
        if json_path.exists():
            print(f"Moving JSON {json_path}\t to {target_path_dict[sha256]}")
            json_path.rename(target_path_dict[sha256] / json_path.name)

        png_path = dot_path.with_suffix(".png")
        if png_path.exists():
            print(f"Moving PNG  {png_path}\t to {target_path_dict[sha256]}")
            png_path.rename(target_path_dict[sha256] / png_path.name)


if __name__ == "__main__":
    group_behavior_map_by_source(
        Path("/tmp/behavior_map_n78rib4x"),
        [
            Path("data/lists/family/basebridge.csv"),
            Path("data/lists/family/droidkungfu.csv"),
            Path("data/lists/benignAPKs_top_0.4_vt_scan_date.csv"),
        ]
    )
