# %%
# 載入 APK 清單
from functools import reduce
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
        .map_elements(
            get_threat_label, return_dtype=ThreatLabels, strategy="threading"
        )
        .alias("threat_labels")
    ).unnest("threat_labels")


dataset = dataset.with_columns(
    pl.col("middle_threat_label").str.replace("^kungfu$", "droidkungfu")
)

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


# %%
# 挑選一個 middle threat label 作為要釋出規則的惡意程式家族
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
# 對於每個樣本，找出通過 5 階段分析的規則
import data_preprocess.rule as rule_lib
import data_preprocess.analysis_result as analysis_result_lib

PATH_TO_RULE_LIST = [
    "/mnt/storage/data/rule_to_release/0627/unselected_rules.csv"
]
rules = pl.concat(list(map(rule_lib.load_list, PATH_TO_RULE_LIST)))
rule_paths = [rule_lib.get(r) for r in rules["rule"].to_list()]
print(f"Num of rules in list: {len(rule_paths)}")
rule_paths = [rule for rule in rule_paths if rule.exists()]
print(f"Num of rules exist: {len(rule_paths)}")

with tqdm.tqdm(
    desc="Getting stage 5 rules", total=len(target_dataset)
) as progress:

    def get_stage_5_rules(sha256: str) -> list[str]:
        apk_path = apk_lib.download(sha256)
        analysis_result = analysis_result_lib.analyze_rules(
            sha256, apk_path, rule_paths, dry_run=True
        )
        progress.update()

        return [rule for rule, stage in analysis_result.items() if stage == 5]

    target_dataset = target_dataset.with_columns(
        pl.col("sha256")
        .map_elements(get_stage_5_rules, return_dtype=pl.List(pl.String()))
        .alias("stage_5_rules")
    )

stage_5_rules = (
    target_dataset.explode("stage_5_rules")
    .unique("stage_5_rules")
    .select("stage_5_rules")
    .rename({"stage_5_rules": "rule"})
)

print("A glance of current apk and rules mapping.")
print(target_dataset.head(5))

print("Num of apk: ", len(target_dataset))
print("Num of rules: ", len(rules))
print("Num of stage 5 rules: ", len(stage_5_rules))
# %%
# Load rules from quark-rules
from pathlib import Path
import polars as pl
import data_preprocess.rule as rule_lib

PATH_TO_QUARK_RULES = Path("/mnt/storage/quark-rules/rules")
rule_paths = [str(p.resolve()) for p in PATH_TO_QUARK_RULES.glob("*.json")]
default_rules = pl.DataFrame(rule_paths, schema={"rule_path": pl.String()})

default_rules = default_rules.with_columns(
    pl.col("rule_path")
    .map_elements(rule_lib.get_hash, return_dtype=pl.String())
    .alias("rule_hash")
)

# %%
# 篩除與 Quark 現有規則集重複的規則

stage_5_rules = stage_5_rules.with_columns(
    pl.col("rule")
    .map_elements(
        lambda r: rule_lib.get_hash(rule_lib.get(r)), return_dtype=pl.String()
    )
    .alias("rule_hash")
)

stage_5_rules_removing_default = stage_5_rules.join(
    default_rules, on="rule_hash", how="anti"
)

print("Num of stage 5 rules: ", len(stage_5_rules))
print(
    "Num of stage 5 rules after removing default rules: ",
    len(stage_5_rules_removing_default),
)


# %%
# 產出規則清單供 AI 訓練權重用
stage_5_rules_removing_default.select("rule").write_csv(
    "/mnt/storage/data/rule_to_release/pjapps/unselected_rules.csv"
)

# 產出 quark rules 規則清單
default_rules.with_columns(
    pl.col("rule_path").str.split("/").list.get(-1).alias("rule")
).select("rule").write_csv(
    "/mnt/storage/data/rule_to_release/default_rules.csv"
)

# %%
# 對於每個規則，找出其調整後的分數，再依照分數排序
# TODO - 把 model 訓練流程紀錄與結果（包含調整後的分數）記錄到 mlflow 中
import polars as pl

PATH_TO_APK_PREDICTION = (
    "/mnt/storage/rule_score_auto_adjust/apk_prediction.csv"
)
prediction = (
    pl.read_csv(PATH_TO_APK_PREDICTION, has_header=True)
    .filter(pl.col("sha256").eq("rule_score"))
    .drop(["y_truth", "y_pred_row", "y_pred"], strict=False)
    .transpose(include_header=True, header_name="rule", column_names="sha256")
)
prediction = prediction.sort(by="rule_score", descending=True)

# %%
stage_5_rules = (
    stage_5_rules.join(prediction, on="rule", how="left")
    .select(["rule", "rule_score"])
    .sort(by="rule_score", descending=True)
)
if stage_5_rules["rule_score"].is_null().any():
    raise ValueError("Some rules do not have scores.")
else:
    print("All rules have scores.")

# %%
# 抓出所有前 20% 分數最高的規則
stage_5_rules = stage_5_rules.sort(by="rule_score", descending=False)
subset = stage_5_rules.head(int(len(stage_5_rules) * 0.2))
print(subset.head(5))
print(f"Num of rules: {len(subset)}")
print(f"Max score: {subset['rule_score'].max()}")
print(f"Min score: {subset['rule_score'].min()}")
# %%
# 畫出規則分數分布圖
import matplotlib.pyplot as plt

plt.figure(figsize=(10, 6))
plt.scatter(subset["rule"], subset["rule_score"])
plt.xlabel("Rule")
plt.ylabel("Rule Score")
plt.title("Rule Score Distribution")
plt.show()

print(f"Num of rules: {len(subset)}")
print(f"Max score: {subset['rule_score'].max()}")
print(f"Min score: {subset['rule_score'].min()}")

# %%
# 對於每個規則，生成一個規則描述
from tools.generate_rule_description import RuleDescriptionAgent
import os
import json
import tqdm

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
agent = RuleDescriptionAgent(OPENAI_API_KEY)

with tqdm.tqdm(desc="Getting rule description", total=len(subset)) as progress:

    Schema = pl.Struct(
        [
            pl.Field("description", pl.String()),
            pl.Field("api1", pl.String()),
            pl.Field("api2", pl.String()),
        ]
    )

    def get_description(rule: str):
        progress.update()
        rule_path = rule_lib.get(rule)
        with rule_path.open("r") as content:
            api_pair = json.loads(content.read())["api"]

        api1 = (
            api_pair[0]["class"]
            + api_pair[0]["method"]
            + api_pair[0]["descriptor"]
        )
        api2 = (
            api_pair[1]["class"]
            + api_pair[1]["method"]
            + api_pair[1]["descriptor"]
        )

        return {
            "description": agent.get_description(api_pair),
            "api1": api1,
            "api2": api2,
        }

    subset = subset.with_columns(
        pl.col("rule")
        .map_elements(
            get_description, return_dtype=Schema, strategy="thread_local"
        )
        .alias("combined")
    ).unnest("combined")

subset.write_csv("./selected_rule_for_releasing.csv")

# %%
# 請 AI 針對規則進行分類

# %%
# 將 AI 的分類結果 join 進 subset
PATH_TO_AI_CLASSIFICATION = "./selected_rule_from_ai_0.2.csv"
ai_classification = pl.read_csv(
    PATH_TO_AI_CLASSIFICATION, has_header=True, columns=["rule", "category"]
)
ai_classification = ai_classification.join(subset, on="rule", how="left")
ai_classification.write_csv("./selected_rule_for_ai_0.2.csv")

# %%
# 讀取規則的兩個 API 至表格中
import polars as pl
import data_preprocess.rule as rule_lib
import json

ai_classification = pl.read_csv(
    "./selected_rule_for_ai_0.2.csv", has_header=True
)

if "api1" in ai_classification.columns:
    ai_classification = ai_classification.drop(["api1", "api2"])


def get_apis(rule: str) -> tuple[str, str]:
    rule_path = rule_lib.get(rule)
    with rule_path.open("r") as content:
        api1, api2 = json.loads(content.read())["api"]
    return {
        "api1": f"{api1['class']}{api1['method']}{api1['descriptor']}",
        "api2": f"{api2['class']}{api2['method']}{api2['descriptor']}",
    }


ai_classification = ai_classification.with_columns(
    pl.col("rule")
    .map_elements(
        get_apis,
        return_dtype=pl.Struct({"api1": pl.String(), "api2": pl.String()}),
        strategy="thread_local",
    )
    .alias("apis")
).unnest("apis")
print(ai_classification.head(5))
ai_classification.write_csv("./selected_rule_for_ai_0.2.csv")
# %%
# 將表格內容寫入規則檔案
from pathlib import Path
import polars as pl
import tqdm
import data_preprocess.rule as rule_lib
import json

rule_table = pl.read_csv(
    "./selected_rule_for_ai_0.2_manually_selected.csv", has_header=True
)

# %%
# 依照大類別與分數由高到低分類規則
rule_table = rule_table.sort(
    by=["category", "rule_score"], descending=[True, True]
)
rule_table.write_csv("./selected_rule_for_ai_0.2_manually_selected.csv")

# %%
# 加上編號
STARTING_NUMBER = 212
rule_table = rule_table.with_row_index(
    name="rule_id", offset=STARTING_NUMBER
).with_columns(
    pl.col("rule_id").map_elements(
        lambda x: f"{x:05d}.json", return_dtype=pl.String()
    )
)

# %%

output_rule_folder = Path("./selected_rule")
output_rule_folder.mkdir(exist_ok=True)

for rule_id, rule, _, _, description, api1, api2, label in tqdm.tqdm(
    rule_table.rows()
):
    rule_path = rule_lib.get(rule)

    with rule_path.open("r") as content:
        rule_content = json.loads(content.read())

    rule_content["crime"] = description
    rule_content["label"] = label.split(",")

    with rule_path.open("w") as content:
        content.write(
            json.dumps(
                rule_content,
                indent=4,
            )
        )

    alter_path = output_rule_folder / rule_id
    with alter_path.open("w") as content:
        content.write(
            json.dumps(
                rule_content,
                indent=4,
            )
        )


# %%
# Load rules from quark-rules
from pathlib import Path
import polars as pl
import data_preprocess.rule as rule_lib
import tqdm
import json

PATH_TO_QUARK_RULES = Path("/mnt/storage/quark-rules/rules")
default_rules = pl.DataFrame(
    [str(p) for p in PATH_TO_QUARK_RULES.glob("*.json")],
    schema={"rule_path": pl.String()},
)

with tqdm.tqdm(desc="Getting rule data", total=len(default_rules)) as progress:

    def get_rule_data(rule_path: str):
        with Path(rule_path).open("r") as content:
            rule_content = json.loads(content.read())

        progress.update()
        return {
            "api1": rule_content["api"][0]["class"]
            + rule_content["api"][0]["method"]
            + rule_content["api"][0]["descriptor"],
            "api2": rule_content["api"][1]["class"]
            + rule_content["api"][1]["method"]
            + rule_content["api"][1]["descriptor"],
            "description": rule_content["crime"],
            "label": ",".join(rule_content["label"]),
        }

    default_rules = default_rules.with_columns(
        pl.col("rule_path")
        .map_elements(
            get_rule_data,
            return_dtype=pl.Struct(
                {
                    "api1": pl.String(),
                    "api2": pl.String(),
                    "description": pl.String(),
                    "label": pl.String(),
                }
            ),
            strategy="thread_local",
        )
        .alias("rule_data")
    ).unnest("rule_data")
default_rules.head(5)
default_rules.write_csv("./default_rules.csv")

# %%
# Second Round
# 將規則描述寫入規則檔案中
from tqdm import tqdm
import json

for rule, description in tqdm(
    subset.select("rule", "description").iter_rows()
):
    rule_path = rule_lib.get(rule)
    with rule_path.open("r") as content:
        rule_content = json.loads(content.read())

    rule_content["crime"] = f"{rule} - {description}"

    with rule_path.open("w") as content:
        content.write(
            json.dumps(
                rule_content,
                indent=4,
            )
        )

# %%
# 為規則清單建立一個資料夾，供 Quark 分析用
import data_preprocess.rule as rule_lib
from pathlib import Path
import tempfile

unselected_rules = rule_lib.load_list(
    "/mnt/storage/data/rule_to_release/0627/unselected_rules.csv"
)
temp_rule_folder = tempfile.TemporaryDirectory(
    prefix="rule_folder_", delete=False
)

rule_lib.build_rule_folder(
    unselected_rules["rule"].to_list(), Path(temp_rule_folder.name)
)
print(f"Rule is now hard linked to folder: {temp_rule_folder.name}")

# %%
# 將 Quark 預設規則也加到規則目錄中
import polars as pl
from pathlib import Path

PATH_TO_QUARK_RULES = Path("/mnt/storage/quark-rules/rules")
default_rules = pl.DataFrame(
    [str(p) for p in PATH_TO_QUARK_RULES.glob("*.json")],
    schema={"rule_path": pl.String()},
)

# 編輯 Quark 規則以在規則描述中加入規則編號
for path_str in default_rules["rule_path"].to_list():
    path = Path(path_str)
    rule = None
    with path.open("r") as inFile:
        rule = json.load(inFile)

    rule["crime"] = f"{path.name} - {rule['crime']}"

    with path.open("w") as outFile:
        json.dump(rule, outFile, indent=4)

for path_str in default_rules["rule_path"].to_list():
    path = Path(path_str)
    target_rule_path = Path(temp_rule_folder.name) / path.name
    if target_rule_path.exists():
        target_rule_path.unlink()
    target_rule_path.symlink_to(path)

print(
    f"Num of rule: {sum((1 for _ in Path(temp_rule_folder.name).glob("*.json")))}"
)

# %%
# 針對每個 APK 生成行為圖
import data_preprocess.apk as apk_lib
from pathlib import Path
from tqdm import tqdm
import subprocess

apks = apk_lib.read_csv(
    "/mnt/storage/data/rule_to_release/0627/basebridge.csv"
)

for apk in tqdm(apks["sha256"], desc="Generating Behavior Map"):
    commands = [
        "quark",
        "-a",
        str(apk_lib.download(apk, dry_run=True)),
        "-r",
        temp_rule_folder.name,
        "-s",
        "-c",
    ]
    print(f"Running command: {' '.join(commands)}")
    try:
        subprocess.run(args=commands, check=True)

        print(f"Behavior map for {apk} generated.\nRenaming to {apk}.json")
        folder = Path(f"classifications")
        folder.mkdir(exist_ok=True)
        Path(f"rules_classification").rename(f"{str(folder)}/{apk}")
        Path(f"rules_classification.json").rename(f"{str(folder)}/{apk}.json")
        Path(f"rules_classification.png").rename(f"{str(folder)}/{apk}.png")

    except subprocess.CalledProcessError as e:
        print(f"Error generating behavior map for {apk}: {e}")
        continue
# %%
# 移除 Behavior Map 中烙單的節點
import pydot
from pathlib import Path
from tqdm import tqdm


def get_all_nodes_with_owners(graph_or_subgraph):
    """
    遞迴取得所有節點及其所在 graph/subgraph 物件。
    傳回 List[Tuple[str, pydot.Subgraph]]
    """
    results = []
    for node in graph_or_subgraph.get_nodes():
        name = node.get_name().strip('"')
        if name.lower() != "node":
            results.append((name, graph_or_subgraph))
    for sub in graph_or_subgraph.get_subgraphs():
        results.extend(get_all_nodes_with_owners(sub))
    return results


def remove_isolated_nodes(dot_input_path: str, dot_output_path: str) -> None:
    graphs = pydot.graph_from_dot_file(dot_input_path)
    if not graphs:
        raise ValueError("Invalid .dot file or no graph found.")

    graph = graphs[0]
    graph.set("rankdir", "LR")

    # 取得所有有邊相連的節點（來源與目的）
    connected_nodes = set()
    for edge in graph.get_edges():
        src = edge.get_source().strip('"')
        dst = edge.get_destination().strip('"')
        connected_nodes.add(src)
        connected_nodes.add(dst)

    # 找出所有節點與其對應的 graph/subgraph
    all_nodes = get_all_nodes_with_owners(graph)

    # 移除孤立節點
    for name, owner in all_nodes:
        if name not in connected_nodes:
            owner.del_node(name)
            # print(f"Removed isolated node: {name}")

    # 寫出檔案
    out_path = Path(dot_output_path)
    graph.write(out_path.with_suffix(".dot"), format="raw")
    graph.write(out_path.with_suffix(".png"), format="png")


parent = Path("/mnt/storage/rule_score_auto_adjust/classifications/cleaned")
parent.mkdir(exist_ok=True)

dots = [
    d
    for d in Path("/mnt/storage/rule_score_auto_adjust/classifications").glob(
        "*"
    )
    if d.suffix not in [".png", ".json"] and d.is_file()
]

parent = Path("/mnt/storage/rule_score_auto_adjust/classifications/cleaned")
parent.mkdir(exist_ok=True)

for dot in tqdm(dots, desc="Removing isolated nodes"):
    output_path = parent / dot.name
    remove_isolated_nodes(str(dot), str(output_path))
    print(f"Cleaned {dot} and saved to {output_path}")
# %%
# Checkpoint
# 從 Behavior Map 中取出沒有落單的 Rule
import pydot
from pathlib import Path
from tqdm import tqdm
import polars as pl


def get_all_nodes_with_owners(graph_or_subgraph):
    results = []
    for node in graph_or_subgraph.get_nodes():
        name = node.get_name().strip('"')
        if name.lower() != "node":
            results.append((name, graph_or_subgraph))
    for sub in graph_or_subgraph.get_subgraphs():
        results.extend(get_all_nodes_with_owners(sub))
    return results


def extract_prefix_labels(dot_input_path: str) -> list[str]:
    graphs = pydot.graph_from_dot_file(dot_input_path)
    if not graphs:
        raise ValueError("Invalid .dot file or no graph found.")

    rules = set()

    while graphs:
        graph = graphs.pop(0)
        graphs.extend(graph.get_subgraphs())

        for node in graph.get_nodes():
            if node:
                label = node.get_attributes().get("label", "")
                tokens = label.split("-")
                if len(tokens) < 2:
                    print(f"Tokens less than 2: {tokens}")
                    tokens.append("")
                prefix, description = tokens[0], tokens[1]
                prefix, description = prefix.strip().strip(
                    '"'
                ), description.strip().strip('"')
                if prefix:  # 忽略空字串
                    rules.add(f"{prefix} - {description}")

    return list(rules)


graph_paths = pl.DataFrame(
    [
        str(p)
        for p in Path(
            "/mnt/storage/rule_score_auto_adjust/classifications/cleaned"
        ).glob("*.dot")
    ],
    schema={"graph_path": pl.String()},
)

graph_paths = graph_paths.with_columns(
    pl.col("graph_path")
    .map_elements(extract_prefix_labels, return_dtype=pl.List(pl.String()))
    .alias("rules")
)

# %%
# 查看有無所有樣本都會中的規則
from functools import reduce

rule_lists = graph_paths["rules"].to_list()
common_rules = list(reduce(lambda x, y: set(x) & set(y), rule_lists))
print(common_rules)

# %%
# 查看每個規則有中的樣本有多少
from collections import Counter
import altair as alt

rule_lists = graph_paths["rules"].to_list()
rule_counter = Counter()

for rules in rule_lists:
    for rule in rules:
        rule_counter[rule] += 1


rule_distribution = pl.DataFrame(
    list(rule_counter.items()),
    schema={"rule": pl.String(), "count": pl.Int64()},
).sort(by="count", descending=True)
print_pr = lambda pr_value: print(
    f"PR {pr_value*100:2f} (Num. Of rule: {len(rule_distribution)*pr_value}): {rule_distribution["count"].quantile(pr_value)}"
)

print_pr(0.90)
print_pr(0.80)
print_pr(0.50)
count_chart = rule_distribution.plot.bar(x=alt.X("rule", sort="-y"), y="count")
count_chart

rule_distribution = rule_distribution.with_columns(
    pl.col("rule").str.split_exact(by="-", n=1)
).unnest("rule")

rule_distribution = rule_distribution.rename(
    {"field_0": "rule", "field_1": "description"}
)

rule_distribution = rule_distribution.with_columns(
    pl.col("description").str.strip_chars().str.replace(r"^[0-9]+\.json$", ""),
    pl.col("rule").str.strip_chars(),
)


import polars as pl
import altair as alt

PATH_TO_APK_PREDICTION = (
    "/mnt/storage/rule_score_auto_adjust/apk_prediction.csv"
)
prediction = (
    pl.read_csv(PATH_TO_APK_PREDICTION, has_header=True)
    .filter(pl.col("sha256").eq("rule_score"))
    .drop(["y_truth", "y_pred_row", "y_pred"], strict=False)
    .transpose(include_header=True, header_name="rule", column_names="sha256")
    .filter(pl.col("rule_score").is_not_null())
)
prediction = prediction.sort(by="rule_score", descending=False)

rule_distribution = rule_distribution.join(
    other=prediction, on="rule", how="left", maintain_order="left"
)

rule_distribution = rule_distribution.with_columns(
    pl.col("rule_score").fill_null(0)
)

score_chart = (
    rule_distribution.with_columns(pl.col("rule_score").fill_null(0))
    .sort(by="rule_score", descending=True)
    .plot.bar(x=alt.X("rule", sort="-y"), y="rule_score")
    .interactive(bind_x=True)
)

# %%
# 讀取規則檔案，抓出他的 API
import data_preprocess.rule as rule_lib


def get_apis_as_struct(rule):
    api1, api2 = rule_lib.get_apis(rule)
    return {"api1": api1, "api2": api2}


rule_distribution = rule_distribution.filter(
    pl.col("rule").str.count_matches(r"^[0-9_]+\.json$").gt(0)
)
rule_distribution = rule_distribution.with_columns(
    pl.col("rule")
    .map_elements(
        lambda r: get_apis_as_struct(r),
        return_dtype=pl.Struct({"api1": pl.String(), "api2": pl.String()}),
    )
    .alias("combined")
).unnest("combined")

rule_distribution.write_csv("detection_rules_for_basebridge.txt")
# %%
score_chart
# %%
count_chart

# %%
# Checkpoint
import data_preprocess.rule as rule_lib
from pathlib import Path
import data_preprocess.behavior_map as bm
import networkx as nx
import polars as pl
from tqdm import tqdm

rules = rule_lib.load_list(
    "/mnt/storage/rule_score_auto_adjust/rule_selected_by_ai.csv"
)


def get_weakly_connected_rules(graph: nx.Graph, rule_name: str) -> list[str]:
    components_with_node = (
        c
        for c in nx.connected_components(graph)
        if any(rule_name in graph.nodes[n].get("rules", {}) for n in c)
    )

    return [
        r
        for c in components_with_node
        for n in c
        for r in graph.nodes[n].get("rules", [])
    ]


for dot in tqdm(
    Path("/mnt/storage/rule_score_auto_adjust/classifications/cleaned").glob(
        "*.dot"
    )
):
    graph = bm.load_dot_to_networkx(str(dot)).to_undirected()

    rules = rules.with_columns(
        pl.col("rule")
        .map_elements(
            lambda rule: get_weakly_connected_rules(graph, rule),
            return_dtype=pl.List(pl.String()),
        )
        .alias(dot.stem)
    )

# 因為有 nest data 所以改寫 parquet 格式
rules.write_parquet("./connected_rules.parquet")
# %%
# Checkpoint
# 讀取寫入的檔案
import polars as pl

rules = pl.read_parquet("./connected_rules.parquet")

# %%
# 計算每個 rule 的 connected rules 數量
rules_with_connected_num = (
    rules.with_columns(
        pl.concat_list(rules.columns).list.unique().alias("num_of_connected")
    )
    .with_columns(pl.col("num_of_connected").list.len())
    .sort(by="num_of_connected", descending=True)
)
rules_with_connected_num.select("rule", "num_of_connected")

# %%
# 計算單一 connected components 有多大
rules_with_max_len = rules.with_columns(
    pl.max_horizontal(
        [
            pl.col(c).list.len()
            for c in rules.columns
            if c not in ["rule", "num_of_connected"]
        ]
    ).alias("max_len")
).sort(by="max_len", descending=True)
rules_with_max_len.select("rule", "max_len")

# %%
# 計算所有 connected rules 數量
rule_lists = rules.select(pl.concat_list(rules.columns).list.unique())[
    "rule"
].to_list()
all_co_work_rules = {r for rule_list in rule_lists for r in rule_list}
print(len(all_co_work_rules))
# %%
# 針對每個樣本繪製經過篩選之規則的 Behavior Map
import networkx as nx
from tqdm import tqdm


def build_rule_graph(rule: str, connected_rules: list[str]) -> nx.Graph:
    G = nx.Graph()

    # 確保所有節點都被加入圖中
    G.add_node(rule)
    G.add_nodes_from(connected_rules)

    # 將 rule 與每個 connected_rule 建立連線
    for r in connected_rules:
        G.add_edge(rule, r)

    return G


sha256s = rules.columns
sha256s.remove("rule")

graphs = {
    sha256: nx.compose_all(
        (
            build_rule_graph(rule, connected_rules)
            for rule, connected_rules in tqdm(
                rules.select("rule", sha256).iter_rows(), total=len(rules)
            )
        )  # type: ignore
    )
    for sha256 in tqdm(rules.columns, desc="Processing")
    if sha256 != "rule"
}

sha256, graph_with_max_components = max(
    graphs.items(), key=lambda e: sum(1 for _ in nx.connected_components(e[1]))
)
print(sha256)
# %%
# 移除 size 為 1 的 connected components
from functools import reduce

for sha256, graph in graphs.items():
    single_node_components = [
        component
        for component in nx.connected_components(graph)
        if len(component) == 1
    ]

    node_to_remove = reduce(
        lambda s1, s2: s1.union(s2), single_node_components
    )
    graphs[sha256].remove_nodes_from(node_to_remove)

sha256, graph_with_max_components = max(
    graphs.items(), key=lambda e: sum(1 for _ in nx.connected_components(e[1]))
)
print(sha256)
# %%
nx.draw(graphs["D7EE7A41F36958AE62E5434395190E1F427C415260DBD4FB62FD2900C0DCAAE2"])
# %%
