import hashlib
from pathlib import Path
import tempfile
import mlflow.artifacts
import polars as pl
import os
import dotenv
import json
from collections import defaultdict

dotenv.load_dotenv()

RULE_LIST_SCHEMA = {"rule": pl.String()}


def get_folder() -> Path:
    return Path(os.getenv("RULE_FOLDER"))


def load_list(rule_list: str) -> pl.DataFrame:
    return pl.read_csv(
        rule_list,
        schema_overrides=RULE_LIST_SCHEMA,
        has_header=True,
        columns=list(RULE_LIST_SCHEMA.keys()),
    )


def get(rule_name: str) -> Path:
    rule_path = get_folder() / f"{rule_name}"
    return rule_path


def build_rule_folder(rule_names: list[str], folder: Path) -> Path:
    for rule in rule_names:
        source_rule_path = get(rule)
        target_rule_path = folder / (source_rule_path.name)

        if target_rule_path.exists():
            target_rule_path.unlink()

        target_rule_path.symlink_to(source_rule_path)


def get_hash(rule_path: str) -> str:
    with Path(rule_path).open("r") as content:
        api = json.load(content)["api"]
        api_str = json.dumps(api)
        return hashlib.sha256(api_str.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    rules = get_folder().glob("*.json")

    rule_hash = defaultdict(list)
    rule_to_drop = []
    for rule in rules:
        hash = get_hash(rule)
        if rule.name not in ["00195.json", "00007.json"] and hash in rule_hash:
            if rule.name.startswith("00"):
                dup_rule = rule_hash[hash].pop()
                rule_hash[hash].append(rule)
                rule = dup_rule

            print(f"Found duplicate rule: {rule}, with {rule_hash[hash]}")
            rule_to_drop.append(rule)
        else:
            rule_hash[hash].append(rule)

    print(f"Num of rules: {len(rule_hash)}")

    # Move all rules in rule_to_drop into a new folder
    drop_folder = get_folder() / "drop"
    drop_folder.mkdir(parents=True, exist_ok=True)
    for rule in rule_to_drop:
        rule.replace(drop_folder / rule.name)


def get_apis(rule: str | None = None, rule_path: Path | None = None) -> list[str]:
    if rule_path is None:
        assert rule is not None, f"Please provide rule or rule_path"
        
        rule_path = get(rule)
        
    with rule_path.open("r") as inFile:
         content = json.load(inFile)
         
    def get_api_str(api: dict[str, str]):
        return f'{api["class"]}{api["method"]}{api["descriptor"]}'            
    
    api_strs = [
        get_api_str(api)
        for api in content["api"]
    ]
    
    return api_strs

def with_ai_adjusted_scores(rules: pl.DataFrame, run_id: str):
    import mlflow
    
    prediction_csv = mlflow.artifacts.download_artifacts(
        run_id=run_id,
        artifact_path="apk_prediction.csv"
    )
    
    
class Rules:
    def __init__(self, rule_folder: Path):
        self.rule_folder = rule_folder
        
    def get(self, rule_name: str) -> Path:
        rule_path = self.rule_folder / f"{rule_name}"
        return rule_path
