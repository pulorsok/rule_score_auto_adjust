import enum
import multiprocessing
import os
import sys
from pathlib import Path
import resource
from typing import Literal
import click
import diskcache
from quark.rulegeneration import RuleGeneration
import polars as pl
import tempfile
import dotenv
from tqdm import tqdm
from prefect import task, flow
from prefect_ray import RayTaskRunner
import data_preprocess.rule as rule_lib

dotenv.load_dotenv()

# CPU count: read from env, default to half of available CPUs (min 1, max 8)
_default_cpus = max(1, min(8, multiprocessing.cpu_count() // 2))
_GENERATE_CPUS = int(os.environ.get("GENERATE_RULES_CPUS", _default_cpus))
# Memory limit per Ray worker (bytes): read from env, default to 2 GB
_OBJECT_STORE_MB = int(os.environ.get("GENERATE_RULES_OBJECT_STORE_MB", 2048))
# macOS: Ray hard-limits object store to 2 GB; cap automatically
_MACOS_OBJECT_STORE_LIMIT = 2048
if sys.platform == "darwin" and _OBJECT_STORE_MB > _MACOS_OBJECT_STORE_LIMIT:
    print(f"[generate_rules] macOS: object store capped {_OBJECT_STORE_MB} → {_MACOS_OBJECT_STORE_LIMIT} MB")
    _OBJECT_STORE_MB = _MACOS_OBJECT_STORE_LIMIT
# Max APIs per pool (0 = no limit); limits N×N combinations for testing
_MAX_APIS = int(os.environ.get("GENERATE_RULES_MAX_APIS", 0))
print(f"[generate_rules] Using {_GENERATE_CPUS} CPUs, {_OBJECT_STORE_MB} MB object store, max_apis={_MAX_APIS or 'unlimited'}")


class GENERATE_STATUS(enum.Enum):
    SUCCESS = "success"
    FAILED = "failed"
    NOT_TRIED = "not_tried"


class _LimitedRuleGeneration(RuleGeneration):
    """RuleGeneration subclass that truncates API pools for faster testing."""
    def __init__(self, apk, output_dir, max_apis: int = 0):
        super().__init__(apk, output_dir)
        if max_apis > 0:
            self.first_api_set = set(list(self.first_api_set)[:max_apis])
            self.second_api_set = set(list(self.second_api_set)[:max_apis])
            print(f"[generate_rules] API pool limited to {max_apis} (was larger)")


@task(log_prints=True)
def generate_rules_for_apk(apk_path: str, output_folder: str) -> Literal[GENERATE_STATUS.SUCCESS, GENERATE_STATUS.FAILED]:
    try:
        max_apis = int(os.environ.get("GENERATE_RULES_MAX_APIS", 0))
        _LimitedRuleGeneration(apk_path, output_folder, max_apis=max_apis).generate_rule()
        print(f"Rules generated and saved to {output_folder}")
        return GENERATE_STATUS.SUCCESS

    except Exception as e:
        print(f"Failed to generate rules for {apk_path}: {e}")
        return GENERATE_STATUS.FAILED


@task(log_prints=True)
def rename_rule_files_in_folder_recursively(target_folder: Path) -> None:
    print(f"Renaming rule files in {target_folder}")
    for rule_file in target_folder.rglob("*.json"):
        new_file = rule_file.with_stem(rule_lib.get_hash(str(rule_file)))
        if new_file.exists():
            print(f"File {new_file} already exists. Skipping rename.")
            continue

        print(f"Renaming rule file {rule_file} to {new_file.name}.")
        rule_file.rename(new_file)

    print(f"Renaming completed in {target_folder.resolve()}")

@task(log_prints=True)
def create_rule_links(target_folder: Path, source_folder: Path) -> None:
    print(f"Linking rules from {source_folder} to {target_folder}")
    for rule in source_folder.rglob("*.json"):
        target_rule_path = target_folder / rule.name
        if target_rule_path.exists():
            print(f"Rule {target_rule_path} already exists. Skipping link.")
            continue
        
        print(f"Linking rule {rule} to {target_rule_path}.")
        target_rule_path.symlink_to(rule.resolve())
        
    print(f"Linking completed. Rules linked to {target_folder.resolve()}")
    

@flow(name="generate_rules_from_apk_list",
      task_runner=RayTaskRunner(init_kwargs={
          "num_cpus": _GENERATE_CPUS,
          "object_store_memory": _OBJECT_STORE_MB * 1024 * 1024,
      }),
      log_prints=True)  # type: ignore
def generate_rules_for_apk_list(apk_lists: list[Path], output_folder: Path, rerun_failed: bool = False):
    cache = diskcache.FanoutCache(f"{output_folder}/rule_generation_cache")

    output_folder = output_folder or Path(tempfile.gettempdir())
    print(f"Output folder for rules: {output_folder.resolve()}")

    apk_folder = Path(os.environ["APK_FOLDER"])
    print(f"APK folder: {apk_folder.resolve()}")

    print(f"Rerun failed APKs: {rerun_failed}")

    apk_table = pl.concat(
        [pl.read_csv(apk_path, columns=["sha256"]) for apk_path in apk_lists], how="vertical"
    ).with_columns(
        pl.col("sha256").map_elements(lambda x: str(apk_folder / f"{x}.apk"), return_dtype=pl.String).alias("apk_path"),
        pl.col("sha256")
        .map_elements(lambda x: str(output_folder / x), return_dtype=pl.String)
        .alias("rule_output_folder"),
    )

    # Submit tasks to generate rules for each APK
    print(f"Total APKs to process: {len(apk_table)}")
    futures = []
    for row in apk_table.iter_rows(named=True):
        if not os.path.exists(row["apk_path"]):
            print(f"APK {row["apk_path"]} does not exist. Skipping.")
            continue

        if row["sha256"] not in cache or (rerun_failed and cache.get(row["sha256"]) == GENERATE_STATUS.FAILED):
            os.makedirs(row["rule_output_folder"], exist_ok=True)

            print(f"Generating rules for {row['sha256']} at {row['rule_output_folder']}")
            future = generate_rules_for_apk.submit(row["apk_path"], row["rule_output_folder"])
            
            futures.append((row["sha256"], future))
        else:
            print(f"Rules for {row['sha256']} already generated with status: {cache.get(row['sha256'])}. Skipping.")

    total_futures = len(futures)
    print(f"PROGRESS:0/{total_futures}")  # machine-readable progress marker
    # Wait for all tasks to complete and collect results
    for i, (sha256, future) in enumerate(tqdm(futures, desc="Generating rules"), start=1):
        try:
            status = future.result()
        except Exception as e:
            # Ray WorkerCrashedError (OOM, SIGSEGV, etc.) — treat as failed and continue
            print(f"Worker crashed for {sha256}: {type(e).__name__}: {e}")
            status = GENERATE_STATUS.FAILED
        cache.set(sha256, status)
        if status == GENERATE_STATUS.SUCCESS:
            print(f"Successfully generated rules for {sha256}")
        else:
            print(f"Failed to generate rules for {sha256}")
        print(f"PROGRESS:{i}/{total_futures}")  # machine-readable progress marker

    print(f"Rule generation completed. Output folder: {output_folder.resolve()}")


@click.command()
@click.option(
    "--apk_list",
    "-a",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    multiple=True,
    help="List of APKs to process.",
)
@click.option(
    "--working_folder",
    "-w",
    type=click.Path(path_type=Path),
    required=False,
    envvar="RULE_FOLDER",
    default=Path("working_folder"),
    help="Folder to save generated rules, defaults to RULE_FOLDER environment variable.",
)
@click.option(
    "--output_folder",
    "-o",
    type=click.Path(path_type=Path),
    required=False,
    default=Path("output_folder"),
    help="Folder to flat the generated rules, defaults to a temp folder.",
)
@click.option(
    "--rerun_failed/--no-rerun-failed",
    is_flag=True,
    default=False,
    help="Rerun rule generation for APKs that previously failed.",
)
def generate_and_collect_rules(apk_list: list[Path], working_folder: Path, output_folder: Path, rerun_failed: bool) -> None:
    """
    Generate rules from a list of APKs and save them to the specified output folder.

    Example usage:
    uv run tools/generate_rules.py -a data/lists/maliciousAPKs_test.csv -w data/generated_rules -o data/rules/
    """
    working_folder.mkdir(exist_ok=True)
    output_folder.mkdir(exist_ok=True)
    
    generate_rules_for_apk_list(apk_list, working_folder, rerun_failed)
    
    rename_rule_files_in_folder_recursively(working_folder)
    
    create_rule_links(output_folder, working_folder)
    
    print(f"Rule generation completed. Rules saved to {working_folder.resolve()}")


if __name__ == "__main__":
    mem_bytes = 22 * 1024 * 1024 * 1024  # 20 GB
    try:
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    except (ValueError, resource.error):
        pass  # macOS does not support RLIMIT_AS; safe to skip
    generate_and_collect_rules()
