import datetime
from pathlib import Path
import resource
import subprocess
import tempfile

import click
from prefect import flow, task
from tools.backup.collect_rules_to_folder import (
    collect_rules_to_folder_from_apk_prediction,
    collect_rules_to_folder,
    create_symbolic_links_to_rules,
)
import data_preprocess.apk as apk_lib
import polars as pl
import shutil
import prefect.cache_policies as cache_policies
from prefect.artifacts import (
    create_progress_artifact,
    update_progress_artifact,
)
from prefect_ray import RayTaskRunner
import data_preprocess.apk as apk_lib


@task
def read_apk_list(apk_list: Path) -> list[str]:
    return apk_lib.read_csv(str(apk_list))["sha256"].to_list()


@task
def download_apk(sha256: str) -> Path | None:
    return apk_lib.download(sha256, dry_run=True)


@task(cache_policy=cache_policies.INPUTS, log_prints=True)
def create_behavior_map_folder():
    out_folder = Path(tempfile.TemporaryDirectory(prefix="behavior_map_", delete=False).name)
    print(f"Behavior Map Folder: {out_folder}")
    return out_folder


@task(
    cache_policy=cache_policies.INPUTS,
    cache_expiration=datetime.timedelta(days=31),
)
def generate_behavior_map(
    apk: Path, rule_folder: Path, out_folder: Path
) -> tuple[Path, Path, Path] | None:
    with tempfile.TemporaryDirectory() as working_folder:
        commands = [
            "quark",
            "-a",
            str(apk),
            "-r",
            str(rule_folder),
            "-s",
            "-c",
        ]
        try:
            print(f"Running command: {' '.join(commands)} at {str(out_folder)}")
            subprocess.run(args=commands, check=True, cwd=working_folder)

            print(f"Generated behavior map for {apk} in {working_folder}.")

            working_path = Path(working_folder)
            dot_path = (out_folder / apk.name).with_suffix(".dot")
            shutil.move(
                (working_path / "rules_classification"),
                dot_path,
            )
            json_path = (out_folder / apk.name).with_suffix(".json")
            shutil.move(
                (working_path / "rules_classification.json"),
                json_path,
            )
            png_path = (out_folder / apk.name).with_suffix(".png")
            shutil.move(
                (working_path / "rules_classification.png"),
                png_path,
            )

            return (dot_path, json_path, png_path)
        except subprocess.CalledProcessError as e:
            print(f"Error generating behavior map for {apk}: {e}")
            return None


@task
def generate_behavior_maps(
    apk_paths: list[Path],
    rule_folder: Path,
) -> Path:
    # Create temp folder
    out_folder = create_behavior_map_folder()

    # Run Quark to generate behavior map
    # Create a progress artifact to record the progress of behavior map generation
    progress_artifact_id = create_progress_artifact(
        progress=0.0,
        description="Indicates the progress of behavior map generation",
    )
    step = 100 / len(apk_paths)

    # Submit tasks to generate behavior maps
    futures = (generate_behavior_map.submit(apk, rule_folder, out_folder) for apk in apk_paths)

    # Wait for all tasks to complete and update the progress artifact
    for idx, future in enumerate(futures):
        future.result()
        update_progress_artifact(artifact_id=progress_artifact_id, progress=step * (idx + 1))  # type: ignore

    return out_folder


@flow
def generate_behavior_map_from_apk_prediction(apk_prediction: Path, apk_list: Path) -> Path:
    rule_folder = collect_rules_to_folder_from_apk_prediction(apk_prediction)
    print(f"{rule_folder=}")

    return generate_behavior_map_from_apk_list_and_rule_folder(
        apk_list=apk_list, rule_folder=rule_folder
    )


@flow
def generate_behavior_map_from_apk_list_and_rule_list(
    apk_list: Path, rule_list: Path, add_builtin_rules: bool
) -> Path:
    rule_names = pl.read_csv(str(rule_list))["rule"].to_list()

    rule_folder = collect_rules_to_folder(rule_names=rule_names)
    print(f"{rule_folder=}")

    if add_builtin_rules:
        builtin_rule_folder = Path("/mnt/storage/quark-rules/rules")
        builtin_rules = builtin_rule_folder.glob("*.json")
        create_symbolic_links_to_rules(
            rules=list(builtin_rules),
            rule_folder=rule_folder,
        )

    return generate_behavior_map_from_apk_list_and_rule_folder(
        apk_list=apk_list, rule_folder=rule_folder
    )


@flow(task_runner=RayTaskRunner())  # type: ignore
def generate_behavior_map_from_apk_list_and_rule_folder(apk_list: Path, rule_folder: Path) -> Path:
    sha256s = pl.read_csv(str(apk_list), columns=["sha256"]).to_series().to_list()

    apk_paths = [apk for apk in download_apk.map(sha256s).result() if apk is not None]

    behavior_map_folder = generate_behavior_maps(
        apk_paths,
        rule_folder,
    )

    return behavior_map_folder


@click.command()
@click.option(
    "--apk_list", "-a", type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path)
)
@click.option(
    "--rule_folder",
    "-r",
    type=click.Path(exists=True, file_okay=False, readable=True, path_type=Path),
)
def entry_point(apk_list: Path, rule_folder: Path) -> None:
    """Generate behavior map from a list of APKs and a rule folder.

    Example usage:
    uv run tools/generate_behavior_map.py -a /mnt/storage/data/rule_to_release/droidkungfu/droidkungfu.csv -r /mnt/storage/quark-rules/rules/

    """
    apk_list = apk_list.resolve()
    rule_folder = rule_folder.resolve()
    behavior_map_folder = generate_behavior_map_from_apk_list_and_rule_folder(
        apk_list=apk_list,
        rule_folder=rule_folder,
    )

    print(f"Behavior map folder created at: {behavior_map_folder}")


if __name__ == "__main__":
    mem_bytes = 22 * 1024 * 1024 * 1024  # 22 GB
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        limit = mem_bytes if hard == resource.RLIM_INFINITY else min(mem_bytes, hard)
        resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
    except (ValueError, OSError):
        pass
    entry_point()
