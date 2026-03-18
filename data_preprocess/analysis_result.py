import os
from pathlib import Path
import json
import enum
from warnings import deprecated
from diskcache import FanoutCache
from quark.core.quark import Quark
from quark.core.struct.ruleobject import RuleObject as Rule
import polars as pl
import functools

SCHEMA = {
    "rule_name": pl.String(),
    "passing_stage": pl.Int8(),
}

_PROJECT_ROOT = Path(__file__).parent.parent
_CACHE_FOLDER = os.getenv("CACHE_FOLDER") or str(_PROJECT_ROOT / "data" / "cache")
cache = FanoutCache(f"{_CACHE_FOLDER}/analysis_result_status")


class ANALYSIS_STATUS(enum.Enum):
    SUCCESS: int = 0
    FAILED: int = 1
    NEED_RUN: int = 2


def get_folder() -> Path:
    return Path(os.getenv("ANALYSIS_RESULT_FOLDER") or str(_PROJECT_ROOT / "data" / "analysis_results"))


@deprecated("Use analyze instead")
def get_file_old(sha256: str) -> Path:
    return get_folder() / f"{sha256}.apk_progress.json"

@deprecated("Use analyze instead")
def get_file(sha256: str) -> Path:
    return get_folder() / f"{sha256}.csv"


@deprecated("Use analyze instead")
def load_old(sha256: str) -> tuple[str, int]:
    def parse_item(item: tuple[str, int] | str) -> tuple[str, int]:
        return (item, -1) if isinstance(item, str) else item

    file = get_file_old(sha256=sha256)
    if not file.exists():
        return tuple()

    try:
        with get_file_old(sha256=sha256).open("r") as file:
            content = json.load(file)
            return [parse_item(item) for item in content]
    except json.JSONDecodeError as e:
        print(f"Failed to parser JSON file: {file}")
        return []


@functools.lru_cache(maxsize=512)
def __load_as_dict(sha256: str) -> dict[str, int]:
    return {
        rule: stage
        for rule, stage in __load_as_dataframe(sha256=sha256).rows()
    }


@deprecated("Use analyze instead")
def load_new(sha256: str) -> list[str, int]:
    table = __load_as_dataframe(sha256=sha256)
    return [r for r in table.rows()]


@deprecated("Use analyze instead")
def load(sha256: str) -> list[str, int]:
    combined = [tuple(item) for item in load_new(sha256=sha256)]
    return list(set(combined))


@deprecated("Use analyze instead")
def save(sha256: str, analysis_result: list[str, int]) -> Path:
    file = get_file(sha256=sha256)
    pl.DataFrame(analysis_result, schema=SCHEMA, orient="row").write_csv(
        file, include_header=True
    )
    return file


def __load_as_dataframe(sha256: str) -> pl.DataFrame:
    file = get_file(sha256=sha256)
    if not file.exists():
        return pl.DataFrame()

    table = pl.read_csv(file, schema=SCHEMA, has_header=True)
    return table


def __save_as_dict(sha256: str, analysis_result: dict[str, int]):
    return save(sha256, list(analysis_result.items()))


def _append_result(sha256: str, results: dict[str, int]) -> Path:
    existing_results = __load_as_dict(sha256)

    for rule, stage in results.items():
        if stage > existing_results.get(rule, -1):
            existing_results[rule] = stage

    return __save_as_dict(sha256, existing_results)


@functools.lru_cache(maxsize=6)
def _get_quark(apk_path: Path) -> "Quark":
    return Quark(str(apk_path))


def analyze_rules(
    sha256: str,
    apk_path: Path,
    rule_paths: list[Path],
    use_cache: bool = True,
    dry_run: bool = False,
) -> dict[str, int]:
    results = {
        rule.name: analyze(sha256, rule, apk_path, use_cache, dry_run)
        for rule in rule_paths
    }
    return results


def analyze(
    sha256: str,
    rule_path: Path,
    apk_path: Path,
    use_cache: bool = True,
    dry_run: bool = False,
) -> int:
    assert apk_path.exists(), f"apk_path {apk_path} does not exist"
    assert rule_path.exists(), f"rule_path {rule_path} does not exist"

    subcache = cache.get(sha256, cache.cache(sha256, disk=sha256))

    rule_name = rule_path.name
    if (not use_cache) or rule_name not in subcache:
        existing_result = __load_as_dict(sha256)
        if (use_cache) and rule_name in existing_result:
            # Migrating: Check if result exists in the analysis_result file
            print(f"Find analysis result for {sha256} and {rule_name} in analysis_result file")
            stage = existing_result[rule_name]
            subcache.set(
                rule_name,
                (
                    ANALYSIS_STATUS.SUCCESS
                    if stage >= 0
                    else ANALYSIS_STATUS.FAILED
                ),
            )
        elif not dry_run:
            # Run Quark Analysis
            # print(f"Run Quark Analysis for {sha256} and {rule_name}")
            try:
                rule_obj = Rule(str(rule_path))
                quark = _get_quark(apk_path)
                quark.run(rule_obj)
                # quark.run() returns None; stage count is in rule_obj.check_item
                stage = rule_obj.check_item.count(True)  # 0–5

                _append_result(sha256, {rule_name: stage})
                subcache.set(rule_name, ANALYSIS_STATUS.SUCCESS)

            except Exception as e:
                print(f"Error analyzing {sha256} {rule_name}: {e}")
                subcache.set(rule_name, ANALYSIS_STATUS.FAILED)
    else:
        # print(f"Analysis result for {sha256} and {rule_name} is in cache")
        pass

    match subcache.get(rule_name, ANALYSIS_STATUS.NEED_RUN):
        case ANALYSIS_STATUS.SUCCESS:
            return __load_as_dict(sha256)[rule_name]
        case ANALYSIS_STATUS.FAILED:
            return -1
        case ANALYSIS_STATUS.NEED_RUN:
            return -2
