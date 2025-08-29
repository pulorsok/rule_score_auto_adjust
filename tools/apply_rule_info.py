import functools
from pathlib import Path
import click
import polars as pl
from prefect import flow, task
from tqdm import tqdm
from tools.backup.collect_rules_to_folder import update_rule_content


@task
def get_rule_scores_from(apk_prediction: Path, revert_score: bool) -> list[tuple[str, float]]:
    rule_score_df = (
        pl.read_csv(apk_prediction, n_rows=1, skip_rows_after_header=1)
        .drop(["y_truth", "y_score", "y_pred"], strict=False)
        .transpose(include_header=True, column_names="sha256", header_name="rule")
    )

    if revert_score:
        rule_score_df = rule_score_df.select(
            pl.col("rule"), (pl.col("rule_score") * -1).alias("rule_score")
        )

    return list(rule_score_df.iter_rows(named=False))


@task
def apply_rule_scores(rule_scores: list[tuple[str, float]], rule_base_folder: Path) -> None:
    for rule_name, score in tqdm(rule_scores):
        rule_path = rule_base_folder / rule_name

        update_rule_content(
            rule_path,
            lambda _, content: content | {"score": round(score, 3)},
        )


@task
def get_rule_descriptions_and_labels_from(rule_review: Path) -> pl.DataFrame:
    return pl.read_csv(rule_review, columns=["rule", "description", "label"])


@task
def apply_rule_description_and_labels(
    rule_description_and_labels: pl.DataFrame, rule_base_folder: Path
) -> None:
    def update_crime(name: str, content: dict, description: str, labels: list[str]) -> dict:
        print(f"Update rule {name} with description: {description}")
        return content | {"crime": f"{description}", "label": labels}

    for rule_name, description, label_str in tqdm(
        rule_description_and_labels.iter_rows(named=False)
    ):
        rule_path = rule_base_folder / rule_name
        labels = label_str.split("|")

        update_rule_content(
            rule_path, functools.partial(update_crime, description=description, labels=labels)
        )

@flow
def apply_rule_info(
    apk_prediction: Path,
    rule_review: Path,
    rule_base_folder: Path,
    revert_score: bool,
) -> None:
    rule_scores = get_rule_scores_from(apk_prediction, revert_score)
    apply_rule_scores(rule_scores, rule_base_folder)

    rule_description_and_labels = get_rule_descriptions_and_labels_from(rule_review)
    apply_rule_description_and_labels(rule_description_and_labels, rule_base_folder)

@click.command()
@click.option(
    "--apk_prediction",
    "-a",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the APK prediction CSV file.",
)
@click.option(
    "--rule_info",
    "-r",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the rule information CSV file.",
)
@click.option(
    "--revert_score",
    "-s",
    is_flag=True,
    default=False,
    help="Whether to revert the rule scores.",
)
@click.option(
    "--rule_base_folder",
    "-b",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    required=True,
    help="Base folder where rules are stored.",
)
def entry_point(
    apk_prediction: Path,
    rule_info: Path,
    rule_base_folder: Path,
    revert_score: bool,
):
    """Apply rule information to the rule base folder.

    Example usage:
    uv run tools/apply_rule_info.py \
        -a /mnt/storage/haeter/rule_score_auto_adjust_haeter/apk_prediction.csv \
        -r /mnt/storage/haeter/rule_score_auto_adjust_haeter/rule_reviews.csv \
        -b /mnt/storage/data/generated_rules/
    """
    apply_rule_info(
        apk_prediction=apk_prediction,
        rule_review=rule_info,
        rule_base_folder=rule_base_folder,
        revert_score=revert_score,
    )

if __name__ == "__main__":
    entry_point()
