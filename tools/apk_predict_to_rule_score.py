from pathlib import Path
import click
import polars as pl


@click.command()
@click.option(
    "-a",
    "--apk-predict-csv",
    type=click.Path(
        file_okay=True,
        dir_okay=False,
        exists=True,
        readable=True,
        resolve_path=True,
        path_type=Path,
    ),
    required=True,
    help="Path to the apk_predict csv file",
)
@click.option(
    "-o",
    "--output-csv",
    type=click.Path(file_okay=True, dir_okay=False, resolve_path=True, path_type=Path),
    required=True,
    help="Path to the output csv file",
)
def predict_to_rule_score(apk_predict_csv: Path, output_csv: Path):
    tb = pl.read_csv(apk_predict_csv, n_rows=1)
    result = (
        tb.transpose(include_header=True, header_name="rule")[4:]
        .with_columns(pl.col("column_0").cast(pl.Float32()).alias("score"))
        .select(["rule", "score"])
        .sort(by="score", descending=True)
    )
    result.write_csv(output_csv)


if __name__ == "__main__":
    predict_to_rule_score()
