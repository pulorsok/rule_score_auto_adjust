from pathlib import Path
import click
import polars as pl
import json

@click.command()
@click.option(
    "--rule_lists",
    "-r",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    multiple=True,
    help="List of rule lists to collect.",
)
@click.option(
    "--rule_base_folder",
    "-b",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    required=True,
    help="Base folder where rules are stored.",
)
@click.option(
    "--output_csv",
    "-o",
    type=click.Path(file_okay=True, path_type=Path),
    required=True,
    default=Path("rule_reviews.csv"),
    help="Output CSV file to collect rule information.",
)
def collect_rule_info_to_csv(
    rule_lists: list[Path],
    rule_base_folder: Path,
    output_csv: Path
):
    """
    Collect rule information from multiple lists to a CSV file.
    
    Example usage:
    uv run tools/collect_rule_info_to_csv.py \
        -r /mnt/storage/data/rule_to_release/golddream/rule_added.csv \
        -r /mnt/storage/data/rule_to_release/default_rules.csv \
        -b /mnt/storage/data/generated_rules \
        -o ./rule_reviews.csv
    """
    
    info_table = pl.concat(
        [
            pl.read_csv(rule_list, has_header=True, columns=["rule"])
            for rule_list in rule_lists
        ],
        how="vertical",
    )

    schema = pl.Struct(
        [
            pl.Field("description", pl.String()),
            pl.Field("api1", pl.String()),
            pl.Field("api2", pl.String()),
            pl.Field("label", pl.String()),
        ]
    )

    def get_description(rule: str):
        rule_path = rule_base_folder / rule
        with rule_path.open("r") as content:
            json_obj = json.loads(content.read())
            api_pair = json_obj["api"]

        api1 = api_pair[0]["class"] + api_pair[0]["method"] + api_pair[0]["descriptor"]
        api2 = api_pair[1]["class"] + api_pair[1]["method"] + api_pair[1]["descriptor"]

        return {
            "description": json_obj["crime"],
            "api1": api1,
            "api2": api2,
            "label": "|".join(json_obj.get("label", [])),
        }

    info_table = (
        info_table.with_columns(
            pl.col("rule")
            .map_elements(get_description, return_dtype=schema, strategy="thread_local")
            .alias("combined")
        )
        .unnest("combined")
        .select(["rule", "description", "label", "api1", "api2"])
    )

    info_table.write_csv(output_csv)
    
    print(f"Collected {len(info_table)} rule info to {output_csv}")

if __name__ == "__main__":
    collect_rule_info_to_csv()
