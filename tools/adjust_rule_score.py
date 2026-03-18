"""
This script is a command-line tool for adjusting rule scores for malware detection.

It can be used to start a fresh training run or continue a previous one.
The learning rates and epochs for training are configurable.

Example usage:

To start a fresh run:
python tools/adjust_rule_score.py --target-family <family_name> --lrs 0.1,0.05 --epochs 50

To continue a previous run:
python tools/adjust_rule_score.py --run-id <mlflow_run_id> --lrs 0.01 --epochs 50
"""

import copy
import datetime
import os
import sys
from dataclasses import dataclass
from itertools import count
from pathlib import Path
import tempfile
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Tuple,
)

import click
import dotenv
import mlflow
import mlflow.pytorch
import polars as pl
import torch
import tqdm
from mlflow.entities import Run
from mlflow.pytorch import log_model
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from torch.optim import Optimizer
from torch.utils.data.dataloader import DataLoader
import data_preprocess.apk as apk_lib

import data_preprocess.analysis_result as analysis_result_lib
from data_preprocess import dataset as dataset_lib
from model import RuleAdjustmentModel

dotenv.load_dotenv()


@dataclass()
class ApkInfo:
    sha256: str
    is_malicious: int
    path: Optional[Path]
    analysis_result: Optional[Dict[str, int]]

    def __init__(self, sha256: str, is_malicious: int, rule_paths: List[Path]):
        self.sha256 = sha256
        self.is_malicious = is_malicious
        self.path = apk_lib.download(sha256, dry_run=True)

        if self.path is not None:
            self.analysis_result = analysis_result_lib.analyze_rules(
                sha256, self.path, rule_paths  # dry_run=False: run analysis if not cached
            )
        else:
            self.analysis_result = {}


def show_and_filter(
    apk_info_list: Iterable[ApkInfo], filter_func: Callable[[ApkInfo], bool]
) -> Generator[ApkInfo, None, None]:
    to_drop = []

    for apk_info in apk_info_list:
        if filter_func(apk_info):
            to_drop.append(apk_info)
        else:
            yield apk_info

    print(f"Drop {len(to_drop)} APKs")
    if to_drop:
        print("Dropped APKs (sha256):")
        for apk_info in to_drop:
            print(f"  - {apk_info.sha256}")


def train_one_epoch(
    dataloader: DataLoader,
    model: torch.nn.Module,
    loss_fn: torch.nn.Module,
    optimizer: Optimizer,
    device: torch.device,
) -> float:
    total_loss = 0.0

    for batch_idx, data in enumerate(dataloader):
        inputs, labels = data
        inputs, labels = inputs.to(device), labels.to(device)

        optimizer.zero_grad()
        outputs = model(inputs)
        loss = loss_fn(outputs, labels)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    average_loss = total_loss / len(dataloader)
    return average_loss


def load_model_from_path(model_path: str, model: torch.nn.Module) -> None:
    model.load_state_dict(torch.load(model_path, weights_only=True))


def run_epochs(
    learning_rate: float,
    model: torch.nn.Module,
    epochs: int,
    dataloader: DataLoader,
    loss_fn: torch.nn.Module,
    device: torch.device,
) -> Tuple[Optional[str], float]:
    optimizer = torch.optim.SGD(model.parameters(), lr=learning_rate, momentum=0.1)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    epoch_number = 0
    model_path = None
    best_vloss = 1_000_000.0

    for epoch in tqdm.tqdm(list(range(epochs))):
        model.train(True)
        avg_loss = train_one_epoch(
            dataloader=dataloader,
            model=model,
            loss_fn=loss_fn,
            optimizer=optimizer,
            device=device,
        )

        running_vloss = 0.0
        model.eval()

        with torch.no_grad():
            for i, vdata in enumerate(dataloader):
                vinputs, vlabels = vdata
                vinputs, vlabels = vinputs.to(device), vlabels.to(device)
                voutputs = model(vinputs)
                vloss = loss_fn(voutputs, vlabels)
                running_vloss += vloss

        avg_vloss = running_vloss / (i + 1)
        print(
            f"EP {epoch_number + 1}, LR {optimizer.param_groups[0]['lr']}, "
            f"LOSS train {avg_loss} valid {avg_vloss}"
        )

        if avg_vloss < best_vloss:
            best_vloss = avg_vloss
            model_folder = Path(tempfile.gettempdir()) / "model_logs"
            model_folder.mkdir(parents=True, exist_ok=True)
            model_path = str(model_folder / f"model_{timestamp}_{epoch_number}")
            torch.save(model.state_dict(), model_path)

        epoch_number += 1

    return model_path, best_vloss


def model_inference(model: torch.nn.Module, x: torch.Tensor) -> float:
    with torch.no_grad():
        return model(x).item()


def model_calculate(model: torch.nn.Module, x: torch.Tensor) -> Any:
    with torch.no_grad():
        return model.calculate_apk_scores(x)


def prepare_data(
    rule_paths: List[Path],
    path_to_apk_list: List[Path],
    builtin_apk_list: Optional[Path] = None,
) -> Tuple[dataset_lib.ApkDataset, DataLoader, List[str]]:
    """Loads and preprocesses data."""
    rules = [rule.name for rule in rule_paths]

    sha256_table = pl.concat(
        pl.read_csv(p, columns=["sha256", "is_malicious"]) for p in path_to_apk_list
    )
    original_apk_info_list = [
        ApkInfo(sha256, is_malicious, rule_paths)
        for sha256, is_malicious in tqdm.tqdm(
            sha256_table.rows(),
            total=len(sha256_table),
            desc="Preparing APK analysis results",
        )
    ]

    apk_info_list: Iterable[ApkInfo] = original_apk_info_list

    print("Filter out apk not exits.")
    apk_not_exist = lambda info: info.path is None or not info.path.exists()
    apk_info_list = list(show_and_filter(apk_info_list, apk_not_exist))

    print("Filter out apk have no analysis result.")
    apk_no_analysis_result = lambda info: info.analysis_result is None or any(
        v < 0 for v in info.analysis_result.values()
    )
    apk_info_list = list(show_and_filter(apk_info_list, apk_no_analysis_result))

    print("Filter out apk didn't pass 5 stage on any rule.")
    apk_no_passing_5_stage = lambda info: info.analysis_result is None or not any(
        v >= 5 for v in info.analysis_result.values()
    )
    apk_info_list = list(show_and_filter(apk_info_list, apk_no_passing_5_stage))

    print("Filter out apks that Quark failed to analyze due to memory issue.")
    memory_issue_apks = {"00015824995BC2F452BBDE2833F79423A8DC6DA8364A641DFB6D068D44C557DF"}
    apk_info_list = list(
        show_and_filter(apk_info_list, lambda info: info.sha256 in memory_issue_apks)
    )

    print("Balance the dataset by removing extra benign APKs.")
    benign_counter = count()
    num_of_malware = sum(1 for info in apk_info_list if info.is_malicious == 1)
    malicious_or_enough_benign = (
        lambda info: info.is_malicious != 1 and next(benign_counter) >= num_of_malware
    )
    apk_info_list = list(show_and_filter(apk_info_list, malicious_or_enough_benign))

    malware_sha256 = {apk.sha256 for apk in original_apk_info_list if apk.is_malicious == 1}
    all_sha256s = {apk.sha256 for apk in apk_info_list}
    missing_malware = [m for m in malware_sha256 if m not in all_sha256s]
    # assert len(missing_malware) == 0, f"Missing malware samples: {missing_malware}"

    builtin_samples = (
        pl.read_csv(builtin_apk_list, columns=["sha256"])["sha256"].to_list()
        if builtin_apk_list
        else []
    )
    missing_apks = [sha256 for sha256 in builtin_samples if sha256 not in all_sha256s]
    assert len(missing_apks) == 0, f"Missing builtin samples: {missing_apks}"

    dataset_obj = dataset_lib.ApkDataset(
        sha256s=[apk.sha256 for apk in apk_info_list],
        is_malicious=[apk.is_malicious for apk in apk_info_list],
        rules=rules,
    )
    print(f"Num of APK: {len(dataset_obj)}")
    print(f"APK distribution: {dataset_obj.apk_info['is_malicious'].value_counts()}")
    print(f"Num of rules: {len(dataset_obj.rules)}")

    dataset_obj.preload()

    dataloader = DataLoader(dataset_obj, batch_size=len(dataset_obj), shuffle=True)
    return dataset_obj, dataloader, rules


def setup_model(num_rules: int) -> Tuple[RuleAdjustmentModel, torch.device, torch.nn.Module]:
    """Initializes model, device, and loss function."""
    if torch.cuda.is_available():
        device = torch.device("cuda")
    elif torch.backends.mps.is_available():
        device = torch.device("mps")  # Apple Silicon
    else:
        device = torch.device("cpu")
    print(f"[setup_model] using device: {device}")

    model = RuleAdjustmentModel(num_rules)
    model = model.to(device)
    loss_fn = torch.nn.BCELoss().to(device)
    return model, device, loss_fn


def setup_mlflow(
    run_id: Optional[str],
    target_family: Optional[str],
    model: torch.nn.Module,
    path_to_apk_list: List[Path],
) -> Tuple[Run, int]:
    """Sets up MLflow for a new or resumed run."""
    # Use local file-based tracking if no server is running
    mlflow_uri = os.getenv("MLFLOW_TRACKING_URI", "")
    if not mlflow_uri:
        mlflow_dir = Path(os.getenv("MLFLOW_LOCAL_DIR", "mlruns"))
        mlflow_dir.mkdir(parents=True, exist_ok=True)
        mlflow_uri = mlflow_dir.resolve().as_uri()   # file:///...
    mlflow.set_tracking_uri(uri=mlflow_uri)
    step = 0
    if run_id:
        run = mlflow.start_run(run_id=run_id)
        client = mlflow.tracking.MlflowClient()
        artifacts = client.list_artifacts(run_id)
        checkpoints = [a.path for a in artifacts if a.path.startswith("checkpoint_")]

        if checkpoints:
            latest_checkpoint = max(checkpoints, key=lambda p: int(p.split("_")[-1]))
            step = int(latest_checkpoint.split("_")[-1])
            local_path = mlflow.artifacts.download_artifacts(
                run_id=run_id, artifact_path=latest_checkpoint
            )
            model.load_state_dict(torch.load(local_path))
            print(f"Resuming from run {run_id} at step {step} from checkpoint {latest_checkpoint}")
    else:
        if not target_family:
            families = {p.stem for p in path_to_apk_list}
            target_family = click.prompt(
                "Input the family name",
                default=next(iter(families), "unknown_family"),
            )

        families = {p.stem for p in path_to_apk_list}
        families.add(target_family)  # type: ignore

        experiment_name = f"adjust_rule_score_for_{target_family}"
        experiment = mlflow.set_experiment(experiment_name)
        mlflow.set_experiment_tag("families", " ".join(sorted(families)))

        run_name = datetime.datetime.now().isoformat(timespec="seconds")
        run = mlflow.start_run(experiment_id=experiment.experiment_id, run_name=run_name)

        model_module = sys.modules[model.__class__.__module__]
        code_path = None
        if (
            model_module is not None
            and hasattr(model_module, "__file__")
            and model_module.__file__ is not None
        ):
            code_path = [str(Path(model_module.__file__).resolve())]

        log_model(pytorch_model=model, code_paths=code_path)
    return run, step


def train_model(
    lrs: List[float],
    epochs: int,
    model: torch.nn.Module,
    dataloader: DataLoader,
    loss_fn: torch.nn.Module,
    device: torch.device,
    step: int,
    dataset_obj: dataset_lib.ApkDataset,
) -> Tuple[Optional[str], int, float]:
    """Main training loop."""
    accuracy = 0.0
    best_model_param_path = None
    best_vloss = 1_000_000.0

    for lr in lrs:
        if accuracy == 1.0:
            break

        mlflow.log_metrics({"learning_rate": lr, "epochs": epochs}, step=step)

        current_best_path, current_vloss = run_epochs(
            lr, model, epochs, dataloader, loss_fn, device
        )
        if current_best_path is not None:
            if current_vloss < best_vloss:
                best_vloss = current_vloss
                best_model_param_path = current_best_path

        step += epochs

    if best_model_param_path:
        load_model_from_path(best_model_param_path, model)

    x_input, y_truth = [], []
    for x, y in dataset_obj:
        x_input.append(x.to(device))
        y_truth.append(y)

    y_pred_row = [model_inference(model, x) for x in x_input]
    y_pred = [1 if y_row > 0.5 else 0 for y_row in y_pred_row]

    accuracy = float(accuracy_score(y_truth, y_pred))
    precision = float(precision_score(y_truth, y_pred))
    recall = float(recall_score(y_truth, y_pred))
    f1 = float(f1_score(y_truth, y_pred))
    print(f"{accuracy=}")
    print(f"{precision=}")
    print(f"{recall=}")
    print(f"{f1=}")

    mlflow.pytorch.log_state_dict(model.state_dict(), artifact_path=f"checkpoint_{step}")

    mlflow.log_metrics(
        {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        step=step,
    )
    return best_model_param_path, step, best_vloss


def log_results(
    model: torch.nn.Module,
    dataset_obj: dataset_lib.ApkDataset,
    device: torch.device,
    rule_paths: Tuple[Path],
    step: int,
    output_csv_path: Path,
) -> None:
    """Logs final results and artifacts."""
    y_truth, y_score, y_pred, accuracy, precision, recall, f1 = calculate_metrics(
        model, dataset_obj, device
    )

    mlflow.log_metrics(
        {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
        step=step,
    )

    apk_prediction = pl.DataFrame(
        {
            "sha256": dataset_obj.apk_info["sha256"],
            "y_truth": y_truth,
            "y_score": y_score,
            "y_pred": y_pred,
        }
    )

    weight_dicts = (
        analysis_result_lib.analyze_rules(
            sha256,
            apk_lib.download(sha256, dry_run=True),
            rule_paths,
            dry_run=True,
        )
        | {"sha256": sha256}
        for sha256 in dataset_obj.apk_info["sha256"]
    )
    weight_dfs = (pl.DataFrame(weight) for weight in weight_dicts)
    weights = pl.concat(weight_dfs, how="vertical")
    weights = weights.transpose(include_header=True, column_names="sha256", header_name="rule")

    rule_scores = dataset_obj.rules.join(
        pl.DataFrame(
            {"rule_score": model.get_rule_scores().cpu().detach().tolist()}
        ).with_row_index(),
        on="index",
        how="left",
    )

    weights_and_rule_scores = rule_scores.join(
        weights, on="rule", how="left", maintain_order="left"
    )

    new_column_names = ["sha256", "y_truth", "y_score", "y_pred"] + weights["rule"].to_list()

    combined = (
        weights_and_rule_scores.transpose(
            include_header=True,
            header_name="sha256",
            column_names="rule",
        )
        .join(apk_prediction, on="sha256", how="full", maintain_order="left")
        .select(new_column_names)
    )

    combined.write_csv(output_csv_path, include_header=True)
    mlflow.log_artifact(str(output_csv_path), Path(output_csv_path).name)


def calculate_metrics(model, dataset_obj, device):
    x_input, y_truth = [], []
    for x, y in dataset_obj:
        x_input.append(x.to(device))
        y_truth.append(y)

    y_pred_row = [model_inference(model, x) for x in x_input]
    y_score = [model_calculate(model, x) for x in x_input]
    y_pred = [1 if y_row > 0.5 else 0 for y_row in y_pred_row]

    accuracy = accuracy_score(y_truth, y_pred)
    precision = precision_score(y_truth, y_pred)
    recall = recall_score(y_truth, y_pred)
    f1 = f1_score(y_truth, y_pred)
    print(f"{accuracy=}")
    print(f"{precision=}")
    print(f"{recall=}")
    print(f"{f1=}")
    return y_truth, y_score, y_pred, accuracy, precision, recall, f1


@click.command()
@click.option(
    "--run-id",
    "run_id",
    type=str,
    default=None,
    help="MLFlow run ID to continue a previous run.",
)
@click.option(
    "--lrs",
    "lrs_str",
    type=str,
    default="0.1",
    help="Comma-separated learning rates.",
)
@click.option(
    "--epochs", "epochs", type=int, default=100, help="Number of epochs for each learning rate."
)
@click.option(
    "--target-family",
    "target_family",
    type=str,
    default=None,
    help="Target family for the experiment.",
)
@click.option(
    "--rule-folder",
    "rule_folder",
    multiple=True,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    help="Path to a rule folder. Can be specified multiple times.",
)
@click.option(
    "--apk-list",
    "apk_list",
    multiple=True,
    default=(
        "data/lists/family/droidkungfu.csv",
        "data/lists/family/basebridge.csv",
        "data/lists/family/golddream.csv",
        "data/lists/benignAPKs_top_0.4_vt_scan_date.csv",
    ),
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    help="Path to an APK list file. Can be specified multiple times.",
)
@click.option(
    "--output-csv",
    "output_csv_path",
    default="apk_prediction.csv",
    type=click.Path(file_okay=True, dir_okay=False, writable=True, path_type=Path),
    help="Path to save the output CSV file.",
)
def main(
    run_id: Optional[str],
    lrs_str: str,
    epochs: int,
    target_family: Optional[str],
    rule_folder: Tuple[Path, ...],
    apk_list: Tuple[Path, ...],
    output_csv_path: Path,
) -> None:
    """Main function for the CLI tool."""
    lrs = [float(lr) for lr in lrs_str.split(",")]

    rule_paths = [
        rule for folder in rule_folder for rule in folder.rglob("*.json") if rule.is_file()
    ]

    dataset_obj, dataloader, rules = prepare_data(rule_paths, list(apk_list))
    model, device, loss_fn = setup_model(len(rules))
    run, step = setup_mlflow(run_id, target_family, model, list(apk_list))

    best_model_param_path, step, best_vloss = train_model(
        lrs, epochs, model, dataloader, loss_fn, device, step, dataset_obj
    )

    current_lrs = lrs

    while True:
        try:
            print(f"\nCurrent learning rates: {current_lrs}")
            prompt = (
                "Enter new learning rates (comma-separated), "
                "'r' to restore best model,"
                "\nor 'c' to proceed to the next step: "
            )
            user_input = input(prompt).strip()

            if not user_input:
                continue

            if user_input.lower() == "r":
                if best_model_param_path:
                    print(f"Restoring model from {best_model_param_path} with vloss {best_vloss}")
                    load_model_from_path(best_model_param_path, model)
                else:
                    print("No best model to restore yet.")
                continue

            elif user_input.lower() == "c":
                print("Proceed to the next step")
                break

            new_lrs = [float(lr) for lr in user_input.split(",")]
            current_lrs = new_lrs

            new_best_path, step, new_vloss = train_model(
                new_lrs, epochs, model, dataloader, loss_fn, device, step, dataset_obj
            )

            if new_best_path and new_vloss < best_vloss:
                best_model_param_path = new_best_path
                best_vloss = new_vloss

        except EOFError:
            print("\nExiting interactive training session.")
            break
        except (ValueError, IndexError):
            print("Invalid input. Please enter a comma-separated list of numbers.")

    if best_model_param_path:
        load_model_from_path(best_model_param_path, model)
    mlflow.pytorch.log_state_dict(model.state_dict(), artifact_path="global_best")

    log_results(model, dataset_obj, device, list(rule_paths), step, output_csv_path)

    # Enter a loop to allow user to round model scores in various precisions
    model_score_backup = model.state_dict()
    while True:
        try:
            precision_input = input(
                "\nEnter the number of decimal places to round rule scores,"
                "\n'r' to revert rule scores,"
                "\n's' to show current rule scores,"
                "\n'x' to multiply the rule score by 10,"
                "\n'n' to reset the current rule scores,"
                "\n't' to test the performance,"
                "\nor 'c' to exit (default is 2): "
            ).strip()
            if not precision_input:
                continue

            if precision_input.lower() == "r":
                print("Reverting the sign of the model scores.")
                current_model_scroes = model.state_dict()
                current_model_scroes["rule_score"] = torch.negative(
                    current_model_scroes["rule_score"]
                )
                model.load_state_dict(current_model_scroes)
                print()
                continue

            elif precision_input.lower() == "s":
                print("Showing the current model scores")
                current_model_scroes = model.state_dict()
                print(current_model_scroes["rule_score"])
                print()
                continue

            elif precision_input.lower() == "t":
                print("Testing the performance with current model scores")
                calculate_metrics(model, dataset_obj, device)
                print()
                continue

            elif precision_input.lower() == "n":
                print("Reset the model scores to the original values.")
                model.load_state_dict(model_score_backup)
                print()
                continue

            elif precision_input.lower() == "x":
                print("Multiply the rule score by 10.")
                current_model_scroes = model.state_dict()
                current_model_scroes["rule_score"] = current_model_scroes["rule_score"] * 10
                model.load_state_dict(current_model_scroes)
                print()
                continue
            
            elif precision_input.lower() == "c":
                print("Proceed to the next step")
                break

            precision = int(precision_input)
            if precision < 0:
                print("Please enter a non-negative integer for precision.")
                continue

            rounded_model_scores = copy.deepcopy(model_score_backup)
            rounded_model_scores["rule_score"] = torch.round(
                model_score_backup["rule_score"], decimals=precision
            )

            model.load_state_dict(rounded_model_scores)
            print(f"Rounded rule scores (to {precision} decimal places):")

            calculate_metrics(model, dataset_obj, device)

        except EOFError:
            print("\nExiting rounding session.")
            break
        except ValueError:
            print("Invalid input. Please enter a non-negative integer.")

    print("Save final results with new model scores.")
    log_results(model, dataset_obj, device, rule_paths, step, output_csv_path)
    mlflow.end_run()


if __name__ == "__main__":
    main()
