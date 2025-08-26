# %%
import datetime
from pathlib import Path
import dotenv
import mlflow.pytorch

dotenv.load_dotenv()

PATH_TO_APK_LIST = [
    "data/lists/family/droidkungfu.csv",
    "data/lists/family/basebridge.csv",
    "data/lists/family/golddream.csv",
    "data/lists/benignAPKs_top_0.4_vt_scan_date.csv",
]

PATH_TO_RULE_LIST = [
    "/mnt/storage/data/rule_to_release/golddream/rule_added.csv",
    "/mnt/storage/data/rule_to_release/default_rules.csv"
]

# %%
import data_preprocess.rule as rule_lib
import polars as pl

rules = pl.concat(list(map(rule_lib.load_list, PATH_TO_RULE_LIST)))[
    "rule"
].to_list()
rule_paths = [rule_lib.get(r) for r in rules]

# %%
from dataclasses import dataclass
import data_preprocess.apk as apk_lib
import data_preprocess.analysis_result as analysis_result_lib
import tqdm
from pathlib import Path
import polars as pl


@dataclass()
class ApkInfo:
    sha256: str
    is_malicious: int
    path: Path | None
    analysis_result: dict[str, int] | None

    def __init__(self, sha256: str, is_malicious: int):
        self.sha256 = sha256
        self.is_malicious = is_malicious
        self.path = apk_lib.download(sha256, dry_run=True)

        if self.path is not None:
            self.analysis_result = analysis_result_lib.analyze_rules(
                sha256, self.path, rule_paths, dry_run=True
            )
        else:
            self.analysis_result = {}


sha256_table = pl.concat(list(map(apk_lib.read_csv, PATH_TO_APK_LIST)))
original_apk_info_list = [
    ApkInfo(sha256, is_malicious)
    for sha256, is_malicious in tqdm.tqdm(
        sha256_table.rows(),
        total=len(sha256_table),
        desc="Preparing APK analysis results",
    )
]

# %%
# Prepare to clean the data
from typing import Generator, Iterable, Callable


def show_and_filter(
    apk_info_list: Iterable[ApkInfo], filter_func: Callable[[ApkInfo], bool]
) -> Generator[ApkInfo, None, None]:
    to_drop = []

    for apk_info in apk_info_list:
        if filter_func(apk_info):
            to_drop.append(apk_info)
        else:
            yield apk_info

    print(
        f'Drop {len(to_drop)} APKs, set checkpoint in this function and see "to_drop" for details'
    )
    
    print(to_drop)


apk_info_list = original_apk_info_list
# %%
print("Filter out apk not exits.")
apk_not_exist = lambda info: info.path is None or not info.path.exists()
apk_info_list = show_and_filter(apk_info_list, apk_not_exist)
apk_info_list = list(apk_info_list)

# %%
print("Filter out apk have no analysis result.")
apk_no_analysis_result = lambda info: any(
    v < 0 for v in info.analysis_result.values()
)
apk_info_list = show_and_filter(apk_info_list, apk_no_analysis_result)
apk_info_list = list(apk_info_list)

# %%
print("Filter out apk didn't pass 5 stage on any rule.")
apk_no_passing_5_stage = lambda info: not any(
    v >= 5 for v in info.analysis_result.values()
)
apk_info_list = show_and_filter(apk_info_list, apk_no_passing_5_stage)
apk_info_list = list(apk_info_list)

# %%
print("Filter out apks that Quark failed to analyze due to memory issue.")

memory_issue_apks = {
    "00015824995BC2F452BBDE2833F79423A8DC6DA8364A641DFB6D068D44C557DF"
}

apk_info_list = show_and_filter(
    apk_info_list, lambda info: info.sha256 in memory_issue_apks
)
apk_info_list = list(apk_info_list)

# %%
print("Balance the dataset by removing extra benign APKs.")

from itertools import count

benign_counter = count()
num_of_malware = sum(1 for info in apk_info_list if info.is_malicious == 1)

malicious_or_enough_benign = (
    lambda info: info.is_malicious != 1
    and next(benign_counter) >= num_of_malware
)
apk_info_list = show_and_filter(apk_info_list, malicious_or_enough_benign)
apk_info_list = list(apk_info_list)

# %%
# 確認所有惡意樣本都還存在

malware_sha256 = {
    apk.sha256 for apk in original_apk_info_list if apk.is_malicious == 1
}
all_sha256s = {apk.sha256 for apk in apk_info_list}

missing_malware = [m for m in malware_sha256 if m not in all_sha256s]

assert (
    len(missing_malware) == 0
), f'Some malware is missing, check "missing_malware"'

# %%
# 確認所有內建樣本都還存在（apk-sample.csv）

builtin_sample = apk_lib.read_csv(
    "/mnt/storage/rule_score_auto_adjust/data/lists/family/apk-sample.csv"
)["sha256"].to_list()

missing_apks = [
    sha256 for sha256 in builtin_sample if sha256 not in all_sha256s
]
assert len(missing_malware) == 0, f'Some apk is missing, check "missing_apks"'

# %%
# Build Dataset
from data_preprocess import dataset as dataset_lib

dataset = dataset_lib.ApkDataset(
    sha256s=[apk.sha256 for apk in apk_info_list],
    is_malicious=[apk.is_malicious for apk in apk_info_list],
    rules=rules,
)

print(f"Num of APK: {len(dataset)}")
print(f"APK distribution: {dataset.apk_info['is_malicious'].value_counts()}")
print(f"Num of rules: {len(dataset.rules)}")

# %%
# Preload Dataset into cache
dataset.preload()

# %%
# Create dataloader
from torch.utils.data.dataloader import DataLoader

# dataloader = DataLoader(dataset, batch_size=len(dataset), shuffle=True)
dataloader = DataLoader(dataset, batch_size=len(dataset), shuffle=True)

# %%
# Build Model
from model import (
    RuleAdjustmentModel_NoTotalScore_Percentage,
    RuleAdjustmentModel,
)

model = RuleAdjustmentModel(len(dataset.rules))
# model = RuleAdjustmentModel_NoTotalScore_Percentage(len(dataset.rules))
print(model)

# %%
# Check is CUDA available
import torch

assert torch.cuda.is_available()
device = torch.device("cuda")
model = model.to(device)


# %%
# Loss Function
import torch

# 測試 Loss
loss_fn = torch.nn.BCELoss().to(device)

# 測試數據
y_pred = torch.tensor([0.0, 1.0, 1.0, 1.0, 0.0])  # 模擬不同的預測值
y_exp = torch.tensor([0.0, 1.0, 1.0, 0.0, 0.0])
loss_value = loss_fn(y_pred, y_exp)

print("Loss:", loss_value.item())
best_model_param_path = None

# %%
# Record environment
# TODO - Record dataset to mlflow
import mlflow
from mlflow.pytorch import log_model
import sys
import click
from pathlib import Path

mlflow.set_tracking_uri(uri="http://localhost:5000")

families = {Path(p).stem for p in PATH_TO_APK_LIST}

target_family = click.prompt(
    "Input the family name",
    default=next(
        iter(families),
        "unknown_family",
    ),
)
families.add(target_family)

experiment_name = f"adjust_rule_score_for_{target_family}"
experiment = mlflow.set_experiment(experiment_name)
mlflow.set_experiment_tag("families", " ".join(sorted(families)))

from datetime import datetime
run_name = datetime.now().isoformat(timespec="seconds")
run = mlflow.start_run(experiment_id=experiment.experiment_id, run_name=run_name)

model_module = sys.modules[model.__class__.__module__]
if model_module is None:
    code_path = str(Path(model_module.__file__).resolve())
else:
    code_path = None

# %%
from mlflow.types.schema import Schema, ColSpec
log_model(
    pytorch_model=model,
    code_paths=code_path
)

# %%
# Train
def train_one_epoch(dataloader, model, loss_fn, optimizer):
    total_loss = 0.0

    for batch_idx, data in enumerate(dataloader):
        # Every data instance is an input + label pair
        inputs, labels = data
        inputs, labels = inputs.to(device), labels.to(device)

        # Zero your gradients for every batch!
        optimizer.zero_grad()

        # Make predictions for this batch
        outputs = model(inputs)

        # Compute the loss and its gradients
        loss = loss_fn(outputs, labels)
        loss.backward()

        # Adjust learning weights
        optimizer.step()

        # Gather data and report
        total_loss += loss.item()    
    
    average_loss = total_loss / len(dataloader)
    return average_loss

# %%
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)
import json

def evaluate(dataloader, model):
    model.eval()
    with torch.no_grad():
        
        y_pred_batches, y_truth_batches = [], []
        for x, y_truth in dataloader:
            y_pred_batches.append(model(x).item())
            y_truth_batches.append(y_truth)
        
        y_pred = torch.cat(y_pred_batches, dim=0)
        y_truth = torch.cat(y_truth_batches, dim=0)
        
        metrics = {
            "accuracy": accuracy_score(y_truth, y_pred),
            "precision": precision_score(y_truth, y_pred),
            "recall": recall_score(y_truth, y_pred),
            "f1": f1_score(y_truth, y_pred),
        }
        
        mlflow.log_metrics(metrics)
        print(json.dumps(metrics, indent=4))
        
        

# %%
# Initializing in a separate cell so we can easily add more epochs to the same run
from torch.utils.tensorboard.writer import SummaryWriter
from datetime import datetime
from tqdm import tqdm

def load_model_from_path(model_path, model):
    model.load_state_dict(torch.load(model_path, weights_only=True))


def run_epochs(learning_rate, model, epochs=100):
    # Optimizer
    optimizer = torch.optim.SGD(model.parameters(), lr=learning_rate, momentum=0.1)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    writer = SummaryWriter("runs/fashion_trainer_{}".format(timestamp))
    epoch_number = 0

    EPOCHS = epochs
    model_path = None

    best_vloss = 1_000_000.0

    from tqdm import tqdm

    for epoch in tqdm(list(range(EPOCHS))):
        # print("EPOCH {}:".format(epoch_number + 1))
        # print(f"learning rate: {optimizer.param_groups[0]['lr']}")

        # Make sure gradient tracking is on, and do a pass over the data
        model.train(True)
        avg_loss = train_one_epoch(
            dataloader=dataloader,
            model=model,
            loss_fn=loss_fn,
            optimizer=optimizer)

        running_vloss = 0.0
        # Set the model to evaluation mode, disabling dropout and using population
        # statistics for batch normalization.
        model.eval()

        # Disable gradient computation and reduce memory consumption.
        with torch.no_grad():
            for i, vdata in enumerate(dataloader):
                vinputs, vlabels = vdata
                vinputs, vlabels = vinputs.to(device), vlabels.to(device)
                voutputs = model(vinputs)
                vloss = loss_fn(voutputs, vlabels)

                running_vloss += vloss

        avg_vloss = running_vloss / (i + 1)
        print(
            "EP {}, LR {}, LOSS train {} valid {}".format(
                epoch_number + 1,
                optimizer.param_groups[0]["lr"],
                avg_loss,
                avg_vloss,
            )
        )

        # Log the running loss averaged per batch
        # for both training and validation
        writer.add_scalars(
            "Training vs. Validation Loss",
            {"Training": avg_loss, "Validation": avg_vloss},
            epoch_number + 1,
        )
        writer.flush()

        # Track best performance, and save the model's state
        if avg_vloss < best_vloss:
            best_vloss = avg_vloss
            model_folder = Path("model_logs")
            model_folder.mkdir(parents=True, exist_ok=True)
            model_path = "model_logs/model_{}_{}".format(
                timestamp, epoch_number
            )
            torch.save(model.state_dict(), model_path)

        epoch_number += 1

    return model_path

# %%
accuracy = 0
step = 0
best_model_param_path = None
# %%
import mlflow.pytorch
for i in range(1):
    if accuracy == 1.0:
        break

    lrs = [0.1] * 1
    epochs = 100
    for lr in lrs:
        mlflow.log_metrics(
            {
                "learning_rate": lr,
                "epochs": epochs
            },
            step=step
        )
        
        best_model_param_path = run_epochs(lr, model, epochs=epochs)
        step += epochs
        if best_model_param_path is not None:
            load_model_from_path(best_model_param_path, model)

    print("Down")

    from sklearn.metrics import (
        accuracy_score,
        precision_score,
        recall_score,
        f1_score,
    )

    if best_model_param_path is not None:
        load_model_from_path(best_model_param_path, model)

    def model_inference(model, x):
        with torch.no_grad():
            return model(x).item()

    x_input, y_truth = [], []
    for x, y in dataset:
        x_input.append(x.to(device))
        y_truth.append(y)

    y_pred_row = [model_inference(model, x) for x in x_input]

    y_pred = [1 if y_row > 0.5 else 0 for y_row in y_pred_row]

    accuracy = accuracy_score(y_truth, y_pred)
    precision = precision_score(y_truth, y_pred)
    recall = recall_score(y_truth, y_pred)
    f1 = f1_score(y_truth, y_pred)
    print(f"{accuracy=}")
    print(f"{precision=}")
    print(f"{recall=}")
    print(f"{f1=}")
    
    # TODO - Use mlflow.pytorch.autologging
    
    mlflow.pytorch.log_state_dict(model.state_dict(), artifact_path=f"checkpoint_{step}") # type: ignore
    
    mlflow.log_metrics(
        {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }, # type: ignore
        step=step
    )

# %%
load_model_from_path(best_model_param_path, model)
mlflow.pytorch.log_state_dict(model.state_dict(), artifact_path=f"global_bast")
# %%
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
)


def model_inference(model, x):
    with torch.no_grad():
        return model(x).item()


def model_calculate(model, x):
    with torch.no_grad():
        return model.calculate_apk_scores(x)


x_input, y_truth = [], []
for x, y in dataset:
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

mlflow.log_metrics(
    {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    },
    step=step
)

# %%
# Record lrs and epochs (Optional, nice to have)
# mlflow.log_text("(Ep 50) 20, 15, 10, 5 * 3, 8, 10 (Ep 100), 10, 20, 50, 100, 500, 500, 500, 100, 10, 10, 50", "lrs_and_epochs_records.txt", run.info.run_id)s
# %%
# Output adjusted scores and prediction for each apk

apk_prediction = pl.DataFrame(
    {
        "sha256": dataset.apk_info["sha256"],
        "y_truth": y_truth,
        "y_score": y_score,
        "y_pred": y_pred,
    }
)

# Prepare analysis results
rule_paths = [rule_lib.get(rule) for rule in rules]

weight_dicts = (
    analysis_result_lib.analyze_rules(
        sha256,
        apk_lib.download(sha256, dry_run=True),
        rule_paths,
        dry_run=True,
    )
    | {"sha256": sha256}
    for sha256 in dataset.apk_info["sha256"]
)
weight_dfs = (pl.DataFrame(weight) for weight in weight_dicts)
weights = pl.concat(weight_dfs, how="vertical")
weights = weights.transpose(
    include_header=True, column_names="sha256", header_name="rule"
)

# Prepare adjusts rule scores
# rule_scores = pl.DataFrame(
#     {"rule_score": model.get_rule_scores().cpu().detach().tolist(), "rule": rules}
# ).with_row_index()

rule_scores = dataset.rules.join(
    pl.DataFrame(
        {"rule_score": model.get_rule_scores().cpu().detach().tolist()}
    ).with_row_index(),
    on="index",
    how="left"
)

# Combine rule_scores and weights
weights_and_rule_scores = rule_scores.join(
    weights, on="rule", how="left", maintain_order="left"
)

new_column_names = ["sha256", "y_truth", "y_score", "y_pred"] + weights[
    "rule"
].to_list()

combined = (
    weights_and_rule_scores.transpose(
        include_header=True,
        header_name="sha256",
        column_names="rule",
    )
    .join(apk_prediction, on="sha256", how="full", maintain_order="left")
    .select(new_column_names)
)

combined.write_csv("apk_prediction.csv", include_header=True)

mlflow.log_artifact(
    "apk_prediction.csv",
    "apk_prediction.csv",
    run.info.run_id
)

# %%
# Close Run
mlflow.end_run()
