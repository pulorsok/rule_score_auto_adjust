import functools
from typing import Iterable
import torch
import data_preprocess.analysis_result as analysis_lib
import data_preprocess.apk as apk_lib
import data_preprocess.rule as rule_lib
from tqdm import tqdm
from pathlib import Path
import polars as pl
import os
from diskcache import Cache

STAGE_WEIGHT_MAPPING = {
    0.0: 0,
    1.0: (2**0) / (2**4),
    2.0: (2**1) / (2**4),
    3.0: (2**2) / (2**4),
    4.0: (2**3) / (2**4),
    5.0: (2**4) / (2**4),
}


class ApkDataset(torch.utils.data.Dataset, Iterable):
    def __init__(
        self,
        sha256s: Iterable[str],
        is_malicious: Iterable[int],
        rules: Iterable[str],
    ):
        self.apk_info = pl.DataFrame(
            (sha256s, is_malicious), schema=apk_lib.APK_SCHEMA
        )

        self.rules = (
            pl.DataFrame(rules, schema=rule_lib.RULE_LIST_SCHEMA)
            .unique(["rule"])
            .with_row_index()
        )

    @functools.cached_property
    def cache(self) -> Cache:
        cache = Cache(self.base_folder)
        cache.clear()
        return cache

    def __iter__(self):
        yield from (self.__getitem__(i) for i in range(self.__len__()))

    def __get_item_no_cache(self, index) -> tuple[torch.Tensor, torch.Tensor]:
        sha256 = self.apk_info.item(row=index, column="sha256")

        apk_path = apk_lib.download(sha256)
        assert (
            apk_path is not None
        ), f"Unable to download apk {sha256}, please consider removing it from the dataset."

        rule_paths = [rule_lib.get(r) for r in self.rules["rule"].to_list()]

        analysis_result = analysis_lib.analyze_rules(
            sha256, apk_path, rule_paths
        )
        rule_weights = {
            rule: STAGE_WEIGHT_MAPPING.get(float(stage), 0.0)
            for rule, stage in analysis_result.items()
        }

        indexed_rule_weights = self.rules.with_columns(
            pl.col("rule")
            .map_elements(
                lambda r: rule_weights.get(r, 0.0), return_dtype=pl.Float32
            )
            .alias("weights")
        )

        rule_weight_tensor = (
            indexed_rule_weights.select("weights")
            .transpose()
            .to_torch(dtype=pl.Float32)
        ).view(-1)

        expected_score = torch.tensor(
            self.apk_info.item(index, "is_malicious"), dtype=torch.float32
        )

        return rule_weight_tensor, expected_score

    def __getitem__(self, index) -> tuple[torch.Tensor, torch.Tensor]:
        if index not in self.cache:
            self.cache[index] = self.__get_item_no_cache(index)
        return self.cache[index]

    def __hash__(self) -> int:
        hash_value = sum(hash(val) for val in self.apk_info["sha256"])
        hash_value += sum(hash(val) for val in self.rules["rule"])
        return hash_value

    def __len__(self) -> int:
        return len(self.apk_info)

    @functools.cached_property
    def base_folder(self) -> Path:
        return self.__createIfNotExists(
            Path(os.getenv("DATASET_CACHE_FOLDER") or str(Path(__file__).parent.parent / "data" / "dataset"))
            / f"{type(self).__name__}_{hash(self)}"
        )

    def preload(self):
        for data in tqdm(
            self, desc="Preloading Dataset", total=self.__len__()
        ):
            pass

    @staticmethod
    def __createIfNotExists(folder: Path) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        return folder
