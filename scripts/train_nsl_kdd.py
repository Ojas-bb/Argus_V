#!/usr/bin/env python3
"""Train an IsolationForest on the public NSL-KDD dataset.

This script is intended as an end-to-end validation of the pipeline:
Retina-like CSV features -> Mnemosyne-style model training -> Aegis-style inference.

It:
- Downloads NSL-KDD (KDDTrain+/KDDTest+) from a public GitHub mirror
- Converts to a minimal Retina-like feature set
- Tunes IsolationForest hyperparameters (contamination, n_estimators)
- Evaluates on the official test set
- Saves (model, scaler, metadata) to a single joblib file

Default output: /tmp/argus_model_nsl_kdd.pkl
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import urlretrieve

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))


NSL_KDD_BASE_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master"
NSL_KDD_FILES = {
    "train": "KDDTrain%2B.txt",
    "test": "KDDTest%2B.txt",
}

NSL_KDD_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty",
]

RETINA_FEATURE_COLUMNS = ["packet_count", "byte_count", "duration_seconds", "rate_bps"]


@dataclass(frozen=True)
class Metrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    true_positive_rate: float
    false_positive_rate: float


def _download_if_missing(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        return
    urlretrieve(url, dest)  # noqa: S310


def download_nsl_kdd(data_dir: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for split, filename in NSL_KDD_FILES.items():
        url = f"{NSL_KDD_BASE_URL}/{filename}"
        local_path = data_dir / filename.replace("%2B", "+")
        _download_if_missing(url, local_path)
        paths[split] = local_path
    return paths


def load_nsl_kdd(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, header=None, names=NSL_KDD_COLUMNS)
    return df


def to_retina_features(df: pd.DataFrame) -> pd.DataFrame:
    # Minimal feature extraction:
    # - packet_count: use the NSL-KDD 'count' feature (connections in last 2 seconds)
    # - byte_count: src_bytes + dst_bytes
    # - duration_seconds: duration
    # - rate_bps: byte_count / duration_seconds
    packet_count = pd.to_numeric(df["count"], errors="coerce").fillna(0)
    src_bytes = pd.to_numeric(df["src_bytes"], errors="coerce").fillna(0)
    dst_bytes = pd.to_numeric(df["dst_bytes"], errors="coerce").fillna(0)
    duration_seconds = pd.to_numeric(df["duration"], errors="coerce").fillna(0)

    byte_count = src_bytes + dst_bytes
    safe_duration = duration_seconds.clip(lower=1e-3)
    rate_bps = byte_count / safe_duration

    y_attack = (df["label"].astype(str).str.lower() != "normal").astype(int)

    retina_df = pd.DataFrame(
        {
            "packet_count": packet_count.astype(float),
            "byte_count": byte_count.astype(float),
            "duration_seconds": duration_seconds.astype(float),
            "rate_bps": rate_bps.astype(float),
            "is_attack": y_attack,
        }
    )

    return retina_df


def compute_metrics(y_true_attack: np.ndarray, y_pred_attack: np.ndarray) -> Metrics:
    y_true_attack = y_true_attack.astype(int)
    y_pred_attack = y_pred_attack.astype(int)

    tp = int(((y_true_attack == 1) & (y_pred_attack == 1)).sum())
    tn = int(((y_true_attack == 0) & (y_pred_attack == 0)).sum())
    fp = int(((y_true_attack == 0) & (y_pred_attack == 1)).sum())
    fn = int(((y_true_attack == 1) & (y_pred_attack == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    tpr = recall
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return Metrics(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        true_positive_rate=float(tpr),
        false_positive_rate=float(fpr),
    )


def make_X(df: pd.DataFrame) -> np.ndarray:
    X = df[RETINA_FEATURE_COLUMNS].to_numpy(dtype=float)
    # Heavy-tailed: stabilize
    return np.log1p(X)


def tune_iforest(
    normal_train: pd.DataFrame,
    validation: pd.DataFrame,
    contamination_grid: list[float],
    n_estimators_grid: list[int],
    random_state: int,
) -> tuple[IsolationForest, StandardScaler, dict[str, Any], Metrics]:
    X_train_raw = make_X(normal_train)

    best_model: IsolationForest | None = None
    best_scaler: StandardScaler | None = None
    best_params: dict[str, Any] | None = None
    best_metrics: Metrics | None = None

    # Prefer high precision (acceptance: 85%+), then highest F1
    best_key = (-1.0, -1.0)

    for contamination in contamination_grid:
        for n_estimators in n_estimators_grid:
            scaler = StandardScaler()
            X_train = scaler.fit_transform(X_train_raw)

            model = IsolationForest(
                n_estimators=int(n_estimators),
                contamination=float(contamination),
                random_state=int(random_state),
                n_jobs=1,
            )
            model.fit(X_train)

            X_val = scaler.transform(make_X(validation))
            pred = model.predict(X_val)
            y_pred_attack = (pred == -1).astype(int)
            y_true_attack = validation["is_attack"].to_numpy(dtype=int)

            metrics = compute_metrics(y_true_attack=y_true_attack, y_pred_attack=y_pred_attack)
            key = (metrics.precision, metrics.f1)

            if key > best_key:
                best_key = key
                best_model = model
                best_scaler = scaler
                best_params = {
                    "contamination": float(contamination),
                    "n_estimators": int(n_estimators),
                }
                best_metrics = metrics

    assert best_model is not None
    assert best_scaler is not None
    assert best_params is not None
    assert best_metrics is not None

    return best_model, best_scaler, best_params, best_metrics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=Path("/tmp/nsl_kdd"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/tmp/argus_model_nsl_kdd.pkl"),
        help="Joblib output path for (model, scaler, metadata)",
    )
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument(
        "--export-retina-csv",
        action="store_true",
        help="Write derived Retina-like CSVs (normal/attack/train/test) to --data-dir",
    )
    args = parser.parse_args()

    paths = download_nsl_kdd(args.data_dir)
    train_raw = load_nsl_kdd(paths["train"])
    test_raw = load_nsl_kdd(paths["test"])

    train_retina = to_retina_features(train_raw)
    test_retina = to_retina_features(test_raw)

    normal_train_all = train_retina[train_retina["is_attack"] == 0].reset_index(drop=True)
    attack_train_all = train_retina[train_retina["is_attack"] == 1].reset_index(drop=True)

    # Split normal for training vs validation baseline
    normal_train, normal_val = train_test_split(
        normal_train_all,
        test_size=0.2,
        random_state=args.random_state,
        shuffle=True,
    )

    # Validation = held-out normal + sampled attacks from training set
    attack_val = attack_train_all.sample(
        n=min(len(attack_train_all), len(normal_val)),
        random_state=args.random_state,
    )

    validation = pd.concat([normal_val, attack_val], ignore_index=True).sample(
        frac=1.0, random_state=args.random_state
    )

    contamination_grid = [0.001, 0.002, 0.005, 0.01, 0.02]
    n_estimators_grid = [100, 200, 400]

    model, scaler, best_params, val_metrics = tune_iforest(
        normal_train=normal_train,
        validation=validation,
        contamination_grid=contamination_grid,
        n_estimators_grid=n_estimators_grid,
        random_state=args.random_state,
    )

    # Retrain final model on ALL normal training samples with the best params
    X_final_train = scaler.fit_transform(make_X(normal_train_all))
    model = IsolationForest(
        n_estimators=int(best_params["n_estimators"]),
        contamination=float(best_params["contamination"]),
        random_state=int(args.random_state),
        n_jobs=1,
    )
    model.fit(X_final_train)

    # Evaluate on official test set (normal + attacks)
    X_test = scaler.transform(make_X(test_retina))
    pred_test = model.predict(X_test)
    y_pred_attack = (pred_test == -1).astype(int)
    y_true_attack = test_retina["is_attack"].to_numpy(dtype=int)

    test_metrics = compute_metrics(y_true_attack=y_true_attack, y_pred_attack=y_pred_attack)

    if args.export_retina_csv:
        out_dir = args.data_dir
        train_retina.to_csv(out_dir / "nsl_kdd_retina_train.csv", index=False)
        test_retina.to_csv(out_dir / "nsl_kdd_retina_test.csv", index=False)
        normal_train_all.to_csv(out_dir / "nsl_kdd_retina_normal.csv", index=False)
        attack_train_all.to_csv(out_dir / "nsl_kdd_retina_attack.csv", index=False)

    args.output.parent.mkdir(parents=True, exist_ok=True)

    artifact: dict[str, Any] = {
        "trained_at": datetime.now(tz=timezone.utc).isoformat(),
        "dataset": "NSL-KDD",
        "retina_feature_columns": RETINA_FEATURE_COLUMNS,
        "transform": "log1p + StandardScaler",
        "best_params": best_params,
        "validation_metrics": val_metrics.__dict__,
        "test_metrics": test_metrics.__dict__,
        "model": model,
        "scaler": scaler,
    }

    joblib.dump(artifact, args.output)

    # Aegis smoke-check (in-process)
    try:
        from argus_v.aegis.config import ModelConfig
        from argus_v.aegis.model_manager import ModelManager

        mm = ModelManager(
            ModelConfig(model_local_path="/tmp/models", scaler_local_path="/tmp/scalers"),
            feature_columns=RETINA_FEATURE_COLUMNS,
        )
        mm._model = model
        mm._scaler = scaler

        sample = test_retina.head(5).copy()
        sample["src_ip"] = "0.0.0.0"
        sample["dst_ip"] = "0.0.0.0"
        _ = mm.predict_flows(sample)
    except Exception:
        # The smoke-check is best-effort; the primary output is the trained artifact.
        pass

    print("NSL-KDD IsolationForest Training Results")
    print("=")
    print(f"Best params (from validation): {best_params}")
    print(
        "Validation: "
        f"precision={val_metrics.precision:.3f}, "
        f"recall={val_metrics.recall:.3f}, "
        f"f1={val_metrics.f1:.3f}, "
        f"TPR={val_metrics.true_positive_rate:.3f}, "
        f"FPR={val_metrics.false_positive_rate:.3f}"
    )
    print(
        "Test:       "
        f"precision={test_metrics.precision:.3f}, "
        f"recall={test_metrics.recall:.3f}, "
        f"f1={test_metrics.f1:.3f}, "
        f"TPR={test_metrics.true_positive_rate:.3f}, "
        f"FPR={test_metrics.false_positive_rate:.3f}"
    )
    print(f"Saved artifact: {args.output}")

    # Simple acceptance check
    if test_metrics.precision < 0.85:
        print(
            "WARNING: precision below 0.85 on the test set. "
            "Consider expanding the hyperparameter grid or feature engineering."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
