import os
import json
import torch
import torch.nn as nn
import pandas as pd

from src.ml.model import Autoencoder
from src.ml.features import build_feature_vector


MODEL_PATH = "models/autoencoder.pt"
SCALER_PATH = "models/scaler.json"
THRESHOLD_PATH = "models/threshold.json"


def load_json(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    with open(path, "r") as file:
        return json.load(file)


def load_model(input_size=10):
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. Run train.py first."
        )

    model = Autoencoder(input_size=input_size)

    model.load_state_dict(
        torch.load(MODEL_PATH, map_location=torch.device("cpu"))
    )

    model.eval()

    return model


def normalize_feature_vector(feature_vector):
    scaler = load_json(SCALER_PATH)

    columns = scaler["columns"]
    mean = scaler["mean"]
    std = scaler["std"]

    df = pd.DataFrame(
        [feature_vector],
        columns=columns
    )

    for column in columns:
        df[column] = (df[column] - mean[column]) / std[column]

    return df.values[0]


def load_threshold():
    threshold_data = load_json(THRESHOLD_PATH)
    return threshold_data["threshold"]


def calculate_reconstruction_error(model, normalized_feature_vector):
    x = torch.tensor(
        normalized_feature_vector,
        dtype=torch.float32
    ).unsqueeze(0)

    with torch.no_grad():
        reconstructed = model(x)
        error = nn.functional.mse_loss(reconstructed, x)

    return error.item()


def predict_anomaly(packets, capture_info=None):
    feature_vector = build_feature_vector(
        packets,
        capture_info
    )

    normalized_feature_vector = normalize_feature_vector(feature_vector)

    model = load_model(
        input_size=len(normalized_feature_vector)
    )

    threshold = load_threshold()

    reconstruction_error = calculate_reconstruction_error(
        model,
        normalized_feature_vector
    )

    is_anomaly = reconstruction_error > threshold

    threat_score = min(
        round((reconstruction_error / threshold) * 100, 2),
        100
    )

    return {
        "is_anomaly": is_anomaly,
        "reconstruction_error": reconstruction_error,
        "threshold": threshold,
        "threat_score": threat_score,
        "feature_vector": feature_vector.tolist(),
        "status": "Anomaly" if is_anomaly else "Normal"
    }