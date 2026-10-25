import os
import json
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim

from src.ml.model import Autoencoder


DATASET_PATH = "data/processed/training_features.csv"
MODEL_PATH = "models/autoencoder.pt"
SCALER_PATH = "models/scaler.json"
THRESHOLD_PATH = "models/threshold.json"


def load_dataset():
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}. Run build_dataset.py first."
        )

    df = pd.read_csv(DATASET_PATH)

    if df.empty:
        raise ValueError("Dataset is empty.")

    return df


def normalize_data(df):
    mean = df.mean()
    std = df.std()

    # Avoid division by zero
    std = std.replace(0, 1)

    normalized_df = (df - mean) / std

    scaler = {
        "mean": mean.to_dict(),
        "std": std.to_dict(),
        "columns": list(df.columns)
    }

    return normalized_df, scaler


def save_scaler(scaler):
    with open(SCALER_PATH, "w") as file:
        json.dump(scaler, file, indent=4)


def calculate_training_errors(model, X):
    model.eval()

    with torch.no_grad():
        reconstructed = model(X)
        errors = torch.mean((reconstructed - X) ** 2, dim=1)

    return errors


def save_threshold(errors, percentile=95):
    threshold = torch.quantile(
        errors,
        percentile / 100
    ).item()

    threshold_data = {
        "threshold": threshold,
        "percentile": percentile
    }

    with open(THRESHOLD_PATH, "w") as file:
        json.dump(threshold_data, file, indent=4)

    return threshold


def train_model(epochs=300, learning_rate=0.001):
    os.makedirs("models", exist_ok=True)

    df = load_dataset()

    normalized_df, scaler = normalize_data(df)
    save_scaler(scaler)

    X = torch.tensor(
        normalized_df.values,
        dtype=torch.float32
    )

    input_size = X.shape[1]

    model = Autoencoder(input_size=input_size)

    criterion = nn.MSELoss()
    optimizer = optim.Adam(
        model.parameters(),
        lr=learning_rate
    )

    print("Starting training...")
    print(f"Samples: {X.shape[0]}")
    print(f"Features: {X.shape[1]}")
    print("-" * 50)

    for epoch in range(epochs):
        model.train()

        outputs = model(X)
        loss = criterion(outputs, X)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 25 == 0:
            print(
                f"Epoch [{epoch + 1}/{epochs}] "
                f"Loss: {loss.item():.6f}"
            )

    torch.save(
        model.state_dict(),
        MODEL_PATH
    )

    training_errors = calculate_training_errors(model, X)
    threshold = save_threshold(training_errors, percentile=95)

    print("-" * 50)
    print("Training completed.")
    print(f"Model saved at: {MODEL_PATH}")
    print(f"Scaler saved at: {SCALER_PATH}")
    print(f"Threshold saved at: {THRESHOLD_PATH}")
    print(f"Threshold: {threshold}")


if __name__ == "__main__":
    train_model(
        epochs=300,
        learning_rate=0.001
    )