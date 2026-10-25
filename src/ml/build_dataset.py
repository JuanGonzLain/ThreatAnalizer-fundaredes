import os
import time #importa la biblioteca time para agregar retrasos entre las capturas de tráfico, lo que puede ser útil para simular diferentes condiciones de red y evitar capturas demasiado rápidas que podrían no reflejar el comportamiento real de la red
import pandas as pd #importa la biblioteca pandas para trabajar con dataframes, lo que facilita el análisis y la visualización de los datos en Streamlit

from src.capture import capture_packets #importa la función capture_packets del módulo src.capture, que se encarga de capturar paquetes de red y devolver información sobre ellos
from src.ml.features import build_feature_vector #importa la función build_feature_vector del módulo src.ml.features, que se encarga de construir un vector de características a partir de la lista de paquetes capturados y la información de captura, este vector se puede utilizar como entrada para el modelo de machine learning para la detección de amenazas, incluye métricas básicas y conteos de protocolos específicos


OUTPUT_PATH = "data/processed/training_features.csv"


FEATURE_COLUMNS = [
    "packets_analyzed",
    "avg_payload_size",
    "avg_inter_arrival_ms",
    "protocols_detected",
    "dropped_packets",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "arp_count",
    "l2_only_count",
]


def ensure_output_folder():
    os.makedirs("data/processed", exist_ok=True)


def save_feature_row(feature_vector):
    ensure_output_folder()

    row = pd.DataFrame(
        [feature_vector],
        columns=FEATURE_COLUMNS
    )

    file_exists = os.path.exists(OUTPUT_PATH)

    row.to_csv(
        OUTPUT_PATH,
        mode="a",
        header=not file_exists,
        index=False
    )


def build_dataset(
    windows=20,
    packets_per_window=50,
    delay_seconds=2
):
    """
    Captures multiple traffic windows and saves each one as a row
    in data/processed/training_features.csv.

    Each row represents one network behavior sample.
    """

    print("Starting dataset generation...")
    print(f"Windows: {windows}")
    print(f"Packets per window: {packets_per_window}")
    print(f"Output: {OUTPUT_PATH}")
    print("-" * 50)

    for i in range(windows):
        print(f"Capturing window {i + 1}/{windows}...")

        capture_result = capture_packets(
            count=packets_per_window
        )

        packets = capture_result["packets"]

        feature_vector = build_feature_vector(
            packets,
            capture_result
        )

        save_feature_row(feature_vector)

        print(f"Saved window {i + 1}")
        print(feature_vector)
        print("-" * 50)

        time.sleep(delay_seconds)

    print("Dataset generation completed.")


if __name__ == "__main__":
    build_dataset(
        windows=30,
        packets_per_window=50,
        delay_seconds=2
    )