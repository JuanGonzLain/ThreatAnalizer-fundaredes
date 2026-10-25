import numpy as np
from src.stats import build_dataframe, get_basic_metrics

#función para construir un vector de características a partir de la lista de paquetes capturados y la información de captura, este vector se puede utilizar 
#como entrada para el modelo de machine learning para la detección de amenazas, incluye métricas básicas y conteos de protocolos específicos
def build_feature_vector(packets, capture_info=None): 
    df = build_dataframe(packets)
    metrics = get_basic_metrics(packets, capture_info)

    if df.empty:
        return np.zeros(10, dtype=np.float32)

    protocol_counts = df["protocol"].value_counts()

    tcp_count = protocol_counts.get("TCP", 0)
    udp_count = protocol_counts.get("UDP", 0)
    icmp_count = protocol_counts.get("ICMP", 0)
    arp_count = protocol_counts.get("ARP", 0)

    l2_only_count = 0
    if "is_l2_only" in df.columns:
        l2_only_count = int(df["is_l2_only"].sum())

    features = np.array([
        metrics["packets_analyzed"],
        metrics["avg_payload_size"],
        metrics["avg_inter_arrival_ms"],
        metrics["protocols_detected"],
        metrics["dropped_packets"],
        tcp_count,
        udp_count,
        icmp_count,
        arp_count,
        l2_only_count,
    ], dtype=np.float32)

    return features