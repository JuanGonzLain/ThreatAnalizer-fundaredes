import pandas as pd

#función para construir un dataframe a partir de la lista de paquetes capturados,
#esto facilita el análisis y la visualización de los datos en Streamlit
def build_dataframe(packets): 
    if not packets:
        return pd.DataFrame()

    return pd.DataFrame(packets)

#función para calcular métricas básicas a partir de la lista de paquetes capturados y 
#la información de captura segun el protocolo, tamaño, tiempo entre paquetes, etc
def get_basic_metrics(packets, capture_info=None): 
    df = build_dataframe(packets) #variable que almacena el dataframe construido a partir de la lista de paquetes capturados

    if df.empty: #condición para verificar si el dataframe está vacío, si es así, devuelve un diccionario con métricas predeterminadas
        return {
            "packets_analyzed": 0,
            "avg_payload_size": 0,
            "avg_inter_arrival_ms": 0,
            "protocols_detected": 0,
            "dropped_packets": 0,
            "threat_score": 0,
        }

    if "timestamp" in df.columns and len(df) > 1: #condición para verificar si la columna "timestamp" existe en el dataframe y si hay más de un paquete, si es así, calcula el tiempo promedio entre la llegada de los paquetes en milisegundos
        avg_inter_arrival_ms = (
            df["timestamp"]
            .sort_values()
            .diff()
            .mean()
            * 1000
        )
    else: #si no se cumplen las condiciones anteriores, se establece el tiempo promedio entre la llegada de los paquetes en 0 milisegundos
        avg_inter_arrival_ms = 0

    dropped_packets = 0 #inicializa la variable para almacenar el número de paquetes descartados, se inicializa en 0 y luego se actualiza si la información de captura proporciona ese dato

    if capture_info: #condición para verificar si se proporciona información de captura, si es así, se actualiza el número de paquetes descartados con el valor proporcionado en la información de captura
        dropped_packets = capture_info.get("discarded_packets", 0)

    return { #devuelve un diccionario con las métricas calculadas, incluyendo el número total de paquetes analizados, el tamaño promedio de la carga útil, el tiempo promedio entre la llegada de los paquetes, el número de protocolos detectados, el número de paquetes descartados y una puntuación de amenaza (que se establece en 0 por ahora)
        "packets_analyzed": len(df), #número total de paquetes analizados, se obtiene contando el número de filas en el dataframe
        "avg_payload_size": round(df["payload_size"].mean(), 2), #tamaño promedio de la carga útil, se calcula tomando el promedio de la columna "payload_size" en el dataframe y redondeando a 2 decimales
        "avg_inter_arrival_ms": round(avg_inter_arrival_ms, 2), #tiempo promedio entre la llegada de los paquetes en milisegundos, se redondea a 2 decimales
        "protocols_detected": df["protocol"].nunique(), #número de protocolos detectados, se calcula contando el número de valores únicos en la columna "protocol" del dataframe
        "dropped_packets": dropped_packets, #número de paquetes descartados, se obtiene del diccionario de información de captura
        "threat_score": 0, #puntuación de amenaza, se establece en 0 por ahora, pero podría ser calculada en función de las métricas anteriores o de otras características de los paquetes
    }


def get_protocol_statistics(packets):
    df = build_dataframe(packets)

    if df.empty:
        return pd.DataFrame(
            columns=[
                "Protocol",
                "Packets",
                "Traffic %",
                "Avg Payload",
                "Total Bytes",
            ]
        )

    protocol_stats = (
        df.groupby("protocol")
        .agg(
            Packets=("protocol", "count"),
            Avg_Payload=("payload_size", "mean"),
            Total_Bytes=("size_bytes", "sum"),
        )
        .reset_index()
    )

    protocol_stats["Traffic %"] = (
        protocol_stats["Packets"] / protocol_stats["Packets"].sum() * 100
    ).round(2)

    protocol_stats["Avg Payload"] = protocol_stats["Avg_Payload"].round(2)

    protocol_stats = protocol_stats.rename(
        columns={
            "protocol": "Protocol",
            "Total_Bytes": "Total Bytes",
        }
    )

    return protocol_stats[
        [
            "Protocol",
            "Packets",
            "Traffic %",
            "Avg Payload",
            "Total Bytes",
        ]
    ]


def get_top_flows(packets, limit=10):
    df = build_dataframe(packets)

    columns = [
        "Source IP",
        "Destination IP",
        "Source Port",
        "Destination Port",
        "Protocol",
        "Packets",
        "Bytes",
    ]

    if df.empty:
        return pd.DataFrame(columns=columns)

    flow_columns = [
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
    ]

    for column in flow_columns:
        if column not in df.columns:
            df[column] = None

    flows = (
        df.groupby(flow_columns, dropna=False)
        .agg(
            Packets=("protocol", "count"),
            Bytes=("size_bytes", "sum"),
        )
        .reset_index()
        .sort_values(by=["Packets", "Bytes"], ascending=False)
        .head(limit)
    )

    flows = flows.rename(
        columns={
            "source_ip": "Source IP",
            "destination_ip": "Destination IP",
            "source_port": "Source Port",
            "destination_port": "Destination Port",
            "protocol": "Protocol",
        }
    )

    return flows[columns]


def get_layer_statistics(packets):
    df = build_dataframe(packets)

    if df.empty:
        return pd.DataFrame(
            columns=[
                "Layer",
                "Packets",
                "Traffic %",
            ]
        )

    layer_stats = (
        df.groupby("layer")
        .agg(Packets=("layer", "count"))
        .reset_index()
    )

    layer_stats["Traffic %"] = (
        layer_stats["Packets"] / layer_stats["Packets"].sum() * 100
    ).round(2)

    layer_stats = layer_stats.rename(columns={"layer": "Layer"})

    return layer_stats