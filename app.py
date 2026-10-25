import streamlit as st

from src.capture import capture_packets
from src.stats import get_basic_metrics, get_protocol_statistics, get_top_flows
from src.ml.predict import predict_anomaly
from src.llm import generate_network_report


st.set_page_config(
    page_title="Threat Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Threat Analyzer")
st.caption("Real-Time Network Traffic Monitoring and Anomaly Detection")


# LIVE CAPTURE

st.subheader("📡 Live Network Capture")

col_btn1, col_btn2 = st.columns([1, 1])

with col_btn1:
    start_live = st.button("Start Live Capture", key="start_live")

with col_btn2:
    generate_live_report = st.button("Generate Report", key="generate_live_report")


if start_live:
    with st.spinner("Capturing packets..."):
        capture_result = capture_packets(count=50)

    packets = capture_result["packets"]

    metrics = get_basic_metrics(packets, capture_result)
    protocol_stats = get_protocol_statistics(packets)
    top_flows = get_top_flows(packets)

    prediction = predict_anomaly(
        packets=packets,
        capture_info=capture_result
    )

    st.session_state["live_packets"] = packets
    st.session_state["live_metrics"] = metrics
    st.session_state["live_protocol_stats"] = protocol_stats
    st.session_state["live_top_flows"] = top_flows
    st.session_state["live_prediction"] = prediction
    st.session_state["live_report"] = None

    st.success("Live capture completed")


live_metrics = st.session_state.get("live_metrics", {
    "packets_analyzed": 0,
    "avg_payload_size": 0,
    "avg_inter_arrival_ms": 0,
    "protocols_detected": 0,
    "dropped_packets": 0,
    "threat_score": 0,
})

live_prediction = st.session_state.get("live_prediction", {
    "status": "Pending",
    "threat_score": 0,
    "reconstruction_error": 0,
    "threshold": 0,
})

live_protocol_stats = st.session_state.get("live_protocol_stats", None)
live_top_flows = st.session_state.get("live_top_flows", None)


st.divider()


# METRICS

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Packets Analyzed", live_metrics["packets_analyzed"])
    st.metric("Avg Payload Size", f"{live_metrics['avg_payload_size']} B")

with col2:
    st.metric("Avg Inter-Arrival Time", f"{live_metrics['avg_inter_arrival_ms']} ms")
    st.metric("Dropped Packets", live_metrics["dropped_packets"])

with col3:
    st.metric("Protocols Detected", live_metrics["protocols_detected"])
    st.metric("Threat Score", f"{live_prediction['threat_score']}%")

st.metric("Model Status", live_prediction["status"])


with st.expander("Model Details"):
    st.write("Reconstruction Error:", live_prediction.get("reconstruction_error", 0))
    st.write("Threshold:", live_prediction.get("threshold", 0))


# PROTOCOL STATS

st.subheader("Protocol Statistics")

if live_protocol_stats is not None:
    st.dataframe(live_protocol_stats, use_container_width=True)
else:
    st.info("No protocol data available yet.")


# TOP FLOWS
st.subheader("Top Network Flows")

if live_top_flows is not None:
    st.dataframe(live_top_flows, use_container_width=True)
else:
    st.info("No flow data available yet.")

# LLM REPORT

st.subheader("LLM Natural Language Report")

if generate_live_report:
    if live_prediction["status"] == "Pending":
        st.warning("Capture traffic first before generating a report.")
    else:
        with st.spinner("Generating natural language report..."):
            report = generate_network_report(
                metrics=live_metrics,
                prediction=live_prediction,
                protocol_stats=live_protocol_stats,
                top_flows=live_top_flows
            )

        st.session_state["live_report"] = report


live_report = st.session_state.get("live_report", None)

if live_report:
    st.info(live_report)
else:
    st.info("Generate a report after capturing traffic.")