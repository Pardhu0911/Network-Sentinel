import pandas as pd
import streamlit as st

from capture import collect_metadata
from detector import DATA, classify_events, train_model

st.set_page_config(page_title="Network Sentinel", layout="wide")
st.title("Network Sentinel")
mode = st.radio("Data source", ["Saved course run", "Local passive capture"], horizontal=True)
if mode == "Saved course run":
    totals = pd.read_csv(DATA / "saved_counts.csv")
    sample = pd.read_csv(DATA / "replay_sample.csv")
    st.metric("Packets in the saved run", f"{totals['Records'].sum():,}")
    st.caption("These labels were recorded by the classroom detector. They have no independent ground truth.")
    left, right = st.columns(2)
    left.subheader("Packet labels")
    left.bar_chart(totals.groupby("ML_Prediction")["Records"].sum())
    right.subheader("Protocols")
    right.bar_chart(totals.groupby("Protocol")["Records"].sum())
    st.subheader("Sampled packet metadata")
    label = st.selectbox("Recorded label", ["All", *sorted(sample["Recorded_Label"].unique())])
    selected = sample if label == "All" else sample[sample["Recorded_Label"] == label]
    st.dataframe(selected, hide_index=True)
    st.caption("The sample has 60 rows per recorded label. The charts above use the totals from the full run.")
else:
    st.caption("Capture up to five seconds on a local interface you are authorized to monitor. Only header metadata is displayed.")
    if st.button("Capture metadata"):
        try:
            events = collect_metadata()
        except (ImportError, OSError, RuntimeError) as exc:
            st.error(f"Local capture unavailable: {exc}")
        else:
            if events.empty:
                st.info("No supported IPv4 packets were observed.")
            else:
                model, encoder = st.cache_resource(train_model)()
                events["Prototype_Label"] = classify_events(events, model, encoder)
                st.session_state["local_events"] = events
    if "local_events" in st.session_state:
        st.dataframe(st.session_state["local_events"], hide_index=True)
