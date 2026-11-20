"""Rebuild the course classifier from address-free traffic counts."""
from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

DATA = Path(__file__).resolve().parent / "data"


def features(timestamps, protocols, encoder):
    times = pd.to_datetime(timestamps, format="%H:%M:%S")
    return pd.DataFrame({
        "Hour": times.dt.hour.to_numpy(),
        "Minute": times.dt.minute.to_numpy(),
        "Second": times.dt.second.to_numpy(),
        "Protocol_Encoded": encoder.transform(protocols),
    })


def train_model():
    counts = pd.read_csv(DATA / "training_counts.csv")
    rows = counts.loc[counts.index.repeat(counts["Records"])].reset_index(drop=True)
    encoder = LabelEncoder().fit(rows["Protocol"])
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(features(rows["Timestamp"], rows["Protocol"], encoder), rows["Attack_Type"])
    return model, encoder


def classify_events(events, model, encoder):
    """Apply the classroom model, followed by its protocol/count/size rules."""
    if events.empty:
        return pd.Series(index=events.index, dtype="object")
    inputs = features(events["Timestamp"], events["Protocol"], encoder)
    probabilities = model.predict_proba(inputs)
    labels = pd.Series(model.classes_[probabilities.argmax(axis=1)], index=events.index)
    labels.loc[probabilities.max(axis=1) < 0.40] = "Normal"
    high_count = events["Packet_Count"] > 20
    small = events["Data_Size"] < 100
    labels.loc[high_count & small & events["Protocol"].eq("TCP")] = "TCP SYN Flood"
    labels.loc[high_count & small & events["Protocol"].eq("UDP")] = "UDP Flood"
    labels.loc[high_count & events["Protocol"].eq("ICMP")] = "ICMP Flood"
    return labels


if __name__ == "__main__":
    forest, _ = train_model()
    print("Model classes:", ", ".join(forest.classes_))
    print(pd.read_csv(DATA / "saved_counts.csv").to_string(index=False))
