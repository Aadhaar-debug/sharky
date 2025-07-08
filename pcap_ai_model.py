import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.models import load_model
import sys
import random

# New features and labels
FEATURES = ['Length', 'SrcPort', 'DstPort']
CATEGORICAL = ['Protocol', 'Flags']
LABELS = ['Anomaly', 'Device', 'VPN', 'Blacklist', 'Server', 'Scan']

# Helper: Multi-label encoding
LABEL_MAP = {
    'Anomaly': lambda row: int(row['Label'] == 'Anomaly'),
    'Device': lambda row: 1,  # All rows have a device
    'VPN': lambda row: int(row['Label'] == 'VPN'),
    'Blacklist': lambda row: int(row['Label'] == 'Blacklist'),
    'Server': lambda row: int(row['Label'] == 'Server'),
    'Scan': lambda row: int(row['Label'] == 'Scan'),
}

def get_device_type(ip):
    # Example device types
    device_types = [
        'Laptop', 'Mobile', 'Tablet', 'Smart TV', 'IoT Device', 'Printer', 'Router', 'Desktop', 'Samsung Mobile', 'iPhone', 'MacBook', 'Windows PC', 'Linux Server', 'Camera', 'Game Console'
    ]
    random.seed(hash(ip) % 100000)  # Deterministic per IP
    return random.choice(device_types)

def preprocess(df, fit_scaler=True, scaler=None):
    df = df.copy()
    # Encode categorical features
    for col in CATEGORICAL:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
    # Scale features
    if fit_scaler:
        scaler = MinMaxScaler()
        df[FEATURES + CATEGORICAL] = scaler.fit_transform(df[FEATURES + CATEGORICAL])
    else:
        df[FEATURES + CATEGORICAL] = scaler.transform(df[FEATURES + CATEGORICAL])
    # Multi-label targets
    y = np.stack([df.apply(LABEL_MAP[label], axis=1) for label in LABELS], axis=1)
    return df[FEATURES + CATEGORICAL], y, scaler

def train_multilabel_nn(X, y):
    model = Sequential([
        Dense(64, activation='relu', input_shape=(X.shape[1],)),
        Dropout(0.2),
        Dense(32, activation='relu'),
        Dense(16, activation='relu'),
        Dense(len(LABELS), activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    es = EarlyStopping(monitor='loss', patience=5, restore_best_weights=True)
    model.fit(X, y, epochs=50, batch_size=64, verbose=1, callbacks=[es])
    return model

def main_train(csv_file, model_file='pcap_ai_model.h5'):
    df = pd.read_csv(csv_file)
    X, y, scaler = preprocess(df, fit_scaler=True)
    model = train_multilabel_nn(X, y)
    model.save(model_file)
    print(f"Model saved to {model_file}")
    import joblib
    joblib.dump(scaler, 'scaler.save')

def main_predict(csv_file, model_file='pcap_ai_model.h5'):
    # Fix: Remove trailing slash if present
    csv_file = csv_file.rstrip('/\\')
    df = pd.read_csv(csv_file)
    import joblib
    scaler = joblib.load('scaler.save')
    # Ensure all required columns exist, fill with default if missing
    for col in CATEGORICAL:
        if col not in df.columns:
            df[col] = 'NONE'  # Default value for missing categorical columns
    for col in FEATURES:
        if col not in df.columns:
            df[col] = 0  # Default value for missing numeric columns
    # Protocol breakdown (use original column before encoding)
    proto_counts = {}
    if 'Protocol' in df.columns:
        for proto in df['Protocol']:
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
    total_packets = sum(proto_counts.values())
    proto_breakdown = [(proto, int(100 * count / total_packets)) for proto, count in proto_counts.items()]
    proto_breakdown_sorted = sorted(proto_breakdown, key=lambda x: x[1], reverse=True)
    # Now encode and scale
    for col in CATEGORICAL:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
    X = scaler.transform(df[FEATURES + CATEGORICAL])
    model = load_model(model_file, compile=False)
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    preds = model.predict(X)
    # Threshold for detection
    pred_labels = (preds > 0.5).astype(int)
    # Reporting
    devices = set(df['Source']).union(set(df['Destination'])) if 'Source' in df.columns and 'Destination' in df.columns else set()
    # Map: device (source IP) -> set of destination IPs/sites
    device_sites = {}
    device_types_map = {}
    if 'Source' in df.columns and 'Destination' in df.columns:
        for src, dst in zip(df['Source'], df['Destination']):
            if src not in device_sites:
                device_sites[src] = set()
            device_sites[src].add(dst)
            if src not in device_types_map:
                device_types_map[src] = get_device_type(src)
    vpn_rows = df[pred_labels[:, LABELS.index('VPN')] == 1] if 'VPN' in LABELS else pd.DataFrame()
    blacklist_rows = df[pred_labels[:, LABELS.index('Blacklist')] == 1] if 'Blacklist' in LABELS else pd.DataFrame()
    server_rows = df[pred_labels[:, LABELS.index('Server')] == 1] if 'Server' in LABELS else pd.DataFrame()
    scan_rows = df[pred_labels[:, LABELS.index('Scan')] == 1] if 'Scan' in LABELS else pd.DataFrame()
    anomaly_rows = df[pred_labels[:, LABELS.index('Anomaly')] == 1] if 'Anomaly' in LABELS else pd.DataFrame()
    # Calculate top talkers
    top_talkers = {}
    if 'Source' in df.columns:
        for src in df['Source']:
            top_talkers[src] = top_talkers.get(src, 0) + 1
    top_talkers_sorted = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:3]
    # Calculate most contacted destinations
    dest_counts = {}
    if 'Destination' in df.columns:
        for dst in df['Destination']:
            dest_counts[dst] = dest_counts.get(dst, 0) + 1
    dest_counts_sorted = sorted(dest_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    # Write formatted report with UTF-8 encoding
    with open('analysis_report.txt', 'w', encoding='utf-8') as f:
        f.write('==== Network Security Summary ====' + '\n\n')
        f.write(f"Number of devices: {len(devices)}\n")
        f.write(f"VPN packets: {len(vpn_rows)}\n")
        f.write(f"Blacklist hits: {len(blacklist_rows)}\n")
        f.write(f"Server packets: {len(server_rows)}\n")
        f.write(f"Scans detected: {len(scan_rows)}\n")
        f.write(f"Anomalies: {len(anomaly_rows)}\n\n")
        f.write('Top Talkers:\n')
        for ip, count in top_talkers_sorted:
            f.write(f"  • {ip} ({count} packets)\n")
        f.write('\n')
        f.write('Most Contacted Destinations:\n')
        for ip, count in dest_counts_sorted:
            f.write(f"  • {ip}\n")
        f.write('\n')
        f.write('Protocol Breakdown:\n')
        for proto, percent in proto_breakdown_sorted:
            f.write(f"  • {proto} : {percent}%\n")
    print('Analysis report saved to analysis_report.txt')

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python pcap_ai_model.py train|predict <csv_file>")
        sys.exit(1)
    if sys.argv[1] == 'train':
        main_train(sys.argv[2])
    elif sys.argv[1] == 'predict':
        main_predict(sys.argv[2])
    else:
        print("Unknown command. Use 'train' or 'predict'.") 