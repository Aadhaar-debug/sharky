# PCAP/CSV Network Analyzer AI

This project is an AI-powered tool for analyzing network traffic captured in Wireshark `.pcapng` or `.csv` files. It uses a neural network to detect anomalies, VPN usage, blacklist hits, server activity, scans, and more, and generates a clean, human-friendly summary report.

## Features
- Parses Wireshark `.pcapng` files (via `pcap_analyzer.py`) and `.csv` files
- Trains a neural network to detect:
  - Anomalies
  - VPN usage
  - Blacklist hits
  - Server activity
  - Scans
  - Protocol breakdown
- Generates a simple, readable summary report
- Works with large capture files

## Example Output
```
==== Network Security Summary ====

Number of devices: 8
VPN packets: 12
Blacklist hits: 1
Server packets: 34
Scans detected: 2
Anomalies: 3

Top Talkers:
  • 192.168.1.2 (1200 packets)
  • 10.0.0.5 (900 packets)
  • 172.16.0.10 (850 packets)

Most Contacted Destinations:
  • 8.8.8.8
  • 104.244.42.1
  • 185.175.0.4

Protocol Breakdown:
  • TCP : 60%
  • UDP : 30%
  • HTTP : 10%
```

## Setup Instructions

### 1. Clone the Repository
```
git clone <your-repo-url>
cd <repo-directory>
```

### 2. Install Requirements
```
pip install -r requirements.txt
```

### 3. Prepare Your Data
- For `.pcapng` files: Use `pcap_analyzer.py` to convert to CSV:
  ```
  python pcap_analyzer.py yourfile.pcapng
  # This creates yourfile.pcapng.csv
  ```
- For `.csv` files: Ensure columns include at least: `No.`, `Time`, `Source`, `Destination`, `Protocol`, `Length`, `Info`

### 4. Train the Model (Optional)
If you want to train your own model:
```
python pcap_ai_model.py train yourfile.csv
```
This creates `pcap_ai_model.h5` and `scaler.save`.

### 5. Run Analysis
```
python pcap_ai_model.py predict yourfile.csv
```
This generates `analysis_report.txt` with the summary.

## Required Libraries
- pandas
- numpy
- scikit-learn
- tensorflow
- pyshark
- scapy
- matplotlib
- seaborn
- jinja2

Install all with:
```
pip install -r requirements.txt
```

## Files
- `pcap_analyzer.py` — Converts `.pcapng` to `.csv`
- `pcap_ai_model.py` — Trains and runs the neural network, generates the report
- `requirements.txt` — Python dependencies
- `sample.csv` — Example input file (replace with your own)
- `pcap_ai_model.h5` — Trained model (generated after training)
- `analysis_report.txt` — Output report (generated after prediction)

## License
See [LICENSE](LICENSE).

---

**Made with ❤️ for easy, smart network traffic analysis!**