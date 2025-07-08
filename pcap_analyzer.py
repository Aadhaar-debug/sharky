import pyshark
import pandas as pd
import sys

# Step 1: Parse PCAP and extract features
def parse_pcap(pcap_file):
    cap = pyshark.FileCapture(pcap_file, only_summaries=True)
    packets = []
    for pkt in cap:
        packets.append({
            'No.': pkt.no,
            'Time': pkt.time,
            'Source': pkt.source,
            'Destination': pkt.destination,
            'Protocol': pkt.protocol,
            'Length': pkt.length,
            'Info': pkt.info
        })
    cap.close()
    return pd.DataFrame(packets)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_analyzer.py <file.pcap>")
        sys.exit(1)
    df = parse_pcap(sys.argv[1])
    print(df.head())
    # Save to CSV for AI model
    csv_file = sys.argv[1] + '.csv'
    df.to_csv(csv_file, index=False)
    print(f"Saved parsed data to {csv_file}") 