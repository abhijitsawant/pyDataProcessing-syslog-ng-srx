#!/usr/bin/env python3
import os
import json
import time
from datetime import datetime

SYSLOG_DIR = "./syslog"
OUTPUT_DIR = "./output"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "master_record.json")


def generate_output_filename(output_dir):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(output_dir, f"FDB_DP_v11_{timestamp}.json")

def process_syslog_files(start_time):
    master_record = {}
    connections = 0
    sessionClose = 0
    filesProcessed = []

    # Walk through syslog directory
    for root, _, files in os.walk(SYSLOG_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            with open(filepath, "r") as f:
                filesProcessed.append(filepath)
                for line in f:
                    parts = line.strip().split(",")
                    connections += 1

                    # Ensure line has required fields
                    if len(parts) < 13:
                        continue
                        
                    (
                        timestamp, firewall_ip, _, source_ip, destination_ip,
                        destination_port, protocol_id, source_nat_ip, destination_nat_ip,
                        packets_in, bytes_in, packets_out, bytes_out
                    ) = parts[:13]
                    

                    # Skip if no packet/byte counts
                    if not (packets_in and bytes_in and packets_out and bytes_out):
                        continue
                    sessionClose +=1
                    try:
                        packets_in = int(packets_in)
                        bytes_in = int(bytes_in)
                        packets_out = int(packets_out)
                        bytes_out = int(bytes_out)
                    except ValueError:
                        continue  # Skip malformed entries

                    key = f"{firewall_ip}_{source_ip}_{destination_ip}_{destination_port}_{protocol_id}"

                    if key not in master_record:
                        master_record[key] = {
                            "key": key,
                            "source-ip": source_ip,
                            "destination-ip": destination_ip,
                            "packets-in": packets_in,
                            "bytes-in": bytes_in,
                            "packets-out": packets_out,
                            "bytes-out": bytes_out,
                            "count": 1
                        }
                    else:
                        rec = master_record[key]
                        rec["packets-in"] += packets_in
                        rec["bytes-in"] += bytes_in
                        rec["packets-out"] += packets_out
                        rec["bytes-out"] += bytes_out
                        rec["count"] += 1

    # Ensure output directory exists
    outputPath = generate_output_filename("output")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    end_time = time.time()
    elapsedTime = end_time - start_time
    metadata = {
        "startTime": start_time,
        "endTime": end_time,
        "elapsedTime": elapsedTime,
        "totalConnections": connections,
        "sessionClose" : f"{sessionClose} ({sessionClose/connections*100:.2f}% of total connections)",
        "flows": len(master_record),
        "filesProcessed": filesProcessed,
        "processingPerformance": {
            "connectionsPerSecond": f"{connections/elapsedTime:.2f} connections/second",
        }
    }
    print(len(master_record))
    payload = {
        "metadata":metadata,
        "data":master_record
    }

    # Write final aggregated result
    with open(outputPath, "w") as out:
        json.dump(payload, out, indent=2)

    print(f"Master record written to {OUTPUT_FILE} with {len(master_record)} unique keys.")

if __name__ == "__main__":
    start_time = time.time()
    process_syslog_files(start_time)
