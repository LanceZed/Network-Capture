import subprocess
import time
import os
import pandas as pd
from datetime import datetime
import numpy as np

interface = "en0" #interface for diffrent os
capture_duration = 10
base_dir = "/Users/abcb/Desktop/network_pipeline" #path to dir

pcap_dir = os.path.join(base_dir, "pcaps")
zeek_dir = os.path.join(base_dir, "zeek_logs")
csv_dir = os.path.join(base_dir, "csvs")
argus_dir = os.path.join(base_dir, "argus_logs")

for d in [pcap_dir, zeek_dir, csv_dir, argus_dir]:
    os.makedirs(d, exist_ok=True)

template_columns = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'service', 'state', 'dur',
    'spkts', 'dpkts', 'sbytes', 'dbytes', 'sload', 'dload', 'sttl', 'dttl',
    'smean', 'dmean', 'smeansz', 'dmeansz', 'ct_srv_src', 'ct_src_ltm', 'ct_dst_ltm', 'label'
]

def run_tshark(pcap_path, tshark_out_path):
    fields = [
        '-e', 'ip.src', '-e', 'tcp.srcport', '-e', 'ip.dst', '-e', 'tcp.dstport',
        '-e', 'ip.ttl', '-e', 'frame.len'
    ]
    command = ["tshark", "-r", pcap_path, "-T", "fields", *fields, "-E", "separator=,"]
    with open(tshark_out_path, 'w') as f:
        subprocess.run(command, stdout=f)

def run_capture(pcap_path):
    command = ["tshark", "-i", interface, "-a", f"duration:{capture_duration}", "-w", pcap_path]
    subprocess.run(command)

def run_zeek(pcap_path, zeek_out_dir):
    os.makedirs(zeek_out_dir, exist_ok=True)
    command = ["zeek", "-C", "-r", pcap_path]
    subprocess.run(command, cwd=zeek_out_dir, capture_output=True)

def run_argus(pcap_path, argus_out_path):
    command = ["argus", "-r", pcap_path, "-w", argus_out_path]
    subprocess.run(command)

def read_argus_summary(argus_out_path):
    command = ["rasort", "-r", argus_out_path, "-m", "saddr sport daddr dport proto"]
    result = subprocess.run(command, capture_output=True, text=True)
    lines = result.stdout.strip().split("\n")
    records = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 5:
            try:
                records.append({
                    "srcip": parts[0],
                    "sport": int(parts[1]),
                    "dstip": parts[2],
                    "dsport": int(parts[3]),
                    "proto": parts[4].lower()
                })
            except Exception:
                continue
    return pd.DataFrame(records)

def read_tshark_summary(tshark_out_path):
    cols = ['srcip', 'sport', 'dstip', 'dsport', 'ttl', 'length']
    try:
        df = pd.read_csv(
            tshark_out_path,
            names=cols,
            on_bad_lines='skip',
            engine='python'
        )
    except Exception as e:
        print(f"Error reading tshark output: {e}")
        return pd.DataFrame()

    df = df.dropna(subset=['srcip', 'dstip'])

    df['sport'] = pd.to_numeric(df['sport'], errors='coerce').fillna(0).astype(int)
    df['dsport'] = pd.to_numeric(df['dsport'], errors='coerce').fillna(0).astype(int)
    df['ttl'] = pd.to_numeric(df['ttl'], errors='coerce').fillna(0)
    df['length'] = pd.to_numeric(df['length'], errors='coerce').fillna(0)

    agg = df.groupby(['srcip', 'sport', 'dstip', 'dsport']).agg(
        sttl=('ttl', 'mean'),
        dttl=('ttl', 'mean'),
        smean=('length', 'mean'),
        dmean=('length', 'mean')
    ).reset_index()

    return agg

def safe_get(df, col):
    return df[col] if col in df.columns else pd.Series([np.nan] * len(df))

def read_zeek_conn_log(log_path):
    with open(log_path, 'r') as f:
        for line in f:
            if line.startswith('#fields'):
                columns = line.strip().split('\t')[1:]
                break
    df = pd.read_csv(log_path, sep='\t', comment='#', header=None, engine='python')
    df.columns = columns
    return df

def convert_connlog_to_nsw_csv(zeek_out_dir, argus_df, tshark_df, out_csv_path):
    log_path = os.path.join(zeek_out_dir, "conn.log")
    if not os.path.exists(log_path):
        return
    df = read_zeek_conn_log(log_path)
    if df.empty:
        return

    out = pd.DataFrame()
    out["srcip"] = safe_get(df, "id.orig_h")
    out["sport"] = safe_get(df, "id.orig_p")
    out["dstip"] = safe_get(df, "id.resp_h")
    out["dsport"] = safe_get(df, "id.resp_p")
    out["proto"] = safe_get(df, "proto").str.lower()
    out["service"] = safe_get(df, "service")
    out["state"] = safe_get(df, "conn_state")
    out["dur"] = pd.to_numeric(safe_get(df, "duration"), errors='coerce')
    out["spkts"] = pd.to_numeric(safe_get(df, "orig_pkts"), errors='coerce')
    out["dpkts"] = pd.to_numeric(safe_get(df, "resp_pkts"), errors='coerce')
    out["sbytes"] = pd.to_numeric(safe_get(df, "orig_bytes"), errors='coerce')
    out["dbytes"] = pd.to_numeric(safe_get(df, "resp_bytes"), errors='coerce')

    out = out[out["dur"] > 0]

    out["sload"] = (out["sbytes"] * 8 / out["dur"]).replace([np.inf, -np.inf], 0)
    out["dload"] = (out["dbytes"] * 8 / out["dur"]).replace([np.inf, -np.inf], 0)

    if not tshark_df.empty:
        out = out.merge(tshark_df, on=["srcip", "sport", "dstip", "dsport"], how="left")

    if not argus_df.empty:
        out = out.merge(argus_df, on=["srcip", "sport", "dstip", "dsport", "proto"], how="left")

    out["smeansz"] = pd.Series(np.where(
    safe_get(df, "orig_pkts").astype(float) > 0,
    safe_get(df, "orig_ip_bytes").astype(float) / safe_get(df, "orig_pkts").astype(float),
    0)).replace([np.inf, -np.inf], 0).fillna(0)

    out["dmeansz"] = pd.Series(np.where(
    safe_get(df, "resp_pkts").astype(float) > 0,
    safe_get(df, "resp_ip_bytes").astype(float) / safe_get(df, "resp_pkts").astype(float),
    0)).replace([np.inf, -np.inf], 0).fillna(0)

    for col in ["sttl", "dttl", "smean", "dmean", "smeansz", "dmeansz"]:
        if col not in out.columns:
            out[col] = 0
        else:
            out[col] = out[col].fillna(0)

    out["ct_srv_src"] = out.groupby(['srcip', 'sport', 'proto'])['dstip'].transform('nunique').fillna(0)
    out["ct_src_ltm"] = out.groupby(['srcip'])['dstip'].transform('nunique').fillna(0)
    out["ct_dst_ltm"] = out.groupby(['dstip'])['srcip'].transform('nunique').fillna(0)

    out["label"] = "unknown"

    for col in template_columns:
        if col not in out.columns:
            out[col] = 0 if col != "label" else "unknown"

    out = out[template_columns]

    if "srcip" in out.columns and "dstip" in out.columns:
        out = out.dropna(subset=["srcip", "dstip"])

    out.to_csv(out_csv_path, index=False)

def main_loop():
    while True:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(pcap_dir, f"capture_{ts}.pcap")
        tshark_file = os.path.join(pcap_dir, f"tshark_{ts}.csv")
        zeek_out = os.path.join(zeek_dir, f"zeek_{ts}")
        csv_out = os.path.join(csv_dir, f"flow_{ts}.csv")
        argus_out = os.path.join(argus_dir, f"argus_{ts}.argus")

        run_capture(pcap_file)
        run_zeek(pcap_file, zeek_out)
        run_tshark(pcap_file, tshark_file)
        run_argus(pcap_file, argus_out)

        tshark_df = read_tshark_summary(tshark_file)
        argus_df = read_argus_summary(argus_out)
        convert_connlog_to_nsw_csv(zeek_out, argus_df, tshark_df, csv_out)

        time.sleep(1)

if __name__ == "__main__":
    main_loop()
