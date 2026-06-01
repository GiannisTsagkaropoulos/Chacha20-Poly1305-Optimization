#!/usr/bin/env python3
"""Plot ChaCha20-Poly2133 AEAD benchmark CSVs produced by `run_chacha_poly2133_benchmarks.py`
"""

import csv
import glob
import os
import re
import sys
from typing import Dict, List
import numpy as np

import matplotlib.pyplot as plt

PLOTS_DIR = os.path.join(os.path.dirname(__file__), "plots")
CSV_GLOB = os.path.join(PLOTS_DIR, "chacha_poly2133_*.csv")
COMBINED_PLOTS_DIR = os.path.join(os.path.dirname(__file__), "../../figures/plots/chacha20_poly2133")

# set machine specific parameters
PEAK_PERF = 4  # in ops/cycle
PEAK_PERF_VEC = 24  # in ops/cycle for vectorized code
MEM_BAND = 13.4  # in bytes/cycle


def read_csv(path: str) -> Dict[str, List[float]]:
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        cols: Dict[str, List[float]] = {h: [] for h in header}
        for row in reader:
            if not row:
                continue
            for h, v in zip(header, row):
                cols[h].append(float(v))
    return cols

def load_ops_csv(path: str) -> Dict[str, Dict[int, int]]:
    ops_data = {}
    try:
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fn = row["function_name"]
                ptxt_len = int(row["ptxt_len"])
                total_ops = int(row["total_ops"])
                if fn not in ops_data:
                    ops_data[fn] = {}
                ops_data[fn][ptxt_len] = total_ops
    except FileNotFoundError:
        print(f"Warning: ops CSV not found at {path}")
    return ops_data

def plot_one(csv_path: str) -> None:
    data = read_csv(csv_path)
    sizes = data["ptxt_len"]
    funcs = [c for c in data.keys() if c != "ptxt_len"]

    base = os.path.splitext(os.path.basename(csv_path))[0]
    m = re.match(r"chacha_poly2133_(\w+?)_(\d+)", base)
    op = m.group(1) if m else "?"
    opt_level = m.group(2) if m else "?"

    ops_csv_path = os.path.join(PLOTS_DIR, "encrypt_ops.csv")
    ops_data = load_ops_csv(ops_csv_path)
    ops_funcs = list(ops_data.keys())

    # Cycles vs size (log-log)
    fig, ax = plt.subplots(figsize=(8, 5))
    for fn in funcs:
        ax.plot(sizes, data[fn], marker="o", linewidth=1.5, label=fn)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("plaintext length [bytes]")
    ax.set_ylabel("cycles")
    ax.set_title(f"ChaCha20-Poly2133 {op} -- cycles vs size  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend()
    fig.tight_layout()
    out_cycles = os.path.join(PLOTS_DIR, f"{base}_cycles.png")
    fig.savefig(out_cycles, dpi=130)
    out_cycles = os.path.join(COMBINED_PLOTS_DIR, f"{base}_cycles.png")
    fig.savefig(out_cycles, dpi=130)
    plt.close(fig)

    # Cycles per byte vs size (semi-log x)
    fig, ax = plt.subplots(figsize=(8, 5))
    for fn in funcs:
        cpb = [c / s for c, s in zip(data[fn], sizes)]
        ax.plot(sizes, cpb, marker="o", linewidth=1.5, label=fn)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("plaintext length [bytes]")
    ax.set_ylabel("cycles / byte")
    ax.set_title(f"ChaCha20-Poly2133 {op} -- cycles per byte  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend()
    fig.tight_layout()
    out_cpb = os.path.join(PLOTS_DIR, f"{base}_cpb.png")
    fig.savefig(out_cpb, dpi=130)
    out_cpb = os.path.join(COMBINED_PLOTS_DIR, f"{base}_cpb.png")
    fig.savefig(out_cpb, dpi=130)
    plt.close(fig)


    # Roofline plot
    fig, ax = plt.subplots(figsize=(10, 5))
    x_range = np.logspace(-20, 7, num=1000, base=2)
    y_peak = np.full_like(x_range, PEAK_PERF)  
    y_bandwidth = MEM_BAND * x_range
    ridge_point = PEAK_PERF / MEM_BAND 
    all_x = []
    all_y = []

    def roofline_scalar(x):
        return np.minimum(PEAK_PERF, MEM_BAND * x)
    def roofline_vector(x):
        return np.minimum(PEAK_PERF_VEC, MEM_BAND * x)

    plt.plot(x_range, roofline_scalar(x_range), color='black', linewidth=2)
    plt.plot(x_range, roofline_vector(x_range), color='black', linewidth=2)
    
    for i, fn in enumerate(funcs):
        sizes_array = np.array(sizes)
        if i < len(ops_funcs):
            ops_per_size = []
            for s in sizes_array:
                s_int = int(s)
                # Get ops for this exact size from ops_data
                ops = ops_data[ops_funcs[i]].get(s_int, None)
                if ops is None:
                    print(f"Warning: no ops data for {ops_funcs[i]} at size {s_int}")
                ops_per_size.append(ops if ops else 0)
            
            total_ops = np.array(ops_per_size)
            op_intensity = total_ops / sizes_array
            ops_per_cycle = total_ops / np.array(data[fn])
            ax.scatter(op_intensity, ops_per_cycle, s=70, zorder=5, 
                    label=fn, edgecolors='white', alpha=0.8)
            all_x.extend(op_intensity)
        all_y.extend(ops_per_cycle)

    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    min_x = ridge_point / 4
    max_x = max(all_x) * 2
    min_y = 1
    max_y = 27
    ax.set_xlim(min_x, max_x)
    ax.set_ylim(min_y, max_y)
    ax.set_xlabel("Operational Intensity [ops/bytes]")
    ax.set_ylabel("Performance [ops/cycle]")
    ax.set_title(f"ChaCha20-Poly2133 {op} -- Roofline  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend(
    loc='upper left',
    bbox_to_anchor=(1.02, 1),
    borderaxespad=0
    )
    fig.tight_layout()
    out_roofline = os.path.join(PLOTS_DIR, f"{base}_roofline.png")
    fig.savefig(out_roofline, dpi=130)
    out_roofline = os.path.join(COMBINED_PLOTS_DIR, f"{base}_roofline.png")
    fig.savefig(out_roofline, dpi=130)
    plt.close(fig)

    # Cycles/Ops vs size (log-log)
    fig, ax = plt.subplots(figsize=(10, 5))
    for fn in funcs:
        sizes_array = np.array(sizes)
        if i < len(ops_funcs):
            ops_per_size = []
            for s in sizes_array:
                s_int = int(s)
                # Get ops for this exact size from ops_data
                ops = ops_data[ops_funcs[i]].get(s_int, None)
                if ops is None:
                    print(f"Warning: no ops data for {ops_funcs[i]} at size {s_int}")
                ops_per_size.append(ops if ops else 0)
            
            total_ops = np.array(ops_per_size)
            op_intensity = total_ops / sizes_array
            ops_per_cycle = total_ops / np.array(data[fn])
            ax.plot(sizes, ops_per_cycle, marker="o", linewidth=1.5, label=fn)

    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Ciphertext length [bytes]")
    ax.set_ylabel("Performance [ops/cycle]")
    ax.set_title(f"ChaCha20-Poly2133 {op} -- ops/cycle vs size  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend(
    loc='upper left',
    bbox_to_anchor=(1.02, 1),
    borderaxespad=0
    )
    fig.tight_layout()
    out_performance = os.path.join(PLOTS_DIR, f"{base}_performance.png")
    fig.savefig(out_performance, dpi=130)
    out_performance = os.path.join(COMBINED_PLOTS_DIR, f"{base}_performance.png")
    fig.savefig(out_performance, dpi=130)
    plt.close(fig)

    print(f"  wrote {out_cycles}")
    print(f"  wrote {out_cpb}")
    print(f"  wrote {out_roofline}")
    print(f"  wrote {out_performance}")


def main() -> int:
    csv_files = sorted(glob.glob(CSV_GLOB))
    if not csv_files:
        print(f"No CSV files found in {PLOTS_DIR}", file=sys.stderr)
        return 1
    for path in csv_files:
        print(f"plotting {path}")
        plot_one(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
