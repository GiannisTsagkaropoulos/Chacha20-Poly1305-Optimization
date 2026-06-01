#!/usr/bin/env python3
"""Plot Poly2133 benchmark CSVs produced by `run_poly2133_benchmarks.py`.

For every `plots/poly2133_create_tag_<level>.csv`, produce three plots:
  * `poly2133_create_tag_<level>_cycles.png` -- raw cycles vs ctxt_len   (log-log)
  * `poly2133_create_tag_<level>_cpb.png`    -- cycles per byte vs size  (semi-log x)
  * `poly2133_create_tag_<level>_roofline.png` -- roofline plot
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
CSV_GLOB = os.path.join(PLOTS_DIR, "poly2133_create_tag_*.csv")
COMBINED_PLOTS_DIR = os.path.join(os.path.dirname(__file__), "../../figures/plots/poly2133")

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

def read_ops_csv(path: str) -> Dict[str, int]:
    with open(path, newline="") as f:
        reader = csv.reader(f)
        next(reader)
        ops_map = {}
        for row in reader:
            if not row:
                continue
            func_name, ops = row
            ops_map[func_name] = int(float(ops))
    return ops_map


def plot_one(csv_path: str) -> None:
    data = read_csv(csv_path)
    sizes = data["ctxt_len"]
    funcs = [c for c in data.keys() if c != "ctxt_len"]

    base = os.path.splitext(os.path.basename(csv_path))[0]
    m = re.match(r"poly2133_create_tag_(\d+)", base)
    opt_level = m.group(1) if m else "?"

    # Read ops data
    ops_map = read_ops_csv(os.path.join(PLOTS_DIR, "poly2133_ops.csv"))

    # Cycles vs size (log-log)
    fig, ax = plt.subplots(figsize=(10, 5))
    for fn in funcs:
        ax.plot(sizes, data[fn], marker="o", linewidth=1.5, label=fn)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("ciphertext length [bytes]")
    ax.set_ylabel("cycles")
    ax.set_title(f"Poly2133 create tag -- cycles vs size  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend(
    loc='upper left',
    bbox_to_anchor=(1.02, 1),
    borderaxespad=0
    )
    fig.tight_layout()
    out_cycles = os.path.join(PLOTS_DIR, f"{base}_cycles.png")
    fig.savefig(out_cycles, dpi=130)
    out_cycles = os.path.join(COMBINED_PLOTS_DIR, f"{base}_cycles.png")
    fig.savefig(out_cycles, dpi=130)
    plt.close(fig)

    # Cycles per byte vs size (semi-log x)
    fig, ax = plt.subplots(figsize=(10, 5))
    for fn in funcs:
        cpb = [c / s for c, s in zip(data[fn], sizes)]
        ax.plot(sizes, cpb, marker="o", linewidth=1.5, label=fn)
    ax.set_xscale("log", base=2)
    ax.set_xlabel("ciphertext length [bytes]")
    ax.set_ylabel("cycles / byte")
    ax.set_title(f"Poly2133 create tag -- cycles per byte  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend(
    loc='upper left',
    bbox_to_anchor=(1.02, 1),
    borderaxespad=0
    )
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
    
    for fn in funcs:
        sizes_array = np.array(sizes)
        total_ops = ops_map[fn] * (sizes_array // 26)
        op_intensity = total_ops / sizes_array
        ops_per_cycle = total_ops / data[fn]
        ax.scatter(op_intensity, ops_per_cycle, s=70, zorder=5, 
                label=fn, edgecolors='white', alpha=0.8)
        all_x.extend(op_intensity)
        all_y.extend(ops_per_cycle)

    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    min_x = ridge_point / 4
    max_x = max(all_x) * 2
    min_y = min(all_y) / 2
    max_y = 26
    ax.set_xlim(min_x, max_x)
    ax.set_ylim(min_y, max_y)
    ax.set_xlabel("Operational Intensity [ops/bytes]")
    ax.set_ylabel("Performance [ops/cycle]")
    ax.set_title(f"Poly2133 create tag -- Roofline  (-O{opt_level})")
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
        total_ops = ops_map[fn] * (sizes_array // 26)
        ops_per_cycle = total_ops / data[fn]
        ax.plot(sizes, ops_per_cycle, marker="o", linewidth=1.5, label=fn)

    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("Ciphertext length [bytes]")
    ax.set_ylabel("Performance [ops/cycle]")
    ax.set_title(f"Poly2133 create tag -- ops/cycle vs size  (-O{opt_level})")
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
