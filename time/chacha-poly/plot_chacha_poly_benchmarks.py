#!/usr/bin/env python3
"""Plot ChaCha20-Poly1305 AEAD benchmark CSVs produced by `run_chacha_poly_benchmarks.py`
"""

import csv
import glob
import os
import re
import sys
from typing import Dict, List

import matplotlib.pyplot as plt

PLOTS_DIR = os.path.join(os.path.dirname(__file__), "plots")
CSV_GLOB = os.path.join(PLOTS_DIR, "chacha_poly_*.csv")


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


def plot_one(csv_path: str) -> None:
    data = read_csv(csv_path)
    sizes = data["ptxt_len"]
    funcs = [c for c in data.keys() if c != "ptxt_len"]

    base = os.path.splitext(os.path.basename(csv_path))[0]
    m = re.match(r"chacha_poly_(\w+?)_(\d+)", base)
    op = m.group(1) if m else "?"
    opt_level = m.group(2) if m else "?"

    # Cycles vs size (log-log)
    fig, ax = plt.subplots(figsize=(8, 5))
    for fn in funcs:
        ax.plot(sizes, data[fn], marker="o", linewidth=1.5, label=fn)
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("plaintext length [bytes]")
    ax.set_ylabel("cycles")
    ax.set_title(f"ChaCha20-Poly1305 {op} -- cycles vs size  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend()
    fig.tight_layout()
    out_cycles = os.path.join(PLOTS_DIR, f"{base}_cycles.png")
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
    ax.set_title(f"ChaCha20-Poly1305 {op} -- cycles per byte  (-O{opt_level})")
    ax.grid(True, which="both", linestyle=":", alpha=0.6)
    ax.legend()
    fig.tight_layout()
    out_cpb = os.path.join(PLOTS_DIR, f"{base}_cpb.png")
    fig.savefig(out_cpb, dpi=130)
    plt.close(fig)

    print(f"  wrote {out_cycles}")
    print(f"  wrote {out_cpb}")


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
