#!/usr/bin/env python3
import os
import glob
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# i7-7700 Kaby Lake
PEAK_PERF = 4.0
PEAK_PERF_VEC = 24.0 
MEM_BAND = 13.4      

DATA_DIR = "data"
OUTPUT_DIR = "../../figures/plots/chacha"

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def compute_byte_transfer(ptxt_len):
    # 12 B Nonce
    # 32 B Key
    # full plaintext + full ciphertext
    return 16 + 32 + (2 * ptxt_len)

Y_TICKS = [2^0, 2, 4, 6, 8, 12, 16, 20, 24]
CACHE_LIMITS =  {
        'L1 (32KB)': 32 * 1024,
        'L2 (256KB)': 256 * 1024,
        'L3 (6MB)': 6 * 1024 * 1024
    }

def plot_performance(df_cycles, df_ops, suffix, out_path):
    plt.figure(figsize=(11, 7)) 
    
    # Align data frames
    common_lens = set(df_cycles['ptxt_len']).intersection(set(df_ops['ptxt_len']))
    df_c = df_cycles[df_cycles['ptxt_len'].isin(common_lens)].sort_values('ptxt_len')
    df_o = df_ops[df_ops['ptxt_len'].isin(common_lens)].sort_values('ptxt_len')
    
    ptxt_len = df_c['ptxt_len'].values
    funcs = [c for c in df_c.columns if c != 'ptxt_len' and not c.startswith('Unnamed')]
    
    for func in funcs:
        if func not in df_o.columns:
            continue
            
        cycles = df_c[func].values
        ops = df_o[func].values
        
        ops_per_cycle = ops / cycles
        
        plt.plot(ptxt_len, ops_per_cycle, marker='o', label=func)
    
    # --- ADDED: Horizontal Theoretical Performance Limits ---
    plt.axhline(y=PEAK_PERF, color='black', linestyle=':', linewidth=2, label=f'Scalar Max ({PEAK_PERF} ops/c)')
    plt.axhline(y=PEAK_PERF_VEC, color='black', linestyle=':', linewidth=2, label=f'Vector Max ({PEAK_PERF_VEC} ops/c)')
    
    for name, size in CACHE_LIMITS.items():
        plt.axvline(x=size, color='black', linestyle='-', linewidth=1, alpha=0.5)
        plt.text(size * 1.1, PEAK_PERF_VEC * 1.5, name, rotation=90, verticalalignment='top', fontsize=9, color='black')

    plt.xscale('log', base=2)
    plt.yscale('log', base=2)
    plt.ylim(1, PEAK_PERF_VEC + 1)
    plt.yticks(ticks=Y_TICKS)
    
    plt.xlabel('Plaintext Length (Bytes)')
    plt.ylabel('Performance (Ops / Cycle)')
    plt.title(f'ChaCha20 Encryption Performance ({suffix})')
    
    plt.grid(True, which="both", ls="--", alpha=0.6)
    plt.legend(loc='lower right')
    plt.tight_layout()
    
    plt.savefig(out_path)
    plt.close()
    print(f"    Saved: {out_path}")


def plot_roofline(df_cycles, df_ops, suffix, out_path):
    plt.figure(figsize=(10, 6))
    
    # Memory bound line (Diagonal): P <= b * I
    y_mem = MEM_BAND * x_roof
    
    y_scalar = np.minimum(y_mem, PEAK_PERF)
    y_vector = np.minimum(y_mem, PEAK_PERF_VEC)
    
    x_roof = np.logspace(-1, 3, 500)
    plt.plot(x_roof, y_scalar, 'r--', linewidth=2, label=f'Scalar Peak ({PEAK_PERF} ops/cycle)')
    plt.plot(x_roof, y_vector, 'b--', linewidth=2, label=f'Vector Peak ({PEAK_PERF_VEC} ops/cycle)')
    
    common_lens = set(df_cycles['ptxt_len']).intersection(set(df_ops['ptxt_len']))
    df_c = df_cycles[df_cycles['ptxt_len'].isin(common_lens)].sort_values('ptxt_len')
    df_o = df_ops[df_ops['ptxt_len'].isin(common_lens)].sort_values('ptxt_len')
    
    funcs = [c for c in df_c.columns if c != 'ptxt_len' and not c.startswith('Unnamed')]
    
    for func in funcs:
        if func not in df_o.columns:
            continue
            
        cycles = df_c[func].values
        ops = df_o[func].values
        ptxt_len = df_c['ptxt_len'].values
        
        bytes_transferred = np.array([compute_byte_transfer(L) for L in ptxt_len])
        
        op_intensity = ops / bytes_transferred
        perf = ops / cycles
        
        plt.scatter(op_intensity, perf, label=func, s=50, alpha=0.8, edgecolor='k')

    plt.xscale('log', base=10)
    plt.yscale('log', base=10)
    
    plt.xlabel('Operational Intensity (Ops / Byte transferred)')
    plt.ylabel('Performance (Ops / Cycle)')
    plt.title(f'Roofline Model: ChaCha20 ({suffix})')
    
    plt.xlim(min(x_roof), max(x_roof))
    plt.ylim(0.01, PEAK_PERF_VEC * 2)
    
    plt.grid(True, which="both", ls="--", alpha=0.6)
    plt.legend(loc='lower right')
    plt.tight_layout()
    
    plt.savefig(out_path)
    plt.close()
    print(f"  -> Saved {out_path}")


def main():
    ensure_dir(OUTPUT_DIR)
    
    cycle_files = glob.glob(os.path.join(DATA_DIR, "encrypt_cycles_*.csv"))
    
    if not cycle_files:
        print(f"No CSV files found in {DATA_DIR}. Please check your paths.")
        return

    for c_file in cycle_files:
        filename = os.path.basename(c_file)
        suffix = filename.replace("encrypt_cycles_", "").replace(".csv", "")
        
        o_file = os.path.join(DATA_DIR, f"encrypt_ops_{suffix}.csv")
        
        if not os.path.exists(o_file):
            print(f"Warning: Missing ops file for {suffix}. Skipping plots.")
            continue
        
        print(f"\nProcessing compilation flag: {suffix}")
        
        df_cycles = pd.read_csv(c_file).dropna(axis=1, how='all')
        df_ops = pd.read_csv(o_file).dropna(axis=1, how='all')
        
        perf_out = os.path.join(OUTPUT_DIR, f"chacha_performance_{suffix}.png")
        roof_out = os.path.join(OUTPUT_DIR, f"chacha_roofline_{suffix}.png")
        
        plot_performance(df_cycles, df_ops, suffix, perf_out)
        plot_roofline(df_cycles, df_ops, suffix, roof_out)

if __name__ == "__main__":
    main()