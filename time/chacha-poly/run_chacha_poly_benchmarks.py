#!/usr/bin/env python3
"""Run the ChaCha20-Poly1305 AEAD benchmarks (encrypt + decrypt) and write CSVs
"""
import subprocess
import os
import sys

BIN_DIR = "../../bin"
OUTPUT_DIR = "plots"

# (operation name, binary prefix) -- the trailing "3" selects the -O3 build.
OPERATIONS = [
    ("encrypt", os.path.join(BIN_DIR, "bench_chacha_poly_encrypt_")),
    ("decrypt", os.path.join(BIN_DIR, "bench_chacha_poly_decrypt_")),
]

SIZES = [1 << i for i in range(10, 26)]


def run(binary: str, arg: str) -> str:
    """Run the binary with one argument and return its stdout."""
    result = subprocess.run(
        [binary, arg],
        capture_output=True, text=True
    )
    if result.returncode != 0 or result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
        result.check_returncode()
    return result.stdout.strip()


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for op_name, prefix in OPERATIONS:
        print(f"=== ChaCha20-Poly1305 {op_name} ===")
        header = run(prefix + "3", "--header")
        rows = [header]

        for size in SIZES:
            if size >= 1 << 20:
                printed_size = f"{size >> 20} MB"
            elif size >= 1 << 10:
                printed_size = f"{size >> 10} KB"
            else:
                printed_size = f"{size} B"
            print("PTXT_LEN:", printed_size)
            try:
                rows.append(run(prefix + "3", str(size)))
            except subprocess.CalledProcessError:
                print("  skipped (binary returned error)", file=sys.stderr)

        output_csv = os.path.join(OUTPUT_DIR, f"chacha_poly_{op_name}_3.csv")
        with open(output_csv, "w") as f:
            f.write("\n".join(rows) + "\n")
        print(f"  wrote {output_csv}")

    print("Success")


if __name__ == "__main__":
    main()
