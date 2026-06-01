#!/usr/bin/env python3
"""Run the ChaCha20-Poly2133 AEAD benchmarks (encrypt + decrypt) and write CSVs
"""
import subprocess
import os
import sys
import time

BIN_DIR = "../../bin"
OUTPUT_DIR = "plots"

# (operation name, binary prefix) -- the trailing "3" selects the -O3 build.
OPERATIONS = [
    ("encrypt", os.path.join(BIN_DIR, "bench_chacha_poly2133_encrypt_")),
    ("decrypt", os.path.join(BIN_DIR, "bench_chacha_poly2133_decrypt_")),
]

EXPONENTS = range(11, 22)


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
        print(f"=== ChaCha20-Poly2133 {op_name} ===")
        header = run(prefix + "3", "--header")
        rows = [header]

        for exp in EXPONENTS:
            size = 1 << exp
            if size >= 1 << 20:
                printed_size = f"{size >> 20} MB"
            elif size >= 1 << 10:
                printed_size = f"{size >> 10} KB"
            else:
                printed_size = f"{size} B"
            print("\n\n ----STARTING RUN---- \n PTXT_LEN:", printed_size, "(", size, "B)")
            start = time.time()
            try:
                rows.append(run(prefix + "3", str(size)))
                end = time.time() - start
                print("Res:", rows)
                print("Time took:", end)
            except subprocess.CalledProcessError:
                print("  skipped (binary returned error)", file=sys.stderr)

        output_csv = os.path.join(OUTPUT_DIR, f"chacha_poly2133_{op_name}_3.csv")
        with open(output_csv, "w") as f:
            f.write("\n".join(rows) + "\n")
        print(f"  wrote {output_csv}")

    print("Success")


if __name__ == "__main__":
    main()
