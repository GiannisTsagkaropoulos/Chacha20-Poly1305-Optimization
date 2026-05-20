#!/usr/bin/env python3
import subprocess
import os
import sys

BINARY     = "./bench_chacha_encrypt"
OUTPUT_DIR = "plots"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "chacha_encrypt.csv")

SIZES = [1 << i for i in range(8,17)] 

def run(arg: str) -> str:
    """Run the binary with one argument and return its stdout."""
    result = subprocess.run(
        [BINARY, arg],
        capture_output=True, text=True
    )
    if result.returncode != 0 or result.stderr:
        print(result.stderr.strip(), file=sys.stderr)
    result.check_returncode()
    return result.stdout.strip()


def main():
    subprocess.run(["make", "bench_chacha_encrypt"], check=True)

    header = run("--header")
    rows = [header]
    for size in SIZES:
        if size >= 1 << 20:
            printed_size = f"{size >> 20} MB"
        elif size >= 1 << 10:
            printed_size = f"{size >> 10} KB"
        else:            
            printed_size = f"{size} B"
        print("PTXT_LEN: ", printed_size)
        try:
            rows.append(run(str(size)))
        except subprocess.CalledProcessError:
            print(f"  skipped (binary returned error)", file=sys.stderr)

    with open(OUTPUT_CSV, "w") as f:
        f.write("\n".join(rows) + "\n")

    print("Success! Data saved to ", OUTPUT_CSV)
    

if __name__ == "__main__":
    main()