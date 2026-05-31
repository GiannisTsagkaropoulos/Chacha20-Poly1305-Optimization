#!/usr/bin/env python3
import subprocess
import os
import sys

BINARY_PREFIX = "../../../bin/poly1305_complete_"
OUTPUT_DIR = "plots"
OUTPUT_FILE_PREFIX = "poly1305_complete"

SIZES = [1 << i for i in range(8,11)]

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

    header = run(BINARY_PREFIX + "3", "--header")

    rows3 = [header]

    for size in SIZES:
        if size >= 1 << 20:
            printed_size = f"{size >> 20} MB"
        elif size >= 1 << 10:
            printed_size = f"{size >> 10} KB"
        else:
            printed_size = f"{size} B"
        print("CTXT_LEN:", printed_size)
        try:
            rows3.append(run(BINARY_PREFIX + "3", str(size)))
        except subprocess.CalledProcessError:
            print("  skipped (binary returned error)", file=sys.stderr)


    OUTPUT_CSV_3 = os.path.join(OUTPUT_DIR, OUTPUT_FILE_PREFIX + "_3.csv")
    with open(OUTPUT_CSV_3, "w") as f:
        f.write("\n".join(rows3) + "\n")

    print("Success")

if __name__ == "__main__":
    main()