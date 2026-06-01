#!/usr/bin/env python3
import subprocess
import os
import sys
import time

BINARY_PREFIX = "../../bin/bench_aead_encrypt_"
OUTPUT_DIR = "plots"
OUTPUT_FILE_PREFIX = "aead_encrypt"

SIZES = [1 << i for i in range(10,28)]

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
    # rows0 = [header]
    # rows1 = [header]
    # rows2 = [header]
    # rows3 = [header]
    rows3_no_vec = [header]

    for size in SIZES:
        if size >= 1 << 20:
            printed_size = f"{size >> 20} MB"
        elif size >= 1 << 10:
            printed_size = f"{size >> 10} KB"
        else:
            printed_size = f"{size} B"
        print("\n\n ----STARTING RUN---- \n PTXT_LEN:", printed_size, "(", size, "B)")
        start = time.time()
        try:
            # rows0.append(run(BINARY_PREFIX + "0", str(size)))
            # rows1.append(run(BINARY_PREFIX + "1", str(size)))
            # rows2.append(run(BINARY_PREFIX + "2", str(size)))
            rows3_no_vec.append(run(BINARY_PREFIX + "3_no_vec", str(size)))
            end = time.time() - start
            print("Res:", rows3_no_vec)
            print("Time took:", end)
        except subprocess.CalledProcessError:
            print("  skipped (binary returned error)", file=sys.stderr)

    # OUTPUT_CSV_0 = os.path.join(OUTPUT_DIR, OUTPUT_FILE_PREFIX + "_0.csv")
    # with open(OUTPUT_CSV_0, "w") as f:
    #     f.write("\n".join(rows0) + "\n")

    # OUTPUT_CSV_1 = os.path.join(OUTPUT_DIR, OUTPUT_FILE_PREFIX + "_1.csv")
    # with open(OUTPUT_CSV_1, "w") as f:
    #     f.write("\n".join(rows1) + "\n")

    # OUTPUT_CSV_2 = os.path.join(OUTPUT_DIR, OUTPUT_FILE_PREFIX + "_2.csv")
    # with open(OUTPUT_CSV_2, "w") as f:
    #     f.write("\n".join(rows2) + "\n")

    # OUTPUT_CSV_3 = os.path.join(OUTPUT_DIR, OUTPUT_FILE_PREFIX + "_3.csv")
    # with open(OUTPUT_CSV_3, "w") as f:
    #     f.write("\n".join(rows3) + "\n")

    OUTPUT_CSV_3_NO_VEC = os.path.join(OUTPUT_DIR, OUTPUT_FILE_PREFIX + "_3_no_vec.csv")
    with open(OUTPUT_CSV_3_NO_VEC, "w") as f:
        f.write("\n".join(rows3_no_vec) + "\n")    

    print("Success")

if __name__ == "__main__":
    main()