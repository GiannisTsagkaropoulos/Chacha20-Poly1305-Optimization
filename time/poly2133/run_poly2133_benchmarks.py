#!/usr/bin/env python3
import subprocess
import os
import sys
import time

import op_computation

BINARY_PREFIX_CYCLES = "../../bin/bench_poly2133_create_tag_"
OUTPUT_DIR = "data"
PREFIX_CYCLES = "cycles_poly2133_create_tag"
PREFIX_OPS = "ops_poly2133_create_tag"

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

def compute_ops_row(header: str, size: int) -> str:
    header_parts = header.split(",")
    func_names = header_parts[1:] 
    
    row_counts = [str(size)]
    
    for name in func_names:
        name = "get_" + name + "_complexity"
            
        if hasattr(op_computation, name):
            op_func = getattr(op_computation, name)
            count = op_func(size)
            row_counts.append(str(count))
        else:
            print(f"Warning: Looked for '{name}' but it doesn't exist.", file=sys.stderr)
            row_counts.append("NaN")
            
    return ",".join(row_counts)


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    header_cycles = run(BINARY_PREFIX_CYCLES + "3", "--header")
    header_ops = header_cycles

    cycles3, ops3 = [header_cycles], [header_ops]
    cycles3_no_vec, ops3_no_vec = [header_cycles], [header_ops]

    pairs = [
        ("_3.csv", cycles3, ops3),
        ("_3_no_vec.csv", cycles3_no_vec, ops3_no_vec)
    ]

    for suffix, cycle_data, op_data in pairs:
        with open(os.path.join(OUTPUT_DIR, PREFIX_CYCLES + suffix), "w") as f:
            f.write("\n".join(cycle_data) + "\n")
        with open(os.path.join(OUTPUT_DIR, PREFIX_OPS + suffix), "w") as f:
            f.write("\n".join(op_data) + "\n") 

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
            cycles3.append(run(BINARY_PREFIX_CYCLES + "3", str(size)))
            cycles3_no_vec.append(run(BINARY_PREFIX_CYCLES + "3_no_vec", str(size)))

            op_row = compute_ops_row(header_cycles, size)

            ops3.append(op_row)
            ops3_no_vec.append(op_row)

            end = time.time() - start

            pairs = [
                ("_3.csv", cycles3, ops3),
                ("_3_no_vec.csv", cycles3_no_vec, ops3_no_vec)
            ]

            for suffix, cycle_data, op_data in pairs:
                with open(os.path.join(OUTPUT_DIR, PREFIX_CYCLES + suffix), "w") as f:
                    f.write("\n".join(cycle_data) + "\n")
                with open(os.path.join(OUTPUT_DIR, PREFIX_OPS + suffix), "a") as f:
                    f.write("\n".join(op_data) + "\n")      
            print("Time took:", end)

        except subprocess.CalledProcessError:
            print("  skipped (binary returned error)", file=sys.stderr)

    print("Success")

if __name__ == "__main__":
    main()