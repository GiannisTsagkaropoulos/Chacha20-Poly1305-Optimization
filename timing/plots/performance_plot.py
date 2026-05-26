import matplotlib.pyplot as plt
import numpy as np
import os
import seaborn as sns
sns.set_theme(style="whitegrid")
print(153446890./111142828.)
# ---------------- SETUP ----------------
# register data files and operational intensities following this structure: data = {file: (int declaring chacha, poly1305 or pol2133, operations_per_block, label)}
# in declaring algorithm: chacha = 0, poly1305 = 1, poly2133 = 2
"""
data = {"../../poly1305_optimization/data_files/inlined_parallel_Horner.txt": (2, 400, "Inlined Parallel Horner"),
        "../../poly1305_optimization/data_files/inlined_carry_delay.txt": (2, 400, "Inlined carry delay"),
        "../../poly1305_optimization/data_files/parallel_Horner.txt": (2, 400, "Parallel Horner"),
        "../../poly1305_optimization/data_files/carry_delay.txt": (2, 400, "Carry Delay Parallel Horner"),
        "../../poly1305_optimization/data_files/inlined_scalr_rep_parallel_Horner.txt": (2, 400, "Paralle Horner with scalar rep"),
        "../../poly1305_optimization/data_files/poly1305.txt": (2, 400, "Initial Poly1305")}


data = {"../data_files/poly2133_baseline.txt": (2, 561, "baseline"),
        "../data_files/poly2133_inlined.txt": (2, 561, "inlined"),
        "../data_files/poly2133_inlined_unrolled.txt": (2, 419, "inlined & unrolled"),
        "../data_files/poly2133_2-level_inline_unroll.txt": (2, 537, "2-level"),
        "../data_files/poly2133_2-level_delcarry.txt": (2, 342, "Delayed carry"),
        "../data_files/poly2133_2-level_precomp.txt": (2, 306, "Pre-computation"),
        "../data_files/poly2133_remif.txt": (2, 269, "Remove if/else"),
        "../data_files/poly2133_delcarry_O3.txt": (2, 342, "Delayed carry -O3"),}
"""

data = {"../data_files/poly2133_vec.txt": (2, 269, "vectorized"),
        "../data_files/poly2133_vec_less_regs.txt": (2, 269, "vectorized less regs"),
        "../data_files/poly2133_vec_scalrep.txt": (2, 269, "vectorized scalrep"),
        "../data_files/poly2133_delcarry.txt": (2, 342, "Delayed carry -O3")}
# set the algorithm name for plot titles and output filenames
Algorithm = "Poly2133"
# ---------------------------------------

runtime_plot_title = f"Runtimes of {Algorithm} Implementations"
runtime_output_filename = f"Runtime_{Algorithm}.png"
performance_plot_title = f"Performance of {Algorithm} Implementations"
performance_output_filename = f"Performance_{Algorithm}.png"

script_dir = os.path.dirname(os.path.abspath(__file__))

output_dir = os.path.join(script_dir, "../figures")
os.makedirs(output_dir, exist_ok=True)


plt.rcParams.update({
    "font.size": 15,          # base font size
    "axes.titlesize": 30,     # title
    "axes.labelsize": 20,     # x and y labels
    "legend.fontsize": 15,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10
})
  

plt.figure(figsize=(10, 7))

for file, (_, _, label) in data.items():
    x = []
    y = []
    with open(os.path.join(script_dir, file)) as f:
        for line in f:
            line = line.strip()
            a, b = map(float, line.split(", "))
            x.append(a)  # message size
            y.append(b)  # cycles
    
    plt.plot(x, y, label=label, marker='|', markersize=8, linewidth=1.5)



plt.title(runtime_plot_title)
plt.xlabel('Message size [bytes]')
plt.ylabel('Runtime [cycles]')
plt.legend(
    loc='upper left',
    bbox_to_anchor=(0, 1),
    borderaxespad=0
)


output_file = os.path.join(output_dir, runtime_output_filename)
plt.savefig(output_file, bbox_inches='tight')
plt.show()


plt.figure(figsize=(10, 7))

for file, (algo, flops, label) in data.items():
    x = []
    y = []
    num_blocks = 1

    
    with open(os.path.join(script_dir, file)) as f:
        for line in f:
            line = line.strip()
            a, b = map(float, line.split(", "))
            operattions = 1
            if algo == 1: # Poly1305
                block_size = 16
                operations = a//block_size * flops

            elif algo == 2: # Poly2133
                block_size = 26
                operations = a//block_size * flops
            else: # chacha20 (assume they give total flops, can change if not the case)
                operations = flops
            
            x.append(a)  # message size
            y.append(operations/b)  # flops/cycles
    
    plt.plot(x, y, label=label, marker='|', markersize=8, linewidth=1.5)


plt.yscale('log', base=2)
plt.xscale('log', base=2)
plt.title(performance_plot_title)
plt.xlabel('Message size [bytes]')
plt.ylabel('Performance [flops/cycles]')
plt.legend(
    loc='upper left',
    bbox_to_anchor=(0, 1),
    borderaxespad=0
)

output_file = os.path.join(output_dir, performance_output_filename)
plt.savefig(output_file, bbox_inches='tight')
plt.show()