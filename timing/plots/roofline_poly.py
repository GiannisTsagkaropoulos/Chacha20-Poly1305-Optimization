import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as ticker
import os
import math

# ---------------- SETUP ----------------
# register data files and operational intensities following this structure: data = {file: (is_poly1305, operations_per_block, label)}
"""
data = {"../data_files/poly1305_tag_cycles.txt": (True, 193, "Poly1305 baseline"),
        "../data_files/inline_poly.txt": (True, 193, "Poly1305 inlined")}
"""
data = {"../../poly1305_optimization/data_files/poly1305_baseline.txt": (True, 193, "baseline"),
        "../../poly1305_optimization/data_files/inlined_Horner.txt": (True, 70, "inlined Horner"),
        "../../poly1305_optimization/data_files/vect_inlined_carry_Horner.txt": (True, 40, "vect carry delay"),
        "../../poly1305_optimization/data_files/carry_delay.txt": (True, 50, "carry delay"),
        "../../poly1305_optimization/data_files/inlined_carry_Horner.txt": (True, 50, "inlined carry delay"),
        "../../poly1305_optimization/data_files/Horner.txt": (True, 70, "Horner")}

# set machine specific parameters
peak_performance = 4  # in flops/cycle
memory_bandwidth = 32  # in bytes/cycle

plot_title = "Roofline Model for Poly1305 Implementations"
output_filename = "roofline_poly1305.png"
# ---------------------------------------

script_dir = os.path.dirname(os.path.abspath(__file__))

output_dir = os.path.join(script_dir, "../figures")
os.makedirs(output_dir, exist_ok=True)

plt.rcParams.update({
    "font.size": 25,          # base font size
    "axes.titlesize": 30,     # title
    "axes.labelsize": 30,     # x and y labels
    "legend.fontsize": 20,
    "xtick.labelsize": 25,
    "ytick.labelsize": 25
})

# Data range
x_range = np.logspace(-20, 7, num=1000, base=2)
y_peak = np.full_like(x_range, peak_performance)  
y_bandwidth = memory_bandwidth * x_range      

def roofline(x):
    return np.minimum(peak_performance, memory_bandwidth * x)

plt.figure(figsize=(10, 7))

# Plot Roofline
ridge_point = peak_performance / memory_bandwidth
plt.plot(x_range, roofline(x_range), color='black', linewidth=2)

# --- RED POINTS (Perfectly Collinear at x=0.25) ---
'''y_values = [3.97, 3.53, 2.76, 2.72, 2.08, 1.76, 1.64, 1.53, 1.47]
# All points share the exact same X value
plt.scatter([0.25]*len(y_values), y_values, color='red', s=70, zorder=5, 
            label='DGEMV Points', edgecolors='white', alpha=0.8)
'''
all_x = []
all_y = []

for file, (is_poly1305, operations_per_block, label) in data.items():
    x = []
    y = []
    with open(os.path.join(script_dir, file)) as f:
        for line in f:
            line = line.strip()
            a, b = map(float, line.split(", "))
            block_size = 16 if is_poly1305 else 26
            total_cycles = b
            total_operations = (a // block_size) * operations_per_block
            y.append(total_operations / b)
            x.append(operations_per_block/block_size)
    
    plt.scatter(x, y, s=70, zorder=5, 
                label=label, edgecolors='white', alpha=0.8)
    all_x.extend(x)
    all_y.extend(y)

plt.xscale('log', base=2)
plt.yscale('log', base=2)

# --- 1. THE ZOOM ---
min_x = ridge_point / 4
max_x = max(all_x) * 2
min_y = min(all_y) / 2
max_y = max(all_y) * 2

plt.xlim(min_x, max_x)
plt.ylim(min_y, max_y)

# --- 2. FORCE TICKS AT EVERY POWER OF 2 ---
min_power_x = math.floor(math.log2(min_x))
max_power_x = math.ceil(math.log2(max_x))
min_power_y = math.floor(math.log2(min_y))
max_power_y = math.ceil(math.log2(max_y))

powers_of_2_x = [2**i for i in range(min_power_x, max_power_x + 1)]
powers_of_2_y = [2**i for i in range(min_power_y, max_power_y + 1)]
plt.gca().xaxis.set_major_locator(ticker.FixedLocator(powers_of_2_x))
plt.gca().yaxis.set_major_locator(ticker.FixedLocator(powers_of_2_y))

# --- 3. CUSTOM FORMATTER ---
def format_func(value, tick_number):
    return f'$2^{{{int(round(np.log2(value)))}}}$'

plt.gca().xaxis.set_major_formatter(ticker.FuncFormatter(format_func))
plt.gca().yaxis.set_major_formatter(ticker.FuncFormatter(format_func))

# --- 4. THE GRID ---
plt.gca().yaxis.set_minor_locator(ticker.LogLocator(base=2, subs=np.arange(1.1, 2, 0.1)))
plt.gca().xaxis.set_minor_locator(ticker.LogLocator(base=2, subs=np.arange(1.1, 2, 0.2)))

plt.gca().yaxis.set_minor_formatter(ticker.NullFormatter())
plt.gca().xaxis.set_minor_formatter(ticker.NullFormatter())

plt.grid(True, which="major", ls="-", color='gray', alpha=0.5)
plt.grid(True, which="minor", ls=":", color='lightgray', alpha=0.5)

plt.title(plot_title)
plt.xlabel('Operational intensity [flops/byte]')
plt.ylabel('Performance [flops/cycle]')
plt.legend(
    loc='upper left',
    bbox_to_anchor=(1.02, 1),
    borderaxespad=0
)

output_file = os.path.join(output_dir, output_filename)
plt.savefig(output_file, bbox_inches='tight')
plt.show()