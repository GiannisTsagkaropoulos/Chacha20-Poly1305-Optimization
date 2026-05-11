import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as ticker

plt.rcParams.update({
    "font.size": 25,          # base font size
    "axes.titlesize": 30,     # title
    "axes.labelsize": 30,     # x and y labels
    "legend.fontsize": 20,
    "xtick.labelsize": 25,
    "ytick.labelsize": 25
})

# Data range
x_range = np.logspace(-5, 7, num=100, base=2)
y_peak = np.full_like(x_range, 4)  
y_bandwidth = 32 * x_range         

plt.figure(figsize=(10, 7))

# Plot Roofline
plt.plot(x_range, y_peak, color='black', linewidth=2)
plt.plot(x_range[x_range <= 0.5], y_bandwidth[x_range <= 0.5], color='black', linewidth=2)

# --- RED POINTS (Perfectly Collinear at x=0.25) ---
'''y_values = [3.97, 3.53, 2.76, 2.72, 2.08, 1.76, 1.64, 1.53, 1.47]
# All points share the exact same X value
plt.scatter([0.25]*len(y_values), y_values, color='red', s=70, zorder=5, 
            label='DGEMV Points', edgecolors='white', alpha=0.8)
'''

x_0 = []
y_0 = []

with open("../data_files/chacha20_encryption_cycles.txt") as f:
    for line in f:
        line = line.strip()
        a, b = map(float, line.split(", "))
        operations = a//64 * (384 + 336 + 320 + 1)
        x_0.append(a)
        y_0.append(operations/b)

plt.scatter([(384 + 336 + 321)//64]*len(y_0), y_0, color='red', s=70, zorder=5, 
            label='Chacha Points', edgecolors='white', alpha=0.8)



plt.xscale('log', base=2)
plt.yscale('log', base=2)

# --- 1. THE ZOOM ---
plt.xlim(2**-4, 2**4) 
plt.ylim(2**0, 2**2)   

# --- 2. FORCE TICKS AT EVERY POWER OF 2 ---
powers_of_2_x = [2**i for i in range(-4, 2)]
powers_of_2_y = [2**i for i in range(-1, 4)]
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

plt.xlabel('Operational intensity [flops/byte]')
plt.ylabel('Performance [flops/cycle]')
plt.legend()
plt.show()