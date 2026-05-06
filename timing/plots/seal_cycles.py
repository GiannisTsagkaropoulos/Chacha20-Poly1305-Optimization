import matplotlib.pyplot as plt

plt.rcParams.update({
    "font.size": 25,          # base font size
    "axes.titlesize": 30,     # title
    "axes.labelsize": 30,     # x and y labels
    "legend.fontsize": 25,
    "xtick.labelsize": 25,
    "ytick.labelsize": 25
})

x_0 = []
y_0 = []

with open("../data_files/seal_cycles.txt") as f:
    for line in f:
        line = line.strip()
        a, b = map(float, line.split(", "))
        operations = 20 + 384*(1+ a//64) + 336*(1+ a//64) + a//16 + 64//16 + 2 
        + 320*(1+ a//64) + 1 + a//64 + a//16 + 64//16 + a//16 + 64//16 #chacha_encrypt and poly_tag
        x_0.append(a)
        y_0.append(operations/b)

max_x = x_0[len(x_0)//2]
max_y = y_0[x_0.index(max_x)]

fig, ax = plt.subplots()

# 🔹 Grey backgrounds
#fig.patch.set_facecolor("lightgrey")   # whole figure
ax.set_facecolor("lightgrey")          # plotting area

ax.plot(x_0, y_0, marker='o', label="flag -o3", color="#029386")
#ax.text(max_x, max_y + 0.05, "no optimization", color="#029386")

ax.set_xlabel("plaintext bytes")
ax.xaxis.set_label_coords(0.5, -0.15)
ax.set_ylabel("arit instr/cycles", rotation=0)
ax.yaxis.set_label_coords(-0.02, 1.02)
ax.set_title("Chacha20_Poly1305")

# 🔹 Only horizontal grid lines
ax.grid(axis='y', color='white', linewidth=1)  # horizontal lines only

plt.show()