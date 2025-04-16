import numpy as np
import matplotlib.pyplot as plt

# Generate random data
data = []

# Calculate statistical values
mean = np.mean(data)
median = np.median(data)
minimum = np.min(data)
maximum = np.max(data)
q1, q3 = np.percentile(data, [25, 75])
iqr = q3 - q1
upper_bound = q3 + (1.5 * iqr)
lower_bound = q1 - (1.5 * iqr)
outliers = [x for x in data if x < lower_bound or x > upper_bound]

plt.boxplot(data)
plt.axhline(upper_bound, color='r', linestyle='--')
plt.axhline(maximum, color='r', linestyle='--')
plt.axhline(minimum, color='r', linestyle='--')
plt.axhline(median, color='r', linestyle='--')
plt.text(0.5, upper_bound, f'upper_bound: {upper_bound:.2f}')
plt.text(0.5, maximum, f'maximum: {maximum:.2f}')
plt.text(0.5, minimum, f'minimum: {minimum:.2f}')
plt.text(1, median, f'Median: {median:.2f}')
'''
bin_size=30

hist, bins = np.histogram(data,bins=int((maximum - minimum) / bin_size))
for i in range(len(hist)):
    print(f"Bin {i+1}: {bins[i]:.2f} - {bins[i+1]:.2f} -> Count: {hist[i]}")

plt.hist(data,bins=int((maximum - minimum) / bin_size))
plt.axvline(median, color='red', linestyle='dashed', linewidth=2)
plt.axvline(mean, color='green', linestyle='dashed', linewidth=2)
'''
# Add labels and title
plt.xlabel('')
plt.ylabel('')
plt.title('')

# Show plot
plt.show()
