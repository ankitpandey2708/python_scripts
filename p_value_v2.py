import numpy as np
from scipy.stats import ttest_ind

week1 = np.array([1000, 1200, 1300, 1100, 900, 1500, 1200])
week2 = np.array([1500, 1700, 1800, 1600, 1400, 1900, 1700])

# Explore the dataset

print('Mean:')
print(week1.mean())
print(week2.mean())
print('Standard Deviation:')
print(week1.std())
print(week2.std())


std_error = np.sqrt((week1.std() ** 2) / len(week1) + (week2.std() ** 2) / len(week2))
conf_int = (week1.mean() - week2.mean()) + np.array([-1, 1]) * 1.96 * std_error
print("Standard Error: {:.2f}".format(std_error))
print("Confidence Interval: [{:.2f}, {:.2f}]".format(conf_int[0], conf_int[1]))
# confidence interval doesn't include zero, which means that the difference in means is statistically significant. We can conclude that the number of visitors increased significantly from week

# Perform a t-test
t_statistic, p_value = ttest_ind(week1, week2)
print("stat: ",t_statistic)
print("p_value: ",p_value)

# Interpret the results
alpha = 0.05
if p_value > alpha:
    print('No significant difference in website traffic between weeks.')
else:
    print('Significant difference in website traffic between weeks.')
