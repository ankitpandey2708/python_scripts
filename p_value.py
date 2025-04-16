import numpy as np
from scipy.stats import ttest_ind
import pandas as pd
import statsmodels.stats.api as sms
'''
# Conversion data for old landing page
control = [0, 1, 1, 1, 0, 0, 0, 1, 1, 0,0, 1, 1, 0, 0]
# Conversion data for new landing page
experimental = [1, 1, 1, 1, 1, 1, 0, 1, 1, 0,0, 1, 1, 1, 0,1,1,1,1]

'''
#https://github.com/renatofillinich/ab_test_guide_in_python/blob/master/AB%20testing%20with%20Python.ipynb
effect_size = sms.proportion_effectsize(0.13, 0.15)    # Calculating effect size based on our expected rates ie change from 13% to expected 15%
required_n = sms.NormalIndPower().solve_power(effect_size,power=0.8, alpha=0.05,ratio=1) # Calculating sample size needed for each group
print(int(required_n))
df = pd.read_csv('ab_data.csv')
session_counts = df['user_id'].value_counts(ascending=False)
multi_users = session_counts[session_counts > 1].count()
users_to_drop = session_counts[session_counts > 1].index
df = df[~df['user_id'].isin(users_to_drop)]
control = df[df['group'] == 'control'].sample(n=4720, random_state=22)
#control=df['converted']
experimental = df[df['group'] == 'treatment'].sample(n=4720, random_state=22)
#experimental=df['converted']
ab_test = pd.concat([control, experimental], axis=0)
ab_test.reset_index(drop=True, inplace=True)


control = ab_test[ab_test['group'] == 'control']['converted']
experimental = ab_test[ab_test['group'] == 'treatment']['converted']


t, p = ttest_ind(control, experimental, equal_var=False) #2 tailed test since we dont know which variant will perform better


old_page_mean = np.mean(control)
new_page_mean = np.mean(experimental)
old_page_var = np.var(control)
new_page_var = np.var(experimental)


# print the p-value
print("P-value:", p)

# determine which variant works best
if p < 0.05:
    # calculate the standard error and the confidence interval
    se = (new_page_var/len(experimental) + old_page_var/len(control))**0.5
    diff = new_page_mean - old_page_mean
    ci = (diff - 1.96*se, diff + 1.96*se)
    
    if ci[0] > 0:
        print("The experimental group works best with a confidence interval of", ci)
    elif ci[1] < 0:
        print("The control group works best with a confidence interval of", ci)
    else:
        print("There is not enough evidence to determine which group works best with a confidence interval of", ci)
else:
    print("There is not enough evidence to determine which group works best.")


'''
if p < 0.05:
    if new_page_mean > old_page_mean:
        print("The new landing page is statistically better than the old landing page.")
    else:
        print("The new landing page is not statistically better than the old landing page.")
else:
    print("There is not enough evidence to conclude that the new landing page is better than the old landing page.")

'''
