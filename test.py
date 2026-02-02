import pandas as pd
import numpy as np

# ------------------------
# Generate synthetic test data
# ------------------------
num_hours = 72  # 3 days of hourly data
date_rng = pd.date_range(start='2025-09-01', periods=num_hours, freq='H')

np.random.seed(42)

df_test = pd.DataFrame({
    'datetime': date_rng,
    'spt': np.random.randint(1024, 65535, size=num_hours),
    'dpt': np.random.randint(1, 1024, size=num_hours),
    'proto': np.random.choice(['TCP', 'UDP', 'ICMP'], size=num_hours),
    'host': np.random.choice(['host1', 'host2', 'host3'], size=num_hours),
    'country': np.random.choice(['US', 'IN', 'CN', 'RU', 'DE'], size=num_hours),
    'srcstr': ['192.168.{}.{}'.format(np.random.randint(0,255), np.random.randint(0,255)) for _ in range(num_hours)]
})

# Save CSV
df_test.to_csv('honeypot_test.csv', index=False)
print("Test CSV 'honeypot_test.csv' created with", num_hours, "rows")
