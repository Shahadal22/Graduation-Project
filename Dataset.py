import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler

# Load the data
df = pd.read_csv('UNSW_2018_IoT_Botnet_Full5pc_1.csv')

# Display basic information about the dataset
df.info()

# Check for missing values
print(df.isnull().sum())

# Print unique category names for each column
for column in df.columns:
    unique_categories = df[column].unique()
    print(f"Unique categories in column '{column}':")
    print(unique_categories)
    print()

# Convert timestamp columns to datetime
# Ensure 'stime' and 'ltime' columns exist in the dataset
if 'stime' in df.columns and 'ltime' in df.columns:
    df['stime'] = pd.to_datetime(df['stime'], unit='s')
    df['ltime'] = pd.to_datetime(df['ltime'], unit='s')
else:
    print("Columns 'stime' and 'ltime' are missing.")

# Convert duration to seconds if 'dur' column exists
if 'dur' in df.columns:
    df['dur'] = pd.to_timedelta(df['dur']).dt.total_seconds()
else:
    print("Column 'dur' is missing.")

# Normalize numerical columns if they exist in the dataset
scaler = MinMaxScaler()
numeric_columns = ['pkts', 'bytes', 'dur', 'mean', 'stddev', 'sum', 'min', 'max', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate', 'srate', 'drate']
numeric_columns = [col for col in numeric_columns if col in df.columns]  # Check if columns exist
df[numeric_columns] = scaler.fit_transform(df[numeric_columns])

# Convert categorical columns to numerical if they exist
categorical_columns = ['flgs', 'proto', 'state']
for col in categorical_columns:
    if col in df.columns:
        df[col] = pd.Categorical(df[col]).codes
    else:
        print(f"Column '{col}' is missing.")

# Device Behavior Simulation
# Ensure 'stime' and 'bytes' columns exist before simulation
if 'stime' in df.columns and 'bytes' in df.columns and 'rate' in df.columns:
    # Simulating login times
    df['login_times'] = (df['stime'].dt.hour + df['stime'].dt.minute / 60) / 24
    # Simulating power consumption
    df['power_consumption'] = df['bytes'] * df['rate']
else:
    print("Columns required for 'login_times' and 'power_consumption' are missing.")

# Network Context Simulation
# Ensure 'saddr' and 'attack' columns exist for network reputation
if 'saddr' in df.columns and 'attack' in df.columns:
    df['network_reputation'] = df.groupby('saddr')['attack'].transform('mean')
else:
    print("Columns 'saddr' and/or 'attack' are missing.")

# Simulate traffic patterns based on 'bytes', 'rate', and 'dur' columns
if 'bytes' in df.columns and 'rate' in df.columns and 'dur' in df.columns:
    df['traffic_patterns'] = df['bytes'] * df['rate'] * df['dur']
else:
    print("Columns required for 'traffic_patterns' are missing.")

# Session Characteristics
# Define port sensitivity levels and apply function
port_sensitivity = {
    'system': 0.8,      # 0-1023
    'user': 0.6,        # 1024-49151
    'dynamic': 0.4,     # 49152-65535
    'unknown': 0.1
}

def get_port_sensitivity(port):
    try:
        port = int(port)
    except (ValueError, TypeError):
        return port_sensitivity['unknown']
    
    if 0 <= port <= 1023:
        return port_sensitivity['system']
    elif 1024 <= port <= 49151:
        return port_sensitivity['user']
    elif 49152 <= port <= 65535:
        return port_sensitivity['dynamic']
    return port_sensitivity['unknown']

# Calculate requested service security if 'dport' exists
if 'dport' in df.columns:
    df['requested_service_security'] = df['dport'].apply(get_port_sensitivity)
else:
    print("Column 'dport' is missing.")

# Simulate session duration based on 'ltime' and 'stime' columns
if 'ltime' in df.columns and 'stime' in df.columns:
    df['session_duration'] = df['dur'] 
else:
    print("Columns 'ltime' and 'stime' are missing.")

df.head()
# Integrity Level
# Simulate hardware security as a random uniform value between 0 and 1
df['hardware_security'] = np.random.uniform(0, 1, len(df))

# Simulate data security as a random uniform value between 0 and 1
df['data_security'] = np.random.uniform(0, 1, len(df))

# Save the final dataset to a new CSV file
df.to_csv('dataset1.csv', index=False)

# Display the first few rows and column names of the final dataset
print(df.head())
print(df.columns)


