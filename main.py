#!/usr/bin/env python
# coding: utf-8

import os
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, Dropout

# ------------------------
# Load Dataset
# ------------------------
for dirname, _, filenames in os.walk('/kaggle/input'):
    for filename in filenames:
        print(os.path.join(dirname, filename))

df = pd.read_csv("../honeypot/input/AWS_Honeypot_marx-geo.csv")
df.drop("Unnamed: 15", axis=1, inplace=True)

# ------------------------
# Extract Date/Time Features
# ------------------------
df["datetime"] = pd.to_datetime(df["datetime"])
df["day"] = df["datetime"].dt.day_name()
df["month"] = df["datetime"].dt.month_name()
df["year"] = df["datetime"].dt.year
df["hour"] = df["datetime"].dt.hour
df["minute"] = df["datetime"].dt.minute

# ------------------------
# Basic EDA
# ------------------------
def plot_basic_eda(df):
    df["proto"].value_counts().plot(kind="bar", title="Protocols Used")
    plt.show()
    df["proto"].value_counts().plot(kind="pie", autopct="%.2f%%", title="Protocols Used")
    plt.show()
    
    df["month"].value_counts().plot(kind="bar", title="Cyberattacks per Month")
    plt.show()
    df["day"].value_counts().plot(kind="bar", title="Cyberattacks per Day")
    plt.show()
    df["hour"].value_counts().plot(kind="bar", title="Cyberattacks per Hour")
    plt.show()
    
    df["host"].value_counts().plot(kind="bar", title="Cyberattacks per Host")
    plt.show()
    df["country"].value_counts().head(10).plot(kind="bar", title="Top 10 Countries")
    plt.show()
    df["srcstr"].value_counts().head(10).plot(kind="bar", title="Top 10 Attack Sources")
    plt.show()

# ------------------------
# Port Analysis
# ------------------------
def plot_port_distribution(df, cols=["spt","dpt"]):
    for col in cols:
        mean_val = df[col].mean()
        median_val = df[col].median()
        mode_val = df[col].mode()[0]

        plt.figure(figsize=(8,4))
        sns.histplot(df[col], kde=True)
        plt.axvline(mean_val, color="b", linestyle="--")
        plt.axvline(median_val, color="g", linestyle="--")
        plt.axvline(mode_val, color="r", linestyle="--")
        plt.legend(["kde", "mean", "median", "mode"])
        plt.title(f"{col.upper()} Distribution")
        plt.show()

# ------------------------
# Additional Honeypot EDA
# ------------------------
def plot_honeypot_eda(df):
    hourly_trend = df.groupby('hour').size()
    plt.figure(figsize=(10,4))
    hourly_trend.plot(kind='line', marker='o', color='red')
    plt.title("Attack Trend per Hour of Day")
    plt.xlabel("Hour of Day")
    plt.ylabel("Number of Attacks")
    plt.grid(True)
    plt.show()

    top_spt = df['spt'].value_counts().head(10)
    plt.figure(figsize=(10,5))
    sns.barplot(x=top_spt.index, y=top_spt.values, palette="viridis")
    plt.title("Top 10 Source Ports Used in Attacks")
    plt.xlabel("Source Port")
    plt.ylabel("Attack Count")
    plt.show()

    top_dpt = df['dpt'].value_counts().head(10)
    plt.figure(figsize=(10,5))
    sns.barplot(x=top_dpt.index, y=top_dpt.values, palette="magma")
    plt.title("Top 10 Destination Ports Attacked")
    plt.xlabel("Destination Port")
    plt.ylabel("Attack Count")
    plt.show()

    country_proto = pd.crosstab(df['country'], df['proto'])
    plt.figure(figsize=(12,6))
    sns.heatmap(country_proto, cmap="YlGnBu", linewidths=0.5)
    plt.title("Country vs Protocol Heatmap")
    plt.show()

# ------------------------
# Prepare LSTM Dataset
# ------------------------
def prepare_lstm_data(df, seq_length=24):
    df_hourly = df.groupby(pd.Grouper(key="datetime", freq="H")).size().reset_index(name="attacks")
    df_hourly = df_hourly.sort_values("datetime")
    
    scaler = MinMaxScaler()
    scaled_attacks = scaler.fit_transform(df_hourly["attacks"].values.reshape(-1,1))
    
    X, y = [], []
    for i in range(seq_length, len(scaled_attacks)):
        X.append(scaled_attacks[i-seq_length:i, 0])
        y.append(scaled_attacks[i, 0])
    
    X, y = np.array(X), np.array(y)
    X = X.reshape((X.shape[0], X.shape[1], 1))
    return X, y, scaler

# ------------------------
# Build LSTM Model
# ------------------------
def build_lstm(input_shape):
    model = Sequential()
    model.add(LSTM(50, activation='relu', input_shape=input_shape))
    model.add(Dropout(0.2))
    model.add(Dense(1))
    model.compile(optimizer='adam', loss='mse')
    return model

# ------------------------
# Plot Predictions
# ------------------------
def plot_predictions(actual, predicted):
    plt.figure(figsize=(12,6))
    plt.plot(actual, label="Actual Attacks")
    plt.plot(predicted, label="Predicted Attacks")
    plt.title("Actual vs Predicted Cyberattacks per Hour")
    plt.xlabel("Hour Index")
    plt.ylabel("Number of Attacks")
    plt.legend()
    plt.show()

# ------------------------
# Run all steps
# ------------------------
plot_basic_eda(df)
plot_port_distribution(df)
plot_honeypot_eda(df)

X, y, scaler = prepare_lstm_data(df, seq_length=24)
model = build_lstm((X.shape[1], X.shape[2]))
model.summary()

history = model.fit(X, y, epochs=50, batch_size=16, validation_split=0.2)

# ------------------------
# Save the LSTM model
# ------------------------
model.save("honeypot_lstm_model.h5")
print("Model saved as 'honeypot_lstm_model.h5'")

# ------------------------
# Load the model (example)
# ------------------------
# loaded_model = load_model("honeypot_lstm_model.h5")
# predicted = loaded_model.predict(X)

predicted = model.predict(X)
predicted = scaler.inverse_transform(predicted)
actual = scaler.inverse_transform(y.reshape(-1,1))

plot_predictions(actual, predicted)
