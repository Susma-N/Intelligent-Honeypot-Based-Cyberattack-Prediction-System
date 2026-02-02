import pandas as pd
from sklearn.preprocessing import MinMaxScaler

def load_honeypot_data(filepath):
    df = pd.read_csv(filepath)
    if "Unnamed: 15" in df.columns:
        df.drop("Unnamed: 15", axis=1, inplace=True)

    df["datetime"] = pd.to_datetime(df["datetime"])
    df["day"] = df["datetime"].dt.day_name()
    df["month"] = df["datetime"].dt.month_name()
    df["year"] = df["datetime"].dt.year
    df["hour"] = df["datetime"].dt.hour
    df["minute"] = df["datetime"].dt.minute
    return df

def prepare_lstm_data(df, seq_length=24):
    df_hourly = df.groupby(pd.Grouper(key="datetime", freq="H")).size().reset_index(name="attacks")
    df_hourly = df_hourly.sort_values("datetime")

    scaler = MinMaxScaler()
    scaled_attacks = scaler.fit_transform(df_hourly["attacks"].values.reshape(-1,1))

    X, y = [], []
    for i in range(seq_length, len(scaled_attacks)):
        X.append(scaled_attacks[i-seq_length:i, 0])
        y.append(scaled_attacks[i, 0])
    X = pd.np.array(X).reshape(len(X), seq_length, 1)  # pd.np used for backward compatibility
    y = pd.np.array(y)
    return X, y, scaler
