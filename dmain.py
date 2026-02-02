from data_loader import load_honeypot_data, prepare_lstm_data
from eda import plot_eda, plot_port_distribution
from lstm_model import build_lstm_model, train_lstm, predict_and_plot

# Load Data
df = load_honeypot_data("../honeypot/input/AWS_Honeypot_marx-geo.csv")

# EDA
plot_eda(df)
plot_port_distribution(df)

# Prepare LSTM Data
X, y, scaler = prepare_lstm_data(df, seq_length=24)

# Build & Train LSTM
model = build_lstm_model((X.shape[1], X.shape[2]))
model.summary()
train_lstm(model, X, y, epochs=50, batch_size=16)

# Predict & Plot
predict_and_plot(model, X, y, scaler)
