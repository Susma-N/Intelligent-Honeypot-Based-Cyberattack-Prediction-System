from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

def build_lstm_model(input_shape):
    model = Sequential()
    model.add(LSTM(50, activation='relu', input_shape=input_shape))
    model.add(Dropout(0.2))
    model.add(Dense(1))
    model.compile(optimizer='adam', loss='mse')
    return model

def train_lstm(model, X, y, epochs=50, batch_size=16):
    history = model.fit(X, y, epochs=epochs, batch_size=batch_size, validation_split=0.2)
    return history

def predict_and_plot(model, X, y, scaler):
    predicted = model.predict(X)
    predicted = scaler.inverse_transform(predicted)
    actual = scaler.inverse_transform(y.reshape(-1,1))

    import matplotlib.pyplot as plt
    plt.figure(figsize=(12,6))
    plt.plot(actual, label="Actual Attacks")
    plt.plot(predicted, label="Predicted Attacks")
    plt.title("Actual vs Predicted Cyberattacks per Hour")
    plt.xlabel("Hour Index")
    plt.ylabel("Number of Attacks")
    plt.legend()
    plt.show()
