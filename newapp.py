# #!/usr/bin/env python
# # coding: utf-8

# import streamlit as st
# import pandas as pd
# import numpy as np
# import matplotlib.pyplot as plt
# import seaborn as sns
# import time
# from sklearn.preprocessing import MinMaxScaler
# from tensorflow.keras.models import Sequential
# from tensorflow.keras.layers import LSTM, Dense, Dropout

# st.set_page_config(page_title="Honeypot MHN Simulation Dashboard", layout="wide")
# st.title("Honeypot Node Simulation & Attack Dashboard")

# # -----------------------
# # Upload CSV or generate synthetic data
# # -----------------------
# uploaded_file = st.sidebar.file_uploader("Upload Honeypot CSV", type=["csv"])

# if uploaded_file:
#     df = pd.read_csv(uploaded_file)
#     df["datetime"] = pd.to_datetime(df["datetime"])
#     st.sidebar.success(f"Loaded {uploaded_file.name}")
# else:
#     st.sidebar.warning("No CSV uploaded, generating synthetic attack data...")
#     num_attacks = st.sidebar.slider("Number of attacks", 100, 1000, 300)
#     start_time = pd.Timestamp("2025-01-01 00:00:00")
#     df = pd.DataFrame({
#         "datetime": [start_time + pd.Timedelta(minutes=i*5) for i in range(num_attacks)],
#         "proto": np.random.choice(["TCP", "UDP", "ICMP"], size=num_attacks),
#         "srcstr": np.random.choice([f"Attacker_{i}" for i in range(1,21)], size=num_attacks),
#         "host": np.random.choice([f"Node_{i}" for i in range(1,11)], size=num_attacks),
#         "country": np.random.choice(["US", "CN", "RU", "IN", "DE"], size=num_attacks)
#     })

# # -----------------------
# # Simulation Setup
# # -----------------------
# num_nodes = st.sidebar.slider("Number of nodes", 5, 50, 10)
# time_interval = st.sidebar.slider("Step interval (s)", 0.05, 0.5, 0.1)
# nodes = {i: {"x": np.random.rand(), "y": np.random.rand(), "attacks":0} for i in range(num_nodes)}

# node_plot = st.empty()
# metrics = st.sidebar.empty()
# sim_progress = st.sidebar.progress(0)

# total_steps = len(df)
# st.subheader(f"Estimated Simulation Run Time: {total_steps*time_interval:.1f}s")

# # -----------------------
# # Simulation Loop (Real-time like MHN)
# # -----------------------
# start_sim = time.time()
# for step, row in df.iterrows():
#     # Random walk movement
#     for i in nodes:
#         nodes[i]["x"] += (np.random.rand()-0.5)*0.05
#         nodes[i]["y"] += (np.random.rand()-0.5)*0.05
#         nodes[i]["x"] = np.clip(nodes[i]["x"], 0, 1)
#         nodes[i]["y"] = np.clip(nodes[i]["y"], 0, 1)
    
#     # Map attack to nodes based on CSV or synthetic source
#     src = np.random.choice(num_nodes)
#     tgt = np.random.choice([i for i in range(num_nodes) if i != src])
#     nodes[src]["attacks"] += 1
#     attacks = [(src, tgt)]
    
#     # -----------------------
#     # Node Plot
#     # -----------------------
#     fig, ax = plt.subplots(figsize=(6,6))
#     xs = [nodes[i]["x"] for i in nodes]
#     ys = [nodes[i]["y"] for i in nodes]
#     sizes = [20 + nodes[i]["attacks"]*5 for i in nodes]
#     colors = ["red" if nodes[i]["attacks"]>5 else "blue" for i in nodes]
    
#     ax.scatter(xs, ys, s=sizes, c=colors)
#     for i in nodes:
#         ax.text(nodes[i]["x"], nodes[i]["y"], str(i))
    
#     for s,t in attacks:
#         ax.annotate("", xy=(nodes[t]["x"], nodes[t]["y"]),
#                     xytext=(nodes[s]["x"], nodes[s]["y"]),
#                     arrowprops=dict(facecolor="orange", shrink=0.05))
    
#     ax.set_xlim(0,1)
#     ax.set_ylim(0,1)
#     ax.set_title(f"Step {step+1}/{total_steps}")
#     node_plot.pyplot(fig)
    
#     # -----------------------
#     # Update Metrics
#     # -----------------------
#     elapsed = time.time() - start_sim
#     est_total = elapsed / (step+1) * total_steps
#     remaining = est_total - elapsed
#     top_nodes = sorted(nodes.items(), key=lambda x: x[1]['attacks'], reverse=True)[:3]
    
#     metrics.markdown(f"""
#     **Step:** {step+1}/{total_steps}  
#     **Elapsed Time:** {elapsed:.1f}s  
#     **Estimated Remaining:** {remaining:.1f}s  
#     **Total Attacks:** {sum([nodes[i]['attacks'] for i in nodes])}  
#     **Top 3 Attack Nodes:** {[i[0] for i in top_nodes]}  
#     """)
    
#     sim_progress.progress((step+1)/total_steps)
#     time.sleep(time_interval)

# st.success("Simulation finished!")

# # -----------------------
# # Post-Simulation EDA
# # -----------------------
# st.subheader("Post-Simulation Attack Analysis")
# cols = st.columns(2)
# with cols[0]:
#     st.write("Protocol Distribution")
#     st.bar_chart(df["proto"].value_counts())
# with cols[1]:
#     st.write("Top Attack Sources")
#     st.bar_chart(df["srcstr"].value_counts().head(10))

# cols2 = st.columns(2)
# with cols2[0]:
#     st.write("Top Target Hosts")
#     st.bar_chart(df["host"].value_counts().head(10))
# with cols2[1]:
#     st.write("Country Distribution")
#     st.bar_chart(df["country"].value_counts().head(10))

# # -----------------------
# # LSTM Hourly Attack Prediction
# # -----------------------
# st.subheader("LSTM: Predict Hourly Attacks")
# df_hourly = df.groupby(pd.Grouper(key="datetime", freq="H")).size().reset_index(name="attacks")
# df_hourly = df_hourly.sort_values("datetime")

# scaler = MinMaxScaler()
# scaled_attacks = scaler.fit_transform(df_hourly["attacks"].values.reshape(-1,1))

# def create_sequences(data, seq_length=24):
#     X, y = [], []
#     for i in range(seq_length, len(data)):
#         X.append(data[i-seq_length:i,0])
#         y.append(data[i,0])
#     return np.array(X), np.array(y)

# seq_length = 24
# X_lstm, y_lstm = create_sequences(scaled_attacks, seq_length)
# X_lstm = X_lstm.reshape((X_lstm.shape[0], X_lstm.shape[1], 1))

# lstm_model = Sequential()
# lstm_model.add(LSTM(50, activation='relu', input_shape=(X_lstm.shape[1],1)))
# lstm_model.add(Dropout(0.2))
# lstm_model.add(Dense(1))
# lstm_model.compile(optimizer='adam', loss='mse')

# lstm_model.fit(X_lstm, y_lstm, epochs=30, batch_size=16, validation_split=0.2, verbose=0)

# predicted = lstm_model.predict(X_lstm)
# predicted = scaler.inverse_transform(predicted)
# actual = scaler.inverse_transform(y_lstm.reshape(-1,1))

# plt.figure(figsize=(12,6))
# plt.plot(actual, label="Actual Attacks")
# plt.plot(predicted, label="Predicted Attacks")
# plt.title("LSTM: Actual vs Predicted Attacks")
# plt.xlabel("Hour Index")
# plt.ylabel("Number of Attacks")
# plt.legend()
# st.pyplot(plt)

#!/usr/bin/env python
# AI-Powered Honeypot Defense System (Optimized for Streamlit + Plotly)
#!/usr/bin/env python
# coding: utf-8

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import IsolationForest
from sklearn.cluster import MiniBatchKMeans
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Bidirectional
from datetime import datetime, timedelta
import time
import gc
import warnings
import json
warnings.filterwarnings('ignore')

# Import prevention solutions (same directory)
try:
    from prevention_solutions import (
        IntelligentFirewallRuleGenerator,
        AdaptiveRateLimiter,
        IncidentResponseAutomation,
        NetworkSegmentationAdvisor,
        ThreatIntelligenceFeedGenerator,
        PredictiveAttackForecaster
    )
    PREVENTION_AVAILABLE = True
except ImportError as e:
    PREVENTION_AVAILABLE = False
    print(f"Warning: prevention_solutions.py not found. Error: {e}")
# ============ Streamlit Page Configuration ============
st.set_page_config(
    page_title="AI-Powered Honeypot Defense System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============ Custom Styling ============
st.markdown("""
    <style>
    .main-header {
        font-size: 36px;
        font-weight: bold;
        color: white;
        text-align: center;
        padding: 20px;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        border-radius: 10px;
    }
    .alert-box {
        padding: 15px;
        border-left: 5px solid #ff4444;
        background-color: black;
        border-radius: 5px;
        margin: 10px 0;
        color: white;
    }
    </style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-header">🛡️ AI-Powered Honeypot Simulation and Prevention for Threats</div>', unsafe_allow_html=True)


# ============ Threat Intelligence Class ============
class ThreatIntelligence:
    def __init__(self):
        self.risk_scores = {
            'TCP': 0.7, 'UDP': 0.5, 'ICMP': 0.3,
            'US': 0.3, 'CN': 0.8, 'RU': 0.9, 'IN': 0.4, 'DE': 0.3
        }

    def calculate_threat_score(self, row):
        score = 0
        score += self.risk_scores.get(row.get('proto', 'TCP'), 0.5) * 30
        score += self.risk_scores.get(row.get('country', 'US'), 0.5) * 25
        if 'dpt' in row and pd.notna(row['dpt']) and row['dpt'] < 1024:
            score += 20
        hour = row.get('hour', 12)
        if 0 <= hour < 6 or 22 <= hour < 24:
            score += 15
        score += min(row.get('attack_count', 1) * 2, 10)
        return min(score, 100)

    def get_severity_level(self, score):
        if score >= 80:
            return "CRITICAL", "🔴"
        elif score >= 60:
            return "HIGH", "🟠"
        elif score >= 40:
            return "MEDIUM", "🟡"
        else:
            return "LOW", "🟢"


# ============ Anomaly Detection ============
def detect_anomalies(df):
    st.subheader("🔍 Anomaly Detection - Identifying Unusual Attack Patterns")

    # Defensive checks
    if 'datetime' not in df.columns:
        st.error("Dataset must include a 'datetime' column for anomaly detection.")
        return df

    # Build features
    features = pd.DataFrame({
        'hour': df['datetime'].dt.hour,
        'day_of_week': df['datetime'].dt.dayofweek,
        'attacks_per_hour': df.groupby(df['datetime'].dt.hour)['datetime'].transform('count')
    })
    proto_encoded = pd.get_dummies(df['proto'].astype(str), prefix='proto')
    features = pd.concat([features, proto_encoded], axis=1).fillna(0)

    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    try:
        df['anomaly'] = iso_forest.fit_predict(features)
        df['anomaly_score'] = iso_forest.score_samples(features)
    except Exception as e:
        st.error(f"Anomaly detection failed: {e}")
        return df

    anomalies = df[df['anomaly'] == -1]
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Attacks", len(df))
    col2.metric("Anomalies Detected", len(anomalies))
    col3.metric("Normal Patterns", len(df) - len(anomalies))

    fig = px.scatter(df, x=df.index, y='anomaly_score',
                     color=df['anomaly'].astype(str),
                     title="Anomaly Detection Timeline",
                     labels={'anomaly_score': 'Anomaly Score', 'index': 'Index'})
    st.plotly_chart(fig, use_container_width=True)
    gc.collect()
    return df


# ============ Optimized Attack Clustering ============
def cluster_attack_patterns(df):
    st.subheader("🎯 Attack Pattern Clustering - Identifying Coordinated Attacks")

    if 'datetime' not in df.columns:
        st.error("Dataset must include a 'datetime' column for clustering.")
        return df

    # Sample large datasets to avoid MemoryError
    max_sample = 10000
    if len(df) > max_sample:
        st.warning(f"Large dataset ({len(df)} rows) — sampling {max_sample} rows for clustering.")
        df_sample = df.sample(max_sample, random_state=42).reset_index(drop=True)
    else:
        df_sample = df.reset_index(drop=True).copy()

    # Build clustering features
    features = pd.DataFrame({
        'hour': df_sample['datetime'].dt.hour,
        'day': df_sample['datetime'].dt.dayofweek,
        'protocol_tcp': (df_sample['proto'].astype(str) == 'TCP').astype(int),
        'protocol_udp': (df_sample['proto'].astype(str) == 'UDP').astype(int)
    }).fillna(0)

    # Safe number of clusters
    n_clusters = 3
    if len(df_sample) > 2000:
        n_clusters = min(10, max(3, len(df_sample) // 1000))

    kmeans = MiniBatchKMeans(n_clusters=n_clusters, random_state=42, batch_size=512)
    try:
        df_sample['cluster'] = kmeans.fit_predict(features)
    except Exception as e:
        st.error(f"Clustering failed: {e}")
        return df

    fig = px.scatter(df_sample, x='datetime', y='hour', color=df_sample['cluster'].astype(str),
                     title="Attack Clusters Over Time (Sampled Data)", labels={'hour': 'Hour'})
    st.plotly_chart(fig, use_container_width=True)

    cluster_stats = df_sample.groupby('cluster').agg({
        'datetime': 'count',
        'proto': lambda x: x.mode()[0] if len(x) > 0 else 'Unknown'
    }).rename(columns={'datetime': 'attack_count', 'proto': 'dominant_protocol'})
    st.dataframe(cluster_stats, use_container_width=True)
    gc.collect()
    return df


# ============ LSTM Builder ============
def build_advanced_lstm(input_shape):
    model = Sequential([
        Bidirectional(LSTM(100, return_sequences=True, activation='relu'), input_shape=input_shape),
        Dropout(0.3),
        Bidirectional(LSTM(50, activation='relu')),
        Dropout(0.2),
        Dense(25, activation='relu'),
        Dense(1)
    ])
    model.compile(optimizer='adam', loss='mse', metrics=['mae'])
    return model


# ============ Predictive Forecasting ============
def advanced_prediction(df):
    st.subheader("📊 Advanced Threat Forecasting - Next 24 Hours")
    if 'datetime' not in df.columns:
        st.warning("Need 'datetime' column for prediction.")
        return

    df_hourly = df.groupby(pd.Grouper(key="datetime", freq="H")).size().reset_index(name="attacks")
    df_hourly = df_hourly.sort_values("datetime")

    if len(df_hourly) < 48:
        st.warning("Insufficient data for prediction. Need at least 48 hours of data.")
        return

    scaler = MinMaxScaler()
    scaled_attacks = scaler.fit_transform(df_hourly["attacks"].values.reshape(-1, 1))

    seq_length = 24
    X, y = [], []
    for i in range(seq_length, len(scaled_attacks)):
        X.append(scaled_attacks[i - seq_length:i, 0])
        y.append(scaled_attacks[i, 0])
    X = np.array(X).reshape(len(X), seq_length, 1)
    y = np.array(y)

    model = build_advanced_lstm((X.shape[1], X.shape[2]))
    with st.spinner("Training LSTM model (may take a while)..."):
        model.fit(X, y, epochs=30, batch_size=16, validation_split=0.2, verbose=0)

    predicted = scaler.inverse_transform(model.predict(X, verbose=0))
    actual = scaler.inverse_transform(y.reshape(-1, 1))
    residuals = actual - predicted
    std_residuals = np.std(residuals)
    upper = predicted + 1.96 * std_residuals
    lower = predicted - 1.96 * std_residuals

    fig = go.Figure()
    fig.add_trace(go.Scatter(y=actual.flatten(), mode='lines', name='Actual'))
    fig.add_trace(go.Scatter(y=predicted.flatten(), mode='lines', name='Predicted'))
    fig.add_trace(go.Scatter(y=upper.flatten(), mode='lines', name='Upper 95%', line=dict(dash='dash')))
    fig.add_trace(go.Scatter(y=lower.flatten(), mode='lines', name='Lower 95%', fill='tonexty', line=dict(dash='dash')))
    fig.update_layout(title="Attack Prediction (95% Confidence)", xaxis_title="Time Index", yaxis_title="Number of Attacks")
    st.plotly_chart(fig, use_container_width=True)
    gc.collect()


# ============ 3D Visualization ============
def visualize_3d_network(df):
    st.subheader("🌐 3D Network Attack Visualization")
    country_coords = {
        'US': (37.1, -95.7, 50), 'CN': (35.9, 104.2, 80),
        'RU': (61.5, 105.3, 70), 'IN': (20.6, 78.9, 60), 'DE': (51.1, 10.4, 40)
    }
    attack_data = df.groupby('country').size().reset_index(name='attacks')
    fig = go.Figure()
    for _, row in attack_data.iterrows():
        if row['country'] in country_coords:
            lat, lon, z = country_coords[row['country']]
            fig.add_trace(go.Scatter3d(
                x=[lon], y=[lat], z=[z],
                mode='markers+text',
                marker=dict(size=max(3, row['attacks']/10), color=row['attacks'], colorscale='Reds', showscale=True),
                text=f"{row['country']}: {row['attacks']}",
                name=row['country']
            ))
    fig.update_layout(title="3D Geographic Attack Distribution", scene=dict(xaxis_title="Longitude", yaxis_title="Latitude", zaxis_title="Intensity"), height=600)
    st.plotly_chart(fig, use_container_width=True)
    gc.collect()


# ============ Alerts ============
def generate_alerts(df, threat_intel):
    st.subheader("🚨 Real-time Threat Alerts")
    recent = df.tail(10).copy()
    recent['threat_score'] = recent.apply(threat_intel.calculate_threat_score, axis=1)
    recent['severity'], recent['icon'] = zip(*recent['threat_score'].apply(threat_intel.get_severity_level))
    for _, attack in recent.iterrows():
        if attack['threat_score'] >= 60:
            st.markdown(f"""
            <div class="alert-box">
            {attack['icon']} <b>{attack['severity']} Severity</b><br>
            Source: {attack.get('country', 'Unknown')} | Protocol: {attack.get('proto', 'Unknown')}<br>
            Threat Score: {attack['threat_score']:.1f}/100<br>
            Time: {attack.get('datetime', 'Unknown')}
            </div>
            """, unsafe_allow_html=True)


# ============ Reports ============
def generate_intelligence_report(df, threat_intel):
    st.subheader("📋 Threat Intelligence Report")
    df['threat_score'] = df.apply(threat_intel.calculate_threat_score, axis=1)

    # Safe accessors (in case of missing columns)
    unique_sources = df['srcstr'].nunique() if 'srcstr' in df.columns else "N/A"
    top_protocol = df['proto'].mode()[0] if 'proto' in df.columns and not df['proto'].mode().empty else "N/A"
    avg_score = f"{df['threat_score'].mean():.2f}" if 'threat_score' in df.columns else "N/A"
    critical = len(df[df['threat_score'] >= 80]) if 'threat_score' in df.columns else "N/A"
    peak_hour = df['datetime'].dt.hour.mode()[0] if 'datetime' in df.columns else "N/A"
    top_country = df['country'].mode()[0] if 'country' in df.columns and not df['country'].mode().empty else "N/A"

    report = {
        "Total Attacks": len(df),
        "Unique Sources": unique_sources,
        "Top Protocol": top_protocol,
        "Average Score": avg_score,
        "Critical Threats": critical,
        "Peak Hour": peak_hour,
        "Most Active Country": top_country
    }

    cols = st.columns(3)
    for i, (k, v) in enumerate(report.items()):
        with cols[i % 3]:
            st.metric(k, v)

    if st.button("📥 Download Report (CSV)"):
        report_df = pd.DataFrame(list(report.items()), columns=['Metric', 'Value'])
        csv = report_df.to_csv(index=False)
        st.download_button("Download CSV", csv, "threat_report.csv", "text/csv")


# ============ New: Honeypot Node Simulation ============
def run_honeypot_simulation(df):
    st.subheader("🧠 Real-Time Honeypot Node Simulation")

    # Sidebar controls
    num_nodes = st.sidebar.slider("Number of Honeypot Nodes", 5, 50, 10)
    time_interval = st.sidebar.slider("Simulation Step Interval (seconds)", 0.05, 0.5, 0.1)

    # Safety: Prevent massive simulations
    if len(df) > 1000:
        st.warning("Large dataset detected. Sampling 1000 rows for smoother simulation.")
        df = df.sample(1000, random_state=42)

    # Initialize node positions
    nodes = {i: {"x": np.random.rand(), "y": np.random.rand(), "attacks": 0} for i in range(num_nodes)}

    node_plot = st.empty()
    metrics = st.sidebar.empty()
    sim_progress = st.sidebar.progress(0)

    total_steps = len(df)
    st.info(f"Estimated simulation time: {total_steps * time_interval:.1f}s (Press Stop to end early)")

    start_time = time.time()

    # Precreate figure & axes once — reused each frame
    fig, ax = plt.subplots(figsize=(5, 5), dpi=80)
    plt.tight_layout()

    for step, row in df.iterrows():
        # Random movement
        for i in nodes:
            nodes[i]["x"] += (np.random.rand() - 0.5) * 0.05
            nodes[i]["y"] += (np.random.rand() - 0.5) * 0.05
            nodes[i]["x"] = np.clip(nodes[i]["x"], 0, 1)
            nodes[i]["y"] = np.clip(nodes[i]["y"], 0, 1)

        # Simulate attack
        src = np.random.choice(num_nodes)
        tgt = np.random.choice([i for i in range(num_nodes) if i != src])
        nodes[src]["attacks"] += 1
        attacks = [(src, tgt)]

        # Clear the previous frame instead of creating new fig
        ax.clear()

        xs = [nodes[i]["x"] for i in nodes]
        ys = [nodes[i]["y"] for i in nodes]
        sizes = [20 + nodes[i]["attacks"] * 5 for i in nodes]
        colors = ["red" if nodes[i]["attacks"] > 5 else "blue" for i in nodes]

        ax.scatter(xs, ys, s=sizes, c=colors)

        for i in nodes:
            ax.text(nodes[i]["x"], nodes[i]["y"], str(i), fontsize=8)

        for s, t in attacks:
            ax.annotate("", xy=(nodes[t]["x"], nodes[t]["y"]),
                        xytext=(nodes[s]["x"], nodes[s]["y"]),
                        arrowprops=dict(facecolor="orange", shrink=0.05, lw=1))

        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.set_xlabel("Network Position X", fontsize=9)
        ax.set_ylabel("Network Position Y", fontsize=9)
        ax.set_title(f"Step {step + 1}/{total_steps}", fontsize=10)

        # Render efficiently
        node_plot.pyplot(fig, clear_figure=False)

        # Update metrics
        elapsed = time.time() - start_time
        est_total = elapsed / (step + 1) * total_steps
        remaining = est_total - elapsed
        top_nodes = sorted(nodes.items(), key=lambda x: x[1]['attacks'], reverse=True)[:3]

        metrics.markdown(f"""
        **Step:** {step + 1}/{total_steps}  
        **Elapsed Time:** {elapsed:.1f}s  
        **Estimated Remaining:** {remaining:.1f}s  
        **Total Attacks:** {sum([nodes[i]['attacks'] for i in nodes])}  
        **Top 3 Attack Nodes:** {[i[0] for i in top_nodes]}  
        """)

        sim_progress.progress((step + 1) / total_steps)
        time.sleep(time_interval)

    plt.close(fig)  # ✅ Free memory when done
    st.success("✅ Simulation finished successfully!")
# ============ Main App ============
def main():
    st.sidebar.title("⚙️ Configuration")
    uploaded = st.sidebar.file_uploader("Upload Honeypot CSV", type=["csv"])

    if uploaded is not None:
        df = pd.read_csv(uploaded)
        # Parse datetime safely
        if 'datetime' in df.columns:
            df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')
        else:
            st.error("Uploaded CSV must include a 'datetime' column (e.g. 2025-01-01 00:00:00).")
            st.stop()

        # Ensure essential columns exist (fill with reasonable defaults if missing)
        if 'hour' not in df.columns:
            df['hour'] = df['datetime'].dt.hour
        if 'attack_count' not in df.columns:
            df['attack_count'] = 1
        if 'proto' not in df.columns:
            df['proto'] = np.random.choice(["TCP", "UDP", "ICMP"], size=len(df))
        if 'country' not in df.columns:
            df['country'] = np.random.choice(["US", "CN", "RU", "IN", "DE"], size=len(df))
        if 'srcstr' not in df.columns:
            df['srcstr'] = [f"unknown_{i}" for i in range(len(df))]
        st.sidebar.success(f"✅ Loaded {uploaded.name}")
    else:
        st.sidebar.info("No file uploaded — using synthetic demo data")
        n = st.sidebar.slider("Synthetic attack count", 100, 2000, 500)
        start = pd.Timestamp("2025-01-01 00:00:00")
        df = pd.DataFrame({
            "datetime": [start + pd.Timedelta(minutes=i * 5) for i in range(n)],
            "proto": np.random.choice(["TCP", "UDP", "ICMP"], size=n, p=[0.6, 0.3, 0.1]),
            "srcstr": [f"192.168.{np.random.randint(0,255)}.{np.random.randint(0,255)}" for _ in range(n)],
            "host": np.random.choice([f"Node_{i}" for i in range(1, 11)], size=n),
            "country": np.random.choice(["US", "CN", "RU", "IN", "DE"], size=n, p=[0.2, 0.3, 0.25, 0.15, 0.1]),
            "dpt": np.random.choice([22, 80, 443, 3389, 21, 23, 3306, 5432], size=n),
            "spt": np.random.randint(1024, 65535, size=n)
        })
        df['hour'] = df['datetime'].dt.hour
        df['attack_count'] = 1

    threat_intel = ThreatIntelligence()

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "🎯 Overview", "🔍 Analytics", "📊 Predictions",
    "🌐 3D View", "📋 Reports", "🧠 Simulation", "🛡️ Prevention"  # NEW TAB
])

    with tab1:
        st.header("Overview")
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Attacks", len(df))
        c2.metric("Unique Sources", df['srcstr'].nunique() if 'srcstr' in df.columns else "N/A")
        avg = df.apply(threat_intel.calculate_threat_score, axis=1).mean() if not df.empty else 0
        c3.metric("Avg Threat Score", f"{avg:.1f}/100")
        crit = sum(df.apply(threat_intel.calculate_threat_score, axis=1) >= 80) if not df.empty else 0
        c4.metric("Critical Threats", crit, delta=f"{crit / len(df) * 100:.1f}%" if len(df) else "0%")
        generate_alerts(df, threat_intel)

        st.markdown("---")
        st.subheader("Quick Visuals")
        col_a, col_b = st.columns(2)
        with col_a:
            if 'proto' in df.columns:
                fig = px.histogram(df, x='proto', title="Protocol Distribution")
                st.plotly_chart(fig, use_container_width=True)
        with col_b:
            if 'country' in df.columns:
                fig = px.histogram(df, x='country', title="Attacks by Country")
                st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.header("Advanced Analytics")
        df = detect_anomalies(df)
        df = cluster_attack_patterns(df)

    with tab3:
        st.header("Predictive Analytics")
        advanced_prediction(df)

    with tab4:
        st.header("Geographic & 3D Visuals")
        visualize_3d_network(df)

    with tab5:
        st.header("Intelligence Reports")
        generate_intelligence_report(df, threat_intel)

    with tab6:
        st.header("Simulation")
        run_honeypot_simulation(df)
    with tab7:
        st.header("🛡️ Automated Prevention & Mitigation Solutions")
        
        # Initialize prevention modules
        firewall_gen = IntelligentFirewallRuleGenerator()
        rate_limiter = AdaptiveRateLimiter()
        incident_response = IncidentResponseAutomation()
        segmentation_advisor = NetworkSegmentationAdvisor()
        threat_feed_gen = ThreatIntelligenceFeedGenerator()
        attack_forecaster = PredictiveAttackForecaster()
        
        # Sub-tabs for different solutions
        sol1, sol2, sol3, sol4, sol5, sol6 = st.tabs([
            "🔥 Firewall Rules", "⏱️ Rate Limiting", "🚨 Incident Response",
            "🏗️ Network Segmentation", "📡 Threat Intel Feed", "🔮 Attack Forecast"
        ])
        
        # SOLUTION 1: Firewall Rules
        with sol1:
            st.subheader("🔥 Intelligent Firewall Rule Generator")
            st.markdown("""
            <div class="prevention-highlight">
            <b>UNIQUE FEATURE:</b> ML-driven automatic firewall rule generation based on attack patterns.
            Generates rules in multiple formats: iptables, Cisco ACL, JSON
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🔄 Generate Firewall Rules", key="gen_fw"):
                with st.spinner("Analyzing threats and generating rules..."):
                    rules = firewall_gen.generate_rules_from_threats(df, threat_intel)
                    
                    st.success(f"✅ Generated {len(rules)} firewall rules!")
                    
                    # Display rules in dataframe
                    rules_df = pd.DataFrame(rules)
                    st.dataframe(rules_df, use_container_width=True)
                    
                    # Export options
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        iptables_rules = firewall_gen.export_rules(format='iptables')
                        st.download_button(
                            "📥 Download iptables Rules",
                            iptables_rules,
                            "firewall_rules.sh",
                            "text/plain"
                        )
                    
                    with col2:
                        cisco_rules = firewall_gen.export_rules(format='cisco')
                        st.download_button(
                            "📥 Download Cisco ACL",
                            cisco_rules,
                            "cisco_acl.txt",
                            "text/plain"
                        )
                    
                    with col3:
                        json_rules = firewall_gen.export_rules(format='json')
                        st.download_button(
                            "📥 Download JSON",
                            json_rules,
                            "firewall_rules.json",
                            "application/json"
                        )
                    
                    # Show sample rules
                    st.subheader("Sample Generated Rules:")
                    st.code(iptables_rules[:500] + "\n...", language="bash")
        
        # SOLUTION 2: Rate Limiting
        with sol2:
            st.subheader("⏱️ Adaptive Rate Limiting System")
            st.markdown("""
            <div class="prevention-highlight">
            <b>UNIQUE FEATURE:</b> Dynamic rate limits that adapt based on attack patterns and predictive analytics.
            Uses statistical analysis (mean + 2σ) for 95% confidence thresholds.
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🔄 Calculate Rate Limits", key="calc_rate"):
                with st.spinner("Calculating adaptive rate limits..."):
                    recommendations = rate_limiter.calculate_adaptive_limits(df)
                    
                    if len(recommendations) > 0:
                        st.success(f"✅ Generated {len(recommendations)} rate limit recommendations!")
                        
                        rec_df = pd.DataFrame(recommendations)
                        st.dataframe(rec_df, use_container_width=True)
                        
                        # Visualize recommendations
                        fig = px.bar(rec_df, x=rec_df.index, y='max_observed',
                                    title="Rate Limit Analysis",
                                    labels={'max_observed': 'Max Observed Rate', 'index': 'Rule'})
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Export nginx config
                        nginx_config = rate_limiter.generate_nginx_config(recommendations)
                        st.download_button(
                            "📥 Download nginx Config",
                            nginx_config,
                            "nginx_rate_limit.conf",
                            "text/plain"
                        )
                        
                        st.subheader("Nginx Configuration Preview:")
                        st.code(nginx_config, language="nginx")
        
        # SOLUTION 3: Incident Response
        with sol3:
            st.subheader("🚨 Automated Incident Response Playbook")
            st.markdown("""
            <div class="prevention-highlight">
            <b>UNIQUE FEATURE:</b> Multi-stage automated response with escalation logic.
            4 severity levels with different automation and human review requirements.
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🔄 Generate Response Playbook", key="gen_playbook"):
                with st.spinner("Creating incident response playbook..."):
                    playbook = incident_response.generate_response_playbook(df, threat_intel)
                    
                    st.success(f"✅ Generated playbook with {len(playbook)} severity levels!")
                    
                    # Display each severity level
                    for action in playbook:
                        severity = action['severity']
                        color = {
                            'LOW': '#4CAF50',
                            'MEDIUM': '#FFC107',
                            'HIGH': '#FF9800',
                            'CRITICAL': '#F44336'
                        }.get(severity, '#999')
                        
                        st.markdown(f"""
                        <div style="background-color: {color}; color: white; padding: 15px; border-radius: 8px; margin: 10px 0;">
                        <h3>{severity} SEVERITY - {action['trigger_count']} Events</h3>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.write("**Response Actions:**")
                        for i, step in enumerate(action['actions'], 1):
                            st.write(f"{i}. {step}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Automation Level", action['automation'])
                        with col2:
                            st.metric("Human Review", "Required" if action['human_review'] else "Not Required")
                        
                        if 'review_sla' in action:
                            st.warning(f"⏰ Review SLA: {action['review_sla']}")
                        
                        st.markdown("---")
                    
                    # Export playbook
                    playbook_text = incident_response.export_playbook(playbook)
                    st.download_button(
                        "📥 Download Complete Playbook",
                        playbook_text,
                        "incident_response_playbook.txt",
                        "text/plain"
                    )
        
        # SOLUTION 4: Network Segmentation
        with sol4:
            st.subheader("🏗️ Network Segmentation Advisor")
            st.markdown("""
            <div class="prevention-highlight">
            <b>UNIQUE FEATURE:</b> ML-driven micro-segmentation recommendations based on attack patterns.
            Identifies critical systems and recommends isolation strategies.
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🔄 Analyze Segmentation", key="analyze_seg"):
                with st.spinner("Analyzing network and generating recommendations..."):
                    recommendations = segmentation_advisor.analyze_and_recommend(df)
                    
                    st.success(f"✅ Generated {len(recommendations)} segmentation recommendations!")
                    
                    for rec in recommendations:
                        priority_color = {
                            'CRITICAL': '#F44336',
                            'HIGH': '#FF9800',
                            'MEDIUM': '#FFC107',
                            'LOW': '#4CAF50'
                        }.get(rec['priority'], '#999')
                        
                        st.markdown(f"""
                        <div style="border-left: 5px solid {priority_color}; padding: 15px; background: #f5f5f5; margin: 10px 0; border-radius: 5px;">
                        <h4>{rec['segment_name']} - Priority: {rec['priority']}</h4>
                        <p><b>Reason:</b> {rec['reason']}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        st.write("**Recommended Rules:**")
                        for rule in rec['rules']:
                            st.write(f"• {rule}")
                        
                        st.markdown("---")
                    
                    # Export diagram
                    diagram = segmentation_advisor.export_diagram(recommendations)
                    st.download_button(
                        "📥 Download Segmentation Plan",
                        diagram,
                        "network_segmentation_plan.txt",
                        "text/plain"
                    )
                    
                    st.subheader("Network Diagram:")
                    st.code(diagram, language="text")
        
        # SOLUTION 5: Threat Intel Feed
        with sol5:
            st.subheader("📡 Threat Intelligence Feed Generator")
            st.markdown("""
            <div class="prevention-highlight">
            <b>UNIQUE FEATURE:</b> STIX/TAXII compatible IOC feeds for SIEM integration.
            Generates machine-readable threat intelligence for automated consumption.
            </div>
            """, unsafe_allow_html=True)
            
            if st.button("🔄 Generate Threat Feed", key="gen_feed"):
                with st.spinner("Generating IOC feed..."):
                    ioc_feed = threat_feed_gen.generate_ioc_feed(df, threat_intel)
                    
                    st.success(f"✅ Generated feed with {len(ioc_feed['indicators'])} indicators!")
                    
                    # Display feed metadata
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Feed Version", ioc_feed['feed_version'])
                    with col2:
                        st.metric("Total Indicators", len(ioc_feed['indicators']))
                    with col3:
                        st.metric("Generated At", ioc_feed['generated_at'][:10])
                    
                    # Display sample indicators
                    st.subheader("Sample Indicators:")
                    sample_indicators = pd.DataFrame(ioc_feed['indicators'][:10])
                    st.dataframe(sample_indicators, use_container_width=True)
                    
                    # Export options
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        json_feed = threat_feed_gen.export_feed(ioc_feed, format='json')
                        st.download_button(
                            "📥 Download JSON Feed",
                            json_feed,
                            "threat_intel_feed.json",
                            "application/json"
                        )
                    
                    with col2:
                        csv_feed = threat_feed_gen.export_feed(ioc_feed, format='csv')
                        st.download_button(
                            "📥 Download CSV Feed",
                            csv_feed,
                            "threat_intel_feed.csv",
                            "text/csv"
                        )
                    
                    # Visualization
                    if len(ioc_feed['indicators']) > 0:
                        indicators_df = pd.DataFrame(ioc_feed['indicators'])
                        
                        # Filter for IP indicators
                        ip_indicators = indicators_df[indicators_df['type'] == 'ipv4']
                        if len(ip_indicators) > 0:
                            fig = px.scatter(ip_indicators, x=ip_indicators.index, y='threat_score',
                                           size='attack_count', color='threat_score',
                                           title="IOC Threat Scores",
                                           labels={'threat_score': 'Threat Score', 'index': 'Indicator ID'})
                            st.plotly_chart(fig, use_container_width=True)
        
        # SOLUTION 6: Attack Forecast
        with sol6:
            st.subheader("🔮 Predictive Attack Window Forecaster")
            st.markdown("""
            <div class="prevention-highlight">
            <b>UNIQUE FEATURE:</b> Time-series based prediction of high-risk attack windows.
            Enables proactive resource allocation and defensive posture adjustment.
            </div>
            """, unsafe_allow_html=True)
            
            hours_to_forecast = st.slider("Forecast Window (hours)", 6, 48, 24, key="forecast_hours")
            
            if st.button("🔄 Generate Forecast", key="gen_forecast"):
                with st.spinner("Forecasting attack windows..."):
                    forecast = attack_forecaster.forecast_attack_windows(df, hours_ahead=hours_to_forecast)
                    
                    if len(forecast) > 0:
                        st.success(f"✅ Generated {hours_to_forecast}-hour forecast!")
                        
                        # Convert to dataframe for visualization
                        forecast_df = pd.DataFrame(forecast)
                        
                        # Visualize forecast
                        fig = go.Figure()
                        
                        # Color code by risk level
                        colors = {'HIGH': 'red', 'NORMAL': 'green'}
                        for risk_level in ['HIGH', 'NORMAL']:
                            risk_data = forecast_df[forecast_df['risk_level'] == risk_level]
                            fig.add_trace(go.Scatter(
                                x=risk_data['datetime'],
                                y=risk_data['predicted_attacks'],
                                mode='lines+markers',
                                name=f'{risk_level} Risk',
                                line=dict(color=colors[risk_level], width=3),
                                marker=dict(size=10)
                            ))
                        
                        fig.update_layout(
                            title="Attack Forecast - Next 24 Hours",
                            xaxis_title="Time",
                            yaxis_title="Predicted Attacks",
                            hovermode='x unified'
                        )
                        st.plotly_chart(fig, use_container_width=True)
                        
                        # Display high-risk windows
                        high_risk_windows = forecast_df[forecast_df['risk_level'] == 'HIGH']
                        
                        if len(high_risk_windows) > 0:
                            st.warning(f"⚠️ {len(high_risk_windows)} HIGH RISK windows detected!")
                            
                            for _, window in high_risk_windows.iterrows():
                                st.markdown(f"""
                                <div style="background-color: #fff3cd; border-left: 5px solid #ff9800; padding: 15px; margin: 10px 0; border-radius: 5px;">
                                <h4>⚠️ High Risk Window: {window['datetime']}</h4>
                                <p><b>Predicted Attacks:</b> ~{window['predicted_attacks']}</p>
                                </div>
                                """, unsafe_allow_html=True)
                                
                                st.write("**Recommended Actions:**")
                                for action in window['recommended_actions']:
                                    st.write(f"• {action}")
                        
                        # Export schedule
                        schedule = attack_forecaster.export_schedule(forecast)
                        st.download_button(
                            "📥 Download Defense Schedule",
                            schedule,
                            "attack_forecast_schedule.txt",
                            "text/plain"
                        )
                        
                        st.subheader("Complete Forecast:")
                        st.dataframe(forecast_df, use_container_width=True)
                    else:
                        st.warning("Insufficient data for forecasting. Need datetime information.")

    gc.collect()


if __name__ == "__main__":
    main()
