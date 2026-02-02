import matplotlib.pyplot as plt
import seaborn as sns

def plot_eda(df):
    # Protocols
    df["proto"].value_counts().plot(kind="bar", title="Protocols Used")
    plt.show()
    df["proto"].value_counts().plot(kind="pie", autopct="%.2f%%", title="Protocols Used")
    plt.show()

    # Month, Day, Hour
    df["month"].value_counts().plot(kind="bar", title="Cyberattacks per Month")
    plt.show()
    df["day"].value_counts().plot(kind="bar", title="Cyberattacks per Day")
    plt.show()
    df["hour"].value_counts().plot(kind="bar", title="Cyberattacks per Hour")
    plt.show()

    # Host, Country, Source
    df["host"].value_counts().plot(kind="bar", title="Cyberattacks per Host")
    plt.show()
    df["country"].value_counts().head(10).plot(kind="bar", title="Top 10 Countries")
    plt.show()
    df["srcstr"].value_counts().head(10).plot(kind="bar", title="Top 10 Attack Sources")
    plt.show()

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
