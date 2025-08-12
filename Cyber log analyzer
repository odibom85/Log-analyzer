import re
import pandas as pd
import matplotlib.pyplot as plt

# Regex for extracting timestamp and IP from log entries
log_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Failed login from (\d+\.\d+\.\d+\.\d+)")

def parse_logs(file_path):
    matches = []
    with open(file_path, "r") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                matches.append(match.groups())
    return pd.DataFrame(matches, columns=["timestamp", "ip"])

def analyze_failed_logins(df):
    ip_counts = df["ip"].value_counts()
    print("Top suspicious IPs:\n", ip_counts.head(5))
    ip_counts.head(10).plot(kind="bar", title="Top 10 Suspicious IPs")
    plt.show()

if __name__ == "__main__":
    logs_df = parse_logs("../data/sample_logs.txt")
    analyze_failed_logins(logs_df)
