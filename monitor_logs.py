import os
import re
import pandas as pd
import time
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import logging
import signal
import sys

# Configuration
LOG_DIR = "/Users/Documents/2024/New Stady/Scientific Programming/test/logs"  # Log files directory
SUSPICIOUS_THRESHOLD = 100  # Request threshold for suspicious activity
POLL_INTERVAL = 10  # Log check interval in seconds

# Log pattern
LOG_PATTERN = (
    r'(?P<IP>\d+\.\d+\.\d+\.\d+) - - '
    r'\[(?P<DateTime>[^\]]+)\] '
    r'"(?P<RequestMethod>GET|POST|PUT|DELETE|HEAD|OPTIONS) (?P<URL>[^ ]+) HTTP/[0-9.]+" '
    r'(?P<StatusCode>\d{3}) (?P<ResponseSize>\d+) '
    r'"(?P<Referer>[^"]+)" '
    r'"(?P<UserAgent>[^"]+)"'
)

# Logging setup
logging.basicConfig(filename='log_analysis.log', level=logging.INFO)

def read_logs(log_dir, processed_files):
    """Read new logs from the specified folder."""
    log_data = []
    for filename in os.listdir(log_dir):
        filepath = os.path.join(log_dir, filename)
        if os.path.isfile(filepath) and filename not in processed_files and filename.endswith(".log"):
            with open(filepath, "r") as file:
                lines = file.readlines()
                log_data.extend([re.match(LOG_PATTERN, line).groupdict() 
                                 for line in lines if re.match(LOG_PATTERN, line)])
            processed_files.add(filename)
    return log_data

def analyze_logs(log_data):
    """Analyze logs for suspicious activity."""
    try:
        if not log_data:
            print("No logs to analyze.")
            return None, None, None, None, None, None, None, None

        df = pd.DataFrame(log_data)

        # Convert DateTime to UTC (if needed) for consistency
        df["DateTime"] = pd.to_datetime(df["DateTime"], format="%d/%b/%Y:%H:%M:%S %z")
        df["DateTime"] = df["DateTime"].dt.tz_convert('UTC')

        df["StatusCode"] = df["StatusCode"].astype(int)
        df["ResponseSize"] = df["ResponseSize"].astype(int)

        # Convert date into different time intervals
        df["Hour"] = df["DateTime"].dt.hour  # Group by hour
        df["Day"] = df["DateTime"].dt.date  # Group by day
        df["Month"] = df["DateTime"].dt.to_period('M')  # Group by month

        # Count visits for each interval
        hour_counts = df.groupby("Hour").size()
        day_counts = df.groupby("Day").size()
        month_counts = df.groupby("Month").size()

        # Detect suspicious IPs
        ip_counts = df["IP"].value_counts()
        suspicious_ips = ip_counts[ip_counts > SUSPICIOUS_THRESHOLD]
        
        if not suspicious_ips.empty:
            print("Suspicious IPs found:")
            for ip, count in suspicious_ips.items():
                print(f"IP: {ip}, requests: {count}")
        else:
            print("No suspicious IPs found.")

        # Analyze HTTP methods, status codes, referers, and User-Agent
        method_counts = df["RequestMethod"].value_counts()
        status_counts = df["StatusCode"].value_counts()
        referer_counts = df["Referer"].value_counts()
        user_agent_counts = df["UserAgent"].value_counts()

        # Output statistics
        print(f"Request Methods:\n{method_counts}")
        print(f"Status Codes:\n{status_counts}")
        print(f"Referers:\n{referer_counts}")
        print(f"User-Agent:\n{user_agent_counts}")

        return df, hour_counts, day_counts, month_counts, method_counts, status_counts, referer_counts, user_agent_counts

    except Exception as e:
        logging.error(f"Error processing logs: {e}")
        print(f"Error: {e}")
        return None, None, None, None, None, None, None, None

# Plot functions to show all graphs in one window

def plot_traffic_by_url(df):
    """Traffic by URL plot."""
    url_counts = df["URL"].value_counts().head(10)
    plt.subplot(2, 3, 1)  # 2 rows, 3 columns, first subplot
    plt.bar(url_counts.index, url_counts.values, color="seagreen")
    plt.title("Traffic by Pages (URL)")
    plt.xlabel("Page (URL)")
    plt.ylabel("Number of Requests")
    plt.xticks(rotation=45)
    plt.grid(True)

def plot_unique_ips(df):
    """Unique IPs count plot by day."""
    unique_ips_per_day = df.groupby("Day")["IP"].nunique()
    plt.subplot(2, 3, 2)  # 2 rows, 3 columns, second subplot
    plt.plot(unique_ips_per_day.index, unique_ips_per_day.values, marker="o", linestyle="-", color="blue")
    plt.title("Unique IPs Count by Day")
    plt.xlabel("Date")
    plt.ylabel("Unique IP Count")
    plt.grid(True)

def plot_http_errors(df):
    """HTTP error plot for 4xx and 5xx status codes."""
    error_counts = df[df["StatusCode"].isin([400, 401, 403, 404, 500, 502, 503, 504])]
    error_counts = error_counts.groupby("StatusCode").size()
    plt.subplot(2, 3, 3)  # 2 rows, 3 columns, third subplot
    plt.bar(error_counts.index.astype(str), error_counts.values, color="tomato")
    plt.title("4xx and 5xx Errors")
    plt.xlabel("Error Code")
    plt.ylabel("Error Count")
    plt.grid(True)

def plot_http_methods(df):
    """Pie chart for HTTP method distribution."""
    method_counts = df["RequestMethod"].value_counts()
    plt.subplot(2, 3, 4)  # 2 rows, 3 columns, fourth subplot
    plt.pie(method_counts, labels=method_counts.index, autopct="%1.1f%%", startangle=90, colors=["lightblue", "lightgreen", "lightcoral", "gold", "plum"])
    plt.title("HTTP Method Distribution")
    plt.axis("equal")  # Equal aspect ratio ensures the pie chart is circular.

def plot_device_usage(df):
    """Mobile vs. Desktop User-Agent chart."""
    mobile_agents = ["Mobile", "Android", "iPhone", "iPad", "Windows Phone", "BlackBerry", "webOS", "Opera Mini"]
    df["Device"] = df["UserAgent"].apply(lambda ua: "Mobile" if any(agent in ua for agent in mobile_agents) else "Desktop")
    
    device_counts = df["Device"].value_counts()
    plt.subplot(2, 3, 5)  # 2 rows, 3 columns, fifth subplot
    plt.pie(device_counts, labels=device_counts.index, autopct="%1.1f%%", startangle=90, colors=["lightblue", "lightgreen"])
    plt.title("Mobile vs. Desktop Users")
    plt.axis("equal")

def graceful_exit(sig, frame):
    """Gracefully exit the script on KeyboardInterrupt (Ctrl+C)."""
    print("\nGracefully exiting...")
    sys.exit(0)

# Register signal handler for graceful exit on Ctrl+C
signal.signal(signal.SIGINT, graceful_exit)

def monitor_logs():
    """Continuous log monitoring with visualization."""
    processed_files = set()
    last_plot_time = datetime.now() - timedelta(hours=1)  # Initial time setup for the first update
    print(f"[{datetime.now()}] Starting log monitoring...")

    while True:
        try:
            current_time = datetime.now()
            # Update graphs every hour
            if current_time - last_plot_time >= timedelta(hours=1):
                log_data = read_logs(LOG_DIR, processed_files)
                if log_data:
                    df, hour_counts, day_counts, month_counts, method_counts, status_counts, referer_counts, user_agent_counts = analyze_logs(log_data)

                    # Create a figure with a specific size
                    plt.figure(figsize=(15, 10))

                    # Call functions to display graphs
                    plot_traffic_by_url(df)  # Traffic by pages
                    plot_unique_ips(df)  # Unique IPs
                    plot_http_errors(df)  # 4xx and 5xx errors
                    plot_http_methods(df)  # HTTP method distribution
                    plot_device_usage(df)  # Mobile vs. desktop users

                    # Adjust layout to prevent overlap and display all plots
                    plt.tight_layout()
                    plt.show()

                    last_plot_time = current_time
            time.sleep(POLL_INTERVAL)
        except Exception as e:
            logging.error(f"Error analyzing logs: {e}")
            print(f"Error analyzing logs: {e}")
            time.sleep(POLL_INTERVAL)

# Start monitoring
monitor_logs()
