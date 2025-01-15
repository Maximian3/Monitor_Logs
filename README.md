# Monitor_Logs

Script Description

This script is designed for monitoring, analyzing, and visualizing data from web server log files. It automatically reads logs, processes them to detect suspicious activities, and generates visual graphs for statistical representation.

---+++++

Main Purpose of the Script

1. Web Server Log Analysis**:
   - Reads log files from a specified directory.
   - Parses log entries using regular expressions.
   - Extracts statistics for IP addresses, pages, HTTP methods, response codes, and other metrics.

2. Suspicious Activity Detection**:
   - Identifies IP addresses exceeding the defined request threshold (`SUSPICIOUS_THRESHOLD`).
   - Logs and reports such IP addresses for further action (e.g., blocking).

3. Data Visualization**:
   - Generates graphs for:
     - Popular pages (URLs) with the highest number of requests.
     - Unique IP addresses per day.
     - HTTP error statistics (4xx and 5xx codes).
     - Distribution of HTTP methods (GET, POST, etc.).
     - Proportion of mobile vs. desktop users based on User-Agent.

4. Real-Time Log Monitoring**:
   - Continuously monitors the log directory for new files.
   - Processes new data every 10 seconds (default, defined by `POLL_INTERVAL`).
   - Updates visual graphs hourly to display the latest insights.

5. Graceful Termination**:
   - Handles keyboard interrupts (`Ctrl+C`) to allow safe and clean script termination.

---+++

Primary Use Cases

1. System Administrators**:
   - Monitor web server activity.
   - Quickly identify suspicious activities, such as botnet attacks or intrusion attempts.

2. Data Analysts**:
   - Analyze user behavior, including popular pages, devices used, and HTTP methods.

3. Security Engineers**:
   - Detect anomalies and respond to threats promptly.

4. General Optimization**:
   - Gather traffic data to improve web application performance.
   - Identify problematic pages with errors (e.g., 404 or 500).

---++++

 Script Benefits

1. Automated Monitoring**:
   - Eliminates manual log inspection.
   - Continuously tracks server activity.

2. Actionable Insights**:
   - Provides real-time data on server performance and usage.

3. Customizable and Extensible**:
   - Can be expanded for additional features, such as automatic IP blocking or alert integrations.

This script is straightforward yet powerful, making it suitable for a wide range of monitoring and analytical tasks.
