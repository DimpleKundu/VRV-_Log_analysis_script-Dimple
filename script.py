import re
import csv
from collections import defaultdict

# File paths
log_file = "sample.log"
output_file = "log_analysis_results.csv"

# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 10

# Dictionaries to store analysis results
ip_request_count = defaultdict(int)
endpoint_access_count = defaultdict(int)
failed_login_attempts = defaultdict(int)

# Regex patterns for parsing log entries
log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) .*? ".*? (.*?) HTTP/.*?" (\d+) .*?')
failed_login_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) .*? ".*?" 401 .*?')

# Read the log file and process each line
with open(log_file, 'r') as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            ip, endpoint, status_code = match.groups()
            ip_request_count[ip] += 1
            endpoint_access_count[endpoint] += 1
            if status_code == '401':
                failed_login_attempts[ip] += 1

# Sort results
sorted_ip_requests = sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)
most_accessed_endpoint = max(endpoint_access_count.items(), key=lambda x: x[1])
suspicious_ips = [(ip, count) for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD]

# Output results to terminal
print("IP Address           Request Count")
for ip, count in sorted_ip_requests:
    print(f"{ip:<20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

print("\nSuspicious Activity Detected:")
if suspicious_ips:
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips:
        print(f"{ip:<20} {count}")
else:
    print("No suspicious activity detected.")

# Write results to CSV
with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    
    # Write IP request counts
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(sorted_ip_requests)

    # Write most accessed endpoint
    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow(most_accessed_endpoint)

    # Write suspicious activity
    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    if suspicious_ips:
        writer.writerows(suspicious_ips)
    else:
        writer.writerow(["No suspicious activity detected"])

print(f"\nResults saved to {output_file}.")
