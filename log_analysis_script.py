import re
import csv
from collections import Counter
import time
import matplotlib.pyplot as plt
import seaborn as sns

start_time = time.time()

# Threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parse the log file and extract IPs, endpoints, and failed login attempts."""
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
    endpoint_pattern = r'\"(?:GET|POST|PUT|DELETE|HEAD) (.+?) HTTP'
    failed_login_pattern = r'(401|Invalid credentials)'

    ip_addresses = []
    endpoints = []
    failed_attempts = []

    with open(file_path, 'r') as file:
        for line in file:
            # Extracting IP addresses
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip_addresses.append(ip_match.group(1))
            
            # Extracting endpoints
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match:
                endpoints.append(endpoint_match.group(1))
            
            # Detecting failed login attempts
            if re.search(failed_login_pattern, line):
                if ip_match:
                    failed_attempts.append(ip_match.group(1))
    
    return ip_addresses, endpoints, failed_attempts

def count_occurrences(data):
    """Count occurrences of each item in the data."""
    return Counter(data)

def detect_suspicious_activity(failed_attempts, threshold):
    """Identify IPs with failed login attempts exceeding the threshold."""
    return {ip: count for ip, count in Counter(failed_attempts).items() if count > threshold}

def save_to_csv(ip_counts, most_accessed, suspicious_ips, output_file):
    """Save results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Requests per IP
        writer.writerow(["Requests per IP address:"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint:"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected:"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        if suspicious_ips:
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["N/A", "N/A"])

def visualize_data(ip_counts, endpoint_counts, suspicious_ips):
    # Setting a consistent style
    sns.set(style="whitegrid")

    # Plotting Requests per IP Address
    plt.figure(figsize=(10, 5))
    sns.barplot(x=list(ip_counts.keys()), y=list(ip_counts.values()), hue=list(ip_counts.keys()), palette='viridis')
    plt.title('Requests per IP Address')
    plt.xlabel('IP Address')
    plt.ylabel('Request Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('Visualization/requests_per_ip.png')
    plt.show()

    # Plotting Most Accessed Endpoints
    plt.figure(figsize=(8, 6))
    endpoint_labels, endpoint_counts_list = zip(*endpoint_counts.items())
    plt.pie(endpoint_counts_list, labels=endpoint_labels, autopct='%1.1f%%', startangle=140, colors=sns.color_palette("pastel"))
    plt.title('Most Accessed Endpoints')
    plt.tight_layout()
    plt.savefig('Visualization/most_accessed_endpoints.png')
    plt.show()

    # Plotting Suspicious IPs with Failed Login Attempts
    if suspicious_ips:
        plt.figure(figsize=(10, 5))
        sns.barplot(x=list(suspicious_ips.values()), y=list(suspicious_ips.keys()), hue=list(suspicious_ips.keys()), palette='magma')
        plt.title('Failed Login Attempts by IP')
        plt.xlabel('Failed Login Attempts')
        plt.ylabel('IP Address')
        plt.tight_layout()
        plt.savefig('Visualization/failed_logins.png')
        plt.show()

def main():
    log_file = "sample.log"
    output_csv = "log_analysis_results.csv"

    # Parsing the log file
    ip_addresses, endpoints, failed_attempts = parse_log_file(log_file)

    ip_counts = count_occurrences(ip_addresses)
    endpoint_counts = count_occurrences(endpoints)
    suspicious_ips = detect_suspicious_activity(failed_attempts, FAILED_LOGIN_THRESHOLD)

    # Most accessed endpoint
    most_accessed = endpoint_counts.most_common(1)[0] if endpoint_counts else ("N/A", 0)

    # Results to terminal
    print("Requests per IP address:")

    print("-"*32)
    print("IP Address         Request Count")
    print("-"*32)
    for ip, count in ip_counts.items():
        print(f"{ip:<24} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("-"*40)
    print("IP Address         Failed Login Attempts")
    print("-"*40)
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<26} {count}")
    else:
        print("N/A                        N/A")

    # Saving results to CSV
    save_to_csv(ip_counts, most_accessed, suspicious_ips, output_csv)
    print(f"\nResults saved to {output_csv}")
    
    # Call visualization after data is processed
    visualize_data(ip_counts, endpoint_counts, suspicious_ips)

    # Print execution time
    print(f"\nScript Execution Time: {time.time() - start_time:.2f} seconds")

if __name__ == "__main__":
    main()