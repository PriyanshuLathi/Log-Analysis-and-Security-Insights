# Log Analysis and Security Insights

## Overview

This Python script analyzes server log files to extract key information, detect suspicious activity, and generate structured insights. It demonstrates file handling, data processing, and cybersecurity analysis techniques, making it useful for identifying patterns and potential threats in server logs. The script is designed to assist system administrators and security professionals in monitoring server traffic and detecting unusual behaviors, such as brute-force attacks or failed login attempts.

## Aim

The script focuses on the following objectives:

- **Data Loading and Parsing:** Efficiently read and process server log files to extract useful information.
- **IP Address Analysis:** Identify and count the number of requests from each unique IP address.
- **Endpoint Access Frequency:** Determine the most frequently accessed endpoints to understand user behavior.
- **Suspicious Activity Detection:** Detect potential brute-force attacks or anomalous behaviors based on failed login attempts (`401` HTTP status codes).

## Dataset Description

The script processes standard server log files that typically include the following components:

- **IP Address:** Identifies the client making the request.
- **Timestamp:** The date and time when the request was made.
- **Request Method and Endpoint:** The HTTP method (GET, POST, etc.) and the requested resource (endpoint).
- **HTTP Status Code:** Indicates the outcome of the request, such as `200 OK`, `401 Unauthorized`, etc.

### Sample Log Entry:

`192.168.1.1 - - [03/Dec/2024:10:12:34 +0000] "GET /home HTTP/1.1" 200 512`

## Practical Implementation

The script includes the following steps:

1. **Load Log Data:** Reads log data from a file specified by the user.
2. **Extract Information:** Parses key components like IP addresses, endpoints, and status codes using regular expressions.
3. **Analyze Requests:** Counts the number of requests per IP and identifies the most frequently accessed endpoints.
4. **Detect Suspicious Activity:** Flags IPs that have made excessive failed login attempts (status code `401`).
5. **Output Results:** Displays the findings in the terminal and exports them to a CSV file for further analysis.

## Features

### 1. **IP Address Analysis:**
- Counts and sorts the number of requests made by each IP address.
- Highlights the most active IPs to identify potential sources of high traffic or suspicious activity.

### 2. **Most Accessed Endpoint:**
- Identifies the most frequently accessed endpoint to understand which resources are most popular or targeted by users.
- Useful for performance monitoring and understanding user behavior.

### 3. **Suspicious Activity Detection:**
- Flags IP addresses that have exceeded a configurable threshold (default: 10) of failed login attempts, indicating potential brute-force attacks.
- Suspicious activity is flagged based on failed `401` status codes.

### 4. **CSV Export:**
- Saves the results of the analysis, including IP request counts, most accessed endpoint, and suspicious IPs, to a CSV file (`log_analysis_results.csv`), which can be used for reporting or further analysis.

## Visualization for sample.log

1. **Requests per IP Address:**

<p align="center"> <img src="https://github.com/user-attachments/assets/85c248e8-5916-4c27-936a-10101d4875d4" alt="URL based web phishing model" width = 750 /> </p>

2. **Most Accessed Endpoints:**

<p align="center"> <img src="https://github.com/user-attachments/assets/2f478f86-4add-49a6-83e9-9f7ff29681e8" alt="URL based web phishing model" width = 750 /> </p>

## Getting Started

To get started with this project, clone the repository and install the necessary dependencies listed in the `requirements.txt` file. Then, run the Python script (`log_analysis_script.py`).

### Steps to run:

1. **Clone the repository:**

    ```bash
    git clone https://github.com/PriyanshuLathi/Log-Analysis-and-Security-Insights
    ```

2. **Navigate to the project directory:**

    ```bash
    cd Log-Analysis-and-Security-Insights
    ```

3. **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Run the script:**

    ```bash
    python log_analysis_script.py
    ```

The script will analyze the log file (`sample.log` by default), detect suspicious activity, and generate CSV output and visualizations.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/PriyanshuLathi/Log-Analysis-and-Security-Insights/blob/main/LICENSE) file for details.

## Contact

For questions or feedback:

- LinkedIn: [Priyanshu Lathi](https://www.linkedin.com/in/priyanshu-lathi)
- GitHub: [Priyanshu Lathi](https://github.com/PriyanshuLathi)

## Authors

- Priyanshu Lathi
