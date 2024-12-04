

# **Log File Analyzer**

## **Project Description**
This project is a simple **Log File Analyzer** built in Python. It reads a server log file, analyzes the data, and generates a summary report. The report includes:

- Number of requests per IP address.
- Most frequently accessed endpoint.
- Suspicious activity detection based on failed login attempts.

## **Features**
1. **Requests per IP:**  
   Displays the number of requests made by each IP address.
   
2. **Most Accessed Endpoint:**  
   Identifies the endpoint (URL) that was accessed the most.

3. **Suspicious Activity:**  
   Detects potential brute-force attacks by identifying IP addresses with excessive failed login attempts.

## **Files**
- **`sample.log`**: The input log file containing the server access logs.
- **`script.py`**: The Python script that reads and analyzes the log file.
- **`log_analysis_results.csv`**: The output file containing the analysis results in a tabular format.

## **Sample Output**
| **Requests per IP** | **Request Count** |
|---------------------|-------------------|
| 203.0.113.5         | 8                 |
| 198.51.100.23       | 8                 |

| **Most Accessed Endpoint** | **Access Count** |
|----------------------------|------------------|
| /login                     | 13               |

| **Suspicious Activity** | **Failed Login Count** |
|-------------------------|------------------------|
| No suspicious activity detected | 0            |


thank you
- Dimple Kundu