# CrowdStrike
# Threat Hunting with CrowdStrike Falcon and Splunk Search Processing Language (SPL)

![GitHub](https://img.shields.io/badge/Splunk-Search%20Processing%20Language-blue)

This repository contains a collection of Splunk's Search Processing Language (SPL) queries designed for threat hunting with CrowdStrike Falcon data related to PowerShell activity. These queries are intended to help security analysts detect and investigate potential threats involving PowerShell on their endpoints.

## How to Use the Queries

1. Ensure you have access to your CrowdStrike Falcon data and have integrated it with your Splunk instance.

2. Copy the SPL queries from the provided `README.md` file or the individual `.spl` files and paste them into your Splunk's search bar.

3. Modify the search timeframe and adapt the queries to match your environment, data sources, and threat-hunting objectives.

4. Execute the queries and analyze the results to identify any suspicious or malicious PowerShell activities in your environment.

## List of SPL Queries

1. **Detecting Suspicious PowerShell Execution**: Identify processes where PowerShell is executed with specific command-line parameters.

2. **Identifying PowerShell Downloads**: Detect PowerShell commands involving the "Invoke-WebRequest" cmdlet.

3. **PowerShell Scripts from URLs**: Find PowerShell commands with URLs in the command-line.

4. **PowerShell Script Block Logging**: Investigate PowerShell scripts along with their script blocks, considering parent processes.

5. **Detecting Base64 Encoded PowerShell Commands**: Identify PowerShell commands with Base64-encoded command parameters.

6. **PowerShell Scriptblock without Bypass**: Detect PowerShell commands run without bypassing execution policy.

7. **Identifying PowerShell Downloads with Suspicious User-Agent**: Identify suspicious PowerShell downloads with non-standard User-Agent.

8. **PowerShell Process Started from Unusual Locations**: Detect PowerShell processes started from locations other than the default path.

9. **Identifying PowerShell Empire Activity**: Identify potential PowerShell Empire activity based on command-line patterns.

10. **Detecting PowerShell Obfuscated Scripts**: Find PowerShell commands that include obfuscated code.

## Contributions

Contributions to this repository are welcome! If you have additional SPL queries or improvements, feel free to open an issue or submit a pull request.

## Disclaimer

Please note that the provided SPL queries are examples for threat hunting and may not cover all possible scenarios or the latest threats. Always review and test the queries in a controlled environment before deploying them in a production environment.


