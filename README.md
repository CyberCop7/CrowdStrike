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

1. **Detecting Suspicious PowerShell Execution**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search (process_cmdline="*-EncodedCommand *" OR process_cmdline="*-Command *" OR process_cmdline="*-c *")
```

2. **Identifying PowerShell Downloads**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search process_cmdline="*Invoke-WebRequest*"
```

3. **PowerShell Scripts from URLs**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search process_cmdline="*http*"
```

4. **PowerShell Script Block Logging**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search process_cmdline="*-EncodedCommand *" OR process_cmdline="*-Command *" OR process_cmdline="*-c *"
| eval script_block=if(isnull(process_parent_path) OR isnull(process_parent_cmdline), process_cmdline, mvzip(process_parent_path, process_parent_cmdline))
| table process_name, process_cmdline, script_block
```

5. **Detecting Base64 Encoded PowerShell Commands**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search process_cmdline="*powershell*"
| regex process_cmdline="powershell\s+-(?:Enc|C)odedCommand"
```

6. **PowerShell Scriptblock without Bypass**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search process_cmdline="*powershell*"
| regex process_cmdline="powershell\s+-NoP\s+-NonI\s+-W Hidden\s+-Exec\sBypass"
```

7. **Identifying PowerShell Downloads with Suspicious User-Agent**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search process_cmdline="*Invoke-WebRequest*"
| search process_cmdline="*UserAgent*"
| search NOT process_cmdline="*UserAgent \"Mozilla*"
```

8. **PowerShell Process Started from Unusual Locations**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search NOT process_path="C:\\Windows\\System32\\powershell.exe"
```

9. **Identifying PowerShell Empire Activity**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process"
| search process_name="powershell.exe" AND process_cmdline="*iex (New-Object*"
```

10. **Detecting PowerShell Obfuscated Scripts**:

```spl
index=your_crowdstrike_falcon_data sourcetype="crowdstrike:json" event_type="process" process_name="powershell.exe"
| search process_cmdline="*powershell*" AND process_cmdline="*-e*"
```

## Contributions

Contributions to this repository are welcome! If you have additional SPL queries or improvements, feel free to open an issue or submit a pull request.

## Disclaimer

Please note that the provided SPL queries are examples for threat hunting and may not cover all possible scenarios or the latest threats. Always review and test the queries in a controlled environment before deploying them in a production environment.


