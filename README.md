# Conti-Ransomware-Investigation
SOC Analyst Investigation | Conti Ransomware | Splunk Threat Hunting | Sysmon Log Analysis

Conti Ransomware Investigation

Platform: TryHackMe
Category: SOC / Blue Team
Focus: Ransomware Investigation & Threat Hunting
SIEM: Splunk

1. Overview

This project documents my investigation of a Conti ransomware incident in a simulated enterprise environment.

The investigation focuses on analyzing Windows security events, identifying suspicious process execution, investigating file creation activity, and examining IIS logs to identify potential web shell activity.

2. Objectives

- Investigate suspicious process execution.
- Analyze Sysmon Event Logs.
- Identify unusual file creation activity.
- Investigate IIS HTTP POST requests.
- Analyze potential web shell deployment.
- Identify vulnerabilities associated with the attack.

3. Tools & Technologies

- Splunk SIEM
- Sysmon
- Windows Event Logs
- IIS Logs
- Windows Server

4. Investigation Areas

4.1 Process Execution Analysis

Sysmon Event ID 1

Investigating process creation events and analyzing execution paths, command lines, and parent-child process relationships.

4.2 File Creation Analysis

Sysmon Event ID 11

Investigating suspicious file creation events and identifying ransomware-related files.

4.3 IIS Log Analysis

Analyzing HTTP POST requests to ASPX files to investigate potential web shell activity.

4.4 Vulnerability Investigation

Investigating the vulnerabilities associated with the exploitation activity observed during the incident.

5. Splunk Queries

Splunk queries used during the investigation are available in:

"Queries/Splunk-Queries.md"

6. Evidence & Screenshots

Investigation screenshots and supporting evidence will be organized in the "Screenshots" directory.

7. Skills Demonstrated

- SIEM Investigation
- Threat Hunting
- Windows Event Log Analysis
- Sysmon Analysis
- IIS Log Analysis
- Process Investigation
- Ransomware Incident Analysis

8. Disclaimer

This project is for educational purposes and defensive cybersecurity training.

Lab: TryHackMe – Conti
