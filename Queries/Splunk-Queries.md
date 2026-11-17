Splunk Queries – Conti Ransomware Investigation

This document contains the SPL queries used during the Conti ransomware investigation on TryHackMe.

1. Suspicious CMD Execution

Event ID: 1 – Process Creation

Objective: Identify cmd.exe execution and investigate its execution path and related details.

index=* EventCode=1 Image="*\\cmd.exe"
| table _time Image CommandLine Hashes

2. Ransomware File Detection

Event ID: 11 – File Creation

Objective: Identify readme.txt creation events and investigate files created across multiple folder locations.

index=* EventCode=11 TargetFilename="*readme.txt*"
| stats count by TargetFilename
| sort -count

3. New User Creation Investigation

Event ID: 1 – Process Creation

Objective: Identify suspicious net.exe or net1.exe execution and investigate account creation commands.

index=* EventCode=1 (Image="*\\net.exe" OR Image="*\\net1.exe")
| table _time Image CommandLine

Observed activity:

A new local user named "securityninja" was created using the Windows net user command.

Public documentation should redact the lab password.

4. Process Injection Investigation

Event ID: 8 – CreateRemoteThread

Objective: Investigate process injection activity and identify the source and target processes.

index=* EventCode=8
| table _time SourceImage TargetImage

Observed activity:

The investigation identified process injection targeting LSASS.

5. IIS Web Shell Investigation

Log Source: IIS Logs

Objective: Identify HTTP POST requests targeting ASPX files.

index=* sourcetype=IIS* cs_method=POST cs_uri_stem="*.aspx"
| table _time cs_method cs_uri_stem

6. Web Shell Command-Line Investigation

Event ID: 1 – Process Creation

Objective: Identify the command line associated with the deployed web shell.

index=* EventCode=1 CommandLine="*i3gfPctK1c2x.aspx*"
| table _time Image CommandLine

Investigation Notes

- Sysmon Event ID 1: Process Creation.
- Sysmon Event ID 8: CreateRemoteThread.
- Sysmon Event ID 11: File Creation.
- IIS logs: HTTP POST request analysis.

Lab: TryHackMe – Conti

Focus: SOC Investigation | Threat Hunting | Splunk SIEM
