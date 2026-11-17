Conti Ransomware Investigation

Platform: TryHackMe
Category: SOC / Blue Team
Focus: Ransomware Investigation & Threat Hunting
SIEM: Splunk

---

1. Overview

This project documents my investigation of a Conti ransomware incident in a simulated enterprise environment.

The investigation involved analyzing Windows Sysmon events, identifying suspicious process execution, investigating persistence techniques, examining process injection, and analyzing IIS logs to identify web shell activity.

2. Investigation Questions & Findings

Q1. Location of the Ransomware

"C:\Users\Administrator\Documents\cmd.exe"


<img width="1920" height="1080" alt="Screenshot (2)" src="https://github.com/user-attachments/assets/08656e50-c703-4579-88a7-e65e5fa625e5" />


Q2. Sysmon Event ID for File Creation

"11"

Q3. Ransomware MD5 Hash

"290c7dfb01e50cea9e19da81a781af2c"

<img width="1920" height="1080" alt="Screenshot (2)" src="https://github.com/user-attachments/assets/6425b1f7-8cd6-4d3c-9ba7-a300e8a1ae92" />


Q4. File Saved in Multiple Folder Locations

"readme.txt"

<img width="1920" height="1080" alt="Screenshot (1)" src="https://github.com/user-attachments/assets/d58fee34-4c82-4019-845d-20fd928e808e" />


Q5. Command Used to Create a New User

net user /add securityninja [REDACTED]

New account identified: "securityninja".

<img width="1920" height="1080" alt="Screenshot (3)" src="https://github.com/user-attachments/assets/6d43c49a-584e-4896-b5a3-a8a95f8e2485" />


Q6. Process Migration Target

C:\Windows\System32\wbem\unsecapp.exe

<img width="1920" height="1080" alt="Screenshot (4)" src="https://github.com/user-attachments/assets/4c83773d-1dd9-41bd-8a7b-57a49b83ae53" />


Q7. Target Process for Retrieving System Hashes

C:\Windows\System32\lsass.exe

<img width="1920" height="1080" alt="Screenshot (4)" src="https://github.com/user-attachments/assets/18472e4b-357c-4ccd-a033-d29636ad9cf7" />


Q8. Deployed Web Shell

i3gfPctK1c2x.aspx

<img width="1920" height="1080" alt="Screenshot (5)" src="https://github.com/user-attachments/assets/bfae5396-8609-4b8f-99b9-580228facadb" />


Q9. Web Shell Execution Command

attrib.exe -r

<img width="1920" height="1080" alt="Screenshot (6)" src="https://github.com/user-attachments/assets/ba7361ab-3203-45fe-b2ad-74dbfff58256" />


The command targeted the Exchange Server OWA authentication directory containing the deployed ASPX web shell.

Q10. Exploited CVEs (Ascending Order)

CVE-2018-13374
CVE-2018-13379
CVE-2020-0796

---

3. Splunk Queries

3.1 Suspicious CMD Execution

Sysmon Event ID 1 – Process Creation

index=* EventCode=1 Image="*\\cmd.exe"
| table _time Image CommandLine Hashes

3.2 Ransomware File Detection

Sysmon Event ID 11 – File Creation

index=* EventCode=11 TargetFilename="*readme.txt*"
| stats count by TargetFilename
| sort -count

3.3 New User Creation Investigation

Sysmon Event ID 1 – Process Creation

index=* EventCode=1 (Image="*\\net.exe" OR Image="*\\net1.exe")
| table _time Image CommandLine

3.4 Process Injection Investigation

Sysmon Event ID 8 – CreateRemoteThread

index=* EventCode=8
| table _time SourceImage TargetImage

3.5 IIS Web Shell Investigation

IIS Logs – HTTP POST Requests

index=* sourcetype=IIS* cs_method=POST cs_uri_stem="*.aspx"
| table _time cs_method cs_uri_stem

3.6 Web Shell Command-Line Investigation

Sysmon Event ID 1 – Process Creation

index=* EventCode=1 CommandLine="*i3gfPctK1c2x.aspx*"
| table _time Image CommandLine

---

4. Tools & Technologies

- Splunk SIEM
- Sysmon
- Windows Event Logs
- IIS Logs
- Windows Server

5. Skills Demonstrated

- SIEM Investigation
- Threat Hunting
- Windows Event Log Analysis
- Process Execution Analysis
- Process Injection Investigation
- Persistence Analysis
- IIS Log Analysis
- Web Shell Investigation
- Ransomware Incident Analysis

6. Conclusion

This investigation provided practical experience in identifying ransomware-related activity, analyzing suspicious processes, investigating persistence mechanisms, detecting process injection, and examining web shell activity using Splunk.

Lab: TryHackMe – Conti

Disclaimer: This project is intended for educational purposes and defensive cybersecurity training.
