# Sysmon-Splunk-detection

This repo contains hands-on detection labs using Splunk, Sysmon, and Windows logging.

## Tools Used
- Sysmon (with config)
- Splunk
- Windows VM (via VMware)

## Attack 1 – Suspicious Scheduled Task Creation
**Command used:**

schtasks /create /sc minute /mo 5 /tn "Updater" /tr "calc.exe" 

**Detection Method in Splunk**
index=* CommandLine="*calc.exe*"
![Log Screenshot](Incident-01.png)

## Attack 2 – Suspicious PowerShell Activity**
**Command used:**

-NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'This is a test of suspicious PowerShell activity'"

**Detection Method in Splunk**
index=* EventCode=1 Image="*powershell.exe" NOT Image="*splunk-powershell.exe"
![Log Screenshot](Incident-02.png)
