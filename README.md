# Threat-Hunting-Sudden-Network-Slowdowns

The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the sucrity team suspects something might be going on internally.

## Activity

Developed a hypothesis based on threat intelligence and security gaps (e.g., “Could there be lateral movement in the network?”).
All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.
### 1. Data Collections
I gathered relevant data from logs, networ traffic, and endpoints by inspecting the logs for excessive successful/failed connections from any devices and if discovered, pibot and inspect those devices for any suspicious file or process events.
At first, I count up failed connections, taking note of any IPs with excessive connections. Based on the query and image below that device names and action types was found failing several connections request against itself and another host on the same network.


| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| failed connections                              | DeviceNetworkEvents<br>\| where ActionType == "ConnectionFailed"<br>\| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP<br>\| order by ConnectionCount

 ![image](https://github.com/user-attachments/assets/5afecac9-c9f2-400e-be79-367c711d9a52)

1.1 From the command below, I investigated the IPs with the highest login failed attempts with focus on the ip in question and in chronological order. I noticed port scanning took place from the outcome of the query due to the sequential order of the port. There were several port scans conducted. Port scanning in this case can be used by attackers to identify network services such as open ports or weak points in a network running and exploit vulnerabilities.

The port scan is obvious as shown in the picture below where the Local Ip is scanning the Remote IP. The ports are in sequential order of well known ports such as http 80, NTP 123, FTP 21 etc.

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| failed connections                              | let IPInQuestion = "10.0.0.5";<br>DeviceNetworkEvents<br>\| where ActionType == "ConnectionFailed"<br>\| where LocalIP == IPInQuestion<br>\| order by Timestamp desc

![image](https://github.com/user-attachments/assets/157e8657-3702-40aa-b11c-08fbea076025)

## 2. Data Analysis
From the query below,I pivoted to the DeviceProcessEvents table to see if we could see anything that was suspicious around the time the port scan started. From the query it shows that the query will scan for 10 minutes before the process began and 10 minutes after.
I noticed a Powershell script named potscan.ps1 launched at 2025-04-06T04:38:39.5050316Z


| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| failed connections                              | let VMName = "tosinvm-ranger1";<br>let specificTime = datetime(2025-04-06T04:38:39.5050316Z);<br>DeviceProcessEvents<br>\| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))<br>\| where DeviceName == VMName<br>\| order by Timestamp desc<br>\| project Timestamp, FileName, InitiatingProcessCommandLine

![image](https://github.com/user-attachments/assets/2d9e5ca8-214d-4c54-91f1-8b89eeb67b7c)

I logged into the suspect computer and observed the powershell script that was used to conduct the port scan from C:\ProgramData

![image](https://github.com/user-attachments/assets/c829fa05-1288-4a25-aad0-eb1d3ad1daf9)

## 3.1 Investigation

During my investigation, I was interested in knowing who ran tha scan on the machine with the help of the script below: Although, I observed the port scan script was launched by the SYSTEM account, this is not expected behaviour and it is not something that was setup by the admin. 

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| failed connections                              | let VMName = "tosinvm-ranger1";<br>let specificTime = datetime(2025-04-06T04:38:39.5050316Z);<br>DeviceProcessEvents<br>\| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))<br>\| where DeviceName == VMName<br>\| where InitiatingProcessCommandLine contains "portscan"<br>\| order by Timestamp desc<br>\| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

![image](https://github.com/user-attachments/assets/d93ce1cd-e1fc-44b4-b941-2f13ab09615d)

This is a call to investigate the user, asking to know why the user ran the powershell script and moreso, I ran an anti malware scan on the system and also isolated the device. 
The malware scan produced no results, so out of caution, we kept the device isolated and put in a ticket through to the IT Support to have it reimaged or rebuilt.

![image](https://github.com/user-attachments/assets/b3735f4b-56ef-4530-9f11-4944ff201dff)

## 3.2  MITRE ATT&CK Framework Related to TTPs:

**Discovery**
- Network Service Scanning (T1046)
- Scan Network (T1040)
  
**Execution**
- PowerShell (T1059.001)
  
**Privilege Escalation**
- Abuse Elevation Control Mechanism (T1548)
  
**Persistence**
- Create or Modify System Process (T1543)
  
**Impact**
- Data Destruction (T1485)
  
**Collection**
- Data from Information Repositories (T1213)
  
**Containment**
- Isolate Network (T1070.004)

