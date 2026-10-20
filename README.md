# Splunk Security Monitoring & BOTSv3 Investigation

## Project overview
This project demonstrates my hands-on SOC investigation skills using Splunk Enterprise and the BOTSv3 security dataset. I leveraged SPL (Search Processing Language) to analyze Windows, firewall, endpoint, Microsoft 365, and authentication logs, identify suspicious activity, reconstruct attack timelines, and develop security dashboards to strengthen threat detection and incident response capabilities.

## Tools and Technologies 

- Tools and Technologies
- Splunk Enterprise
- Splunk Search & Reporting
- Splunk SPL
- Windows Security Event Logs
- Windows Firewall Logs
- Microsoft 365 / Azure AD Sign-In Logs
- OneDrive and SharePoint Logs
- Boss of the SOC Version 3 (BOTSv3)
- Splunk Reports
- Splunk Dashboards

## 1. Data Ingestion Pipeline

I used **Splunk Enterprise** to ingest, process, and index Windows Security and firewall logs, transforming raw event data into searchable information for monitoring network activity.&#x20;

<img width="1602" height="982" alt="Redacted Splunk Search Dashboard" src="https://github.com/user-attachments/assets/461a7359-a601-49d7-88d1-cf78ff26de41" />


## 2. Custom Field Extractions

I used **Splunk Enterprise** to filter and analyze over **106,000 allowed firewall traffic events** from Windows Security logs. I examined key fields, including source and destination IP addresses, source ports, and event codes (5156 and 5158), to better understand network connections and firewall activity.

<img width="1599" height="984" alt="Redacted Firewall Traffic Dashboard" src="https://github.com/user-attachments/assets/33872368-65f0-488f-bf70-1f3010178d08" />


## 3. Statistical Analysis via SPL

I used SPL to summarize security events and identify activity patterns. Example searches included in the repository demonstrate `stats count`, grouping, sorting, and time-based summaries.

```spl
index=* sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort - count
```

## 4. Firewall Analysis Dashboard

I created a Splunk dashboard called:

Firewall Analysis 

The dashboard included information such as:

- Source IP address
- Source port
- Destination IP address
- Destination port
- Firewall event type
- Computer name
- Event count
- Allowed versus blocked firewall traffic

<img width="1638" height="1128" alt="firewall-analysis-redacted" src="https://github.com/user-attachments/assets/87d848f6-5f85-4827-9003-4602908ab708" />

The dashboard provided a faster way to review firewall activity instead of manually examining individual raw events.


## BOTSv3 Security Investigation

In the second phase of this project, I integrated the **Boss of the SOC Version 3 (BOTSv3) dataset** into Splunk Enterprise to conduct hands-on security investigations and threat hunting using realistic security logs. My analysis primarily focused on: Botsv3 

## Discovering Available Log Sources

Before beginning the investigation, I explored the available sourcetypes.

<img width="1075" height="699" alt="Screenshot 2026-10-18 205209" src="https://github.com/user-attachments/assets/221c8136-3649-4265-92c9-09bd1637afbb" />

One SPL search I used was:

```spl
index=botsv3 earliest=0
```
## Suspicious Dropbox Process Investigation

During the endpoint investigation, I searched for Dropbox-related activity.
index=botsv3 earliest=0 "*Dropbox*"

<img width="1090" height="473" alt="Screenshot 2026-10-18 211033" src="https://github.com/user-attachments/assets/c40d1923-1612-4786-a3b1-06ce66d8d58c" />

During my investigation, I discovered a suspicious instance of **DropboxUpdate.exe** executing from a temporary directory rather than its legitimate installation location, indicating potential unauthorized or malicious activity.
Suspicious Process Path:

C:\Users\BRUCEG~1\AppData\Local\Temp\GUM4F89.tmp\DropboxUpdate.exe


#### Correlating Dropbox Activity with Windows Security Events

I refined my investigation by analyzing Windows Security event logs to identify and correlate activity associated with the suspicious process.

```spl
index=botsv3 sourcetype="WinEventLog:Security" earliest=0 Process_Name="*DropboxUpdate.exe"
| where like(Process_Name, "%Temp%")
| table _time ComputerName Account_Name Process_Name EventCode
```
<img width="1091" height="468" alt="Screenshot 2026-10-18 214820" src="https://github.com/user-attachments/assets/3dcaab3a-6d81-4e76-9154-95636c2ecc66" />

My analysis of Windows Security logs linked the suspicious **DropboxUpdate.exe** process to the following:

- **Endpoint:** `BGIST-L.froth.ly`
- **User Account:** `BruceGist`
- **Process:** `DropboxUpdate.exe`
- **Execution Location:** Temporary directory
- **Windows Event IDs:** `4663` (Object Access) and `4689` (Process Termination)

By correlating these events, I traced the suspicious executable to a specific user account and endpoint, providing valuable context for further threat investigation.

## Windows Event 4663 Investigation

I further investigated Windows Event ID 4663, which logs attempts to access files and other system objects, to identify file access activity potentially associated with the suspicious process.

<img width="1235" height="971" alt="dropbox-event-4663-details" src="https://github.com/user-attachments/assets/59f482e3-4dc0-4442-af20-fdcf9ad9f852" />

The email contained information including:

```text
From: HyunKi Kim <hyunki1984@naver.com>
To: Grace Hoppy
Subject: All your datas belong to us
During my investigation, I detected activity associated with the **DropboxUpdate.exe** process on the **BGIST-L** endpoint.
```
The email contained references to stolen data and mentioned the user **Bruce**, providing additional evidence for the investigation. By analyzing email telemetry in Splunk, I was able to correlate suspicious communications with endpoint and cloud activity, demonstrating the value of multiple log sources in SOC investigations.

## Investigating Suspicious Authentication Activity from Hong Kong

I analyzed Azure Active Directory (Azure AD) sign-in logs to investigate authentication activity originating from Hong Kong and identify potential indicators of suspicious account access.

```text
index=botsv3 sourcetype="ms:aad:signin" location.country="HK"
```
The search returned 27 events.

<img width="1075" height="661" alt="Screenshot 2026-10-18 221926" src="https://github.com/user-attachments/assets/33d42df6-c040-44ae-96be-e83b02170070" />

One of the events showed information including:
```text
ipAddress: 104.207.83.63
location.country: HK
loginStatus: Success
mfaRequired: false
userPrincipalName: fyodor@froth.ly
```
This gave me an important indicator:

```text
104.207.83.63
```
I used the identified IP address to investigate related activity across multiple log sources, helping uncover potential connections and suspicious behavior.

## Account and MFA Analysis

I analyzed the IP address to identify associated user accounts and Microsoft applications, helping uncover potential connections to suspicious authentication activity.

```text
index=botsv3 earliest=0 "104.207.83.63"
| stats count by userPrincipalName, appDisplayName, location.country, mfaRequired
```

<img width="1089" height="520" alt="Screenshot 2026-10-18 222700" src="https://github.com/user-attachments/assets/8dd312d4-8474-47ee-b5ab-828f1618d84c" />

The results showed activity involving accounts including:

```text
bgist@froth.ly
fyodor@froth.ly
```
Applications included:

- Azure Portal
- Microsoft Office 365 Portal
- O365 Suite UX
- Office 365 Exchange Online
- Office 365 SharePoint Online
-  Office365 Shell WCSS-Client
- Skype Web Experience on Office 365

The events also showed:

```text
location.country = HK
mfaRequired = false
```
This allowed me to analyze identity, location, application usage, IP address, and MFA status together.

## SharePoint and Birthday Photo Activity

I used the suspicious IP address to investigate related **Microsoft 365 activity**, identifying potential connections to unauthorized access and suspicious user behavior.

One of the searches used during the investigation was:

```text
index=botsv3 *"104.207.83.63"* SourceFileName="*"
```
This revealed SharePoint and OneDrive activity.

<img width="1094" height="702" alt="Screenshot 2026-10-18 224336" src="https://github.com/user-attachments/assets/82ca83fb-af78-433f-bea2-ee93def5bad4" />


One event contained information including:

```text
ClientIP: 104.207.83.63
EventSource: SharePoint
SourceFileName: morebeer.jpg
SourceRelativeUrl: Documents/Birthday Pictures
UserId: bgist@froth.ly
Workload: OneDrive
```
This connected the investigated IP address with activity involving Bruce Gist's Microsoft 365 files.

I then searched across the BOTSv3 dataset for activity involving the IP address.

```text
index=botsv3 *"104.207.83.63"*
| stats count by ClientIP, UserId, Workload
```
<img width="1103" height="410" alt="Screenshot 2026-10-19 230900" src="https://github.com/user-attachments/assets/bc815aed-814a-4ae3-a88d-5ff1ea3ff6b4" />

The results showed the same IP associated with both:
```text
bgist@froth.ly
fyodor@froth.ly
```
The IP appeared across multiple Microsoft workloads, including:
```text
AzureActiveDirectory
OneDrive
SharePoint
Exchange
```
This was an important correlation step because a single IP address connected multiple user identities and cloud services. 

## Key Takeaways & Skills Gained

This project strengthened my ability to conduct **SOC investigations using Splunk Enterprise**, progressing from broad log searches to focused threat analysis.

I gained hands-on experience in:

- **SPL Analysis:** Used `stats`, `table`, and `where` to filter, summarize, and analyze security events across multiple data sources.
- **Endpoint & Network Security:** Investigated Windows Event IDs, suspicious processes, file activity, IP addresses, and firewall traffic.
- **Cloud Security:** Analyzed Azure AD authentication, MFA, Microsoft 365, OneDrive, and SharePoint activity.
- **Threat Hunting:** Correlated IP addresses, user accounts, processes, and email artifacts to investigate suspicious behavior.
- **Security Visualization:** Reconstructed event timelines, created Splunk reports, and developed security dashboards.

### Biggest Takeaway

**One log entry rarely tells the full story.** By correlating evidence across multiple security sources, I learned how to connect suspicious activities, reconstruct attack timelines, and develop a clearer understanding of potential threats.
