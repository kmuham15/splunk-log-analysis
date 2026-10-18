# Splunk Security Monitoring & BOTSv3 Investigation

## Project overview
This project demonstrates hands-on Splunk experience in data ingestion, custom field extraction, SPL statistical analysis, and dashboard visualization to analyze Windows Security logs, monitor firewall activity, and strengthen SOC threat detection capabilities.
## 1. Data Ingestion Pipeline

I explored indexed Windows Security events using Splunk search and examined the available event telemetry. The screenshot shows **118,078 events** returned within the selected time range. This represents the search result volume, not the number of security incidents.

<img width="1602" height="982" alt="Redacted Splunk Search Dashboard" src="https://github.com/user-attachments/assets/461a7359-a601-49d7-88d1-cf78ff26de41" />


## 2. Custom Field Extractions

I investigated the fields available in firewall-related Windows Security events, including `Source_Address`, `Destination_Address`, `Source_Port`, `Destination_Port`, and `EventCode`. The screenshot demonstrates extracted fields in the search interface; it does not independently prove that a custom extraction configuration was saved.

<img width="1599" height="984" alt="Redacted Firewall Traffic Dashboard" src="https://github.com/user-attachments/assets/33872368-65f0-488f-bf70-1f3010178d08" />


## 3. Statistical Analysis via SPL

I practiced using SPL to summarize security events and identify activity patterns. Example searches included in the repository demonstrate `stats count`, grouping, sorting, and time-based summaries.

```spl
index=* sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort - count
```

## 4. Dashboard Design & Visualization

I built a **Firewall Analysis** dashboard featuring a pie chart comparing allowed and blocked firewall activity, together with an event table displaying network fields and traffic direction. This brings event-level investigation and overall activity patterns into one view.

<img width="1638" height="1128" alt="firewall-analysis-redacted" src="https://github.com/user-attachments/assets/87d848f6-5f85-4827-9003-4602908ab708" />

Security Intelligence

## Security Investigation - Bots V3

```text
Windows Security Telemetry
          ↓
      Splunk Index
          ↓
  Field Review / Extraction
          ↓
      SPL Analysis
          ↓
  Statistical Summaries
          ↓
  Dashboard Visualization
          ↓
 Investigation and Context
```


## Key takeaways

- Ingested and searchable logs are the foundation of useful security monitoring.
- Source and destination information gives analysts essential network context.
- Statistical queries help turn high-volume telemetry into understandable patterns.
- Dashboards communicate trends efficiently while retaining event-level detail.
- A high event count or unusual pattern is an investigative lead, **not automatic evidence of an attack**.

## Repository contents

```text
Splunk-SOC-Security-Analytics/
├── README.md
├── chapters/
│   ├── 01-data-ingestion-pipeline.md
│   ├── 02-custom-field-extractions.md
│   ├── 03-statistical-analysis-via-spl.md
│   └── 04-dashboard-design-visualization.md
├── queries/
│   ├── 01-event-volume.spl
│   ├── 02-firewall-event-fields.spl
│   ├── 03-top-source-addresses.spl
│   ├── 04-firewall-traffic-distribution.spl
│   └── 05-hourly-activity.spl
└── screenshots/
    ├── 01-data-ingestion-pipeline.png
    ├── 02-custom-field-extractions.png
    └── 04-dashboard-design.png
```

## About the author

I am a cybersecurity professional and project manager building hands-on skills in **SOC operations, SIEM monitoring, incident response, network security, and cloud security**. This project documents my technical growth through practical Splunk investigation and visualization exercises.

## Privacy and evidence notes

The included screenshots are based on my actual Splunk course environment. Visible computer-name and application-path areas have been blurred before publication. Loopback IP addresses such as `127.0.0.1` are retained because they do not identify a publicly reachable host. I recommend reviewing the final images before publishing additional environment details.

**Educational portfolio project.** No real-world compromise or confirmed malicious incident is claimed.
