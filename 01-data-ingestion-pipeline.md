# Data Ingestion Pipeline

## What I practiced

Reviewed Windows Security events in Splunk and validated that searchable telemetry was available. The screenshot shows a broad `index=*` search with 118,078 events for the selected time window; this is an observed search count, not a claim of distinct threats.

## Example SPL

```spl
index=* sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort - count
```

## Lab evidence

![Data Ingestion Pipeline](../screenshots/01-data-ingestion-pipeline.png)

## SOC relevance

This step helps analysts turn event telemetry into searchable context, identify patterns, and decide what requires deeper investigation. High event volume alone does not establish malicious behavior.
