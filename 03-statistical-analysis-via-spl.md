# Statistical Analysis via SPL

## What I practiced

Used SPL aggregation concepts such as `stats count` and sorting to summarize security telemetry by event code, source address, and network activity. The example queries are included as reproducible templates; the supplied screenshots do not display their output.

## Example SPL

```spl
index=* sourcetype="WinEventLog:Security"
| where isnotnull(Source_Address)
| stats count by Source_Address
| sort - count
```

## SOC relevance

This step helps analysts turn event telemetry into searchable context, identify patterns, and decide what requires deeper investigation. High event volume alone does not establish malicious behavior.
