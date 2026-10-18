# Dashboard Design & Visualization

## What I practiced

Built a Splunk Firewall Analysis dashboard combining a pie chart of allowed versus blocked traffic with an event detail table. The screenshot shows a dashboard editor view. The visual suggests most observed events were allowed, but no precise ratio is asserted.

## Example SPL

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=5156 OR EventCode=5157 OR EventCode=5158 OR EventCode=5159)
| eval traffic_category=case(in(EventCode,5156,5158),"Allowed",in(EventCode,5157,5159),"Blocked")
| stats count by traffic_category
```

## Lab evidence

![Dashboard Design & Visualization](../screenshots/04-dashboard-design.png)

## SOC relevance

This step helps analysts turn event telemetry into searchable context, identify patterns, and decide what requires deeper investigation. High event volume alone does not establish malicious behavior.
