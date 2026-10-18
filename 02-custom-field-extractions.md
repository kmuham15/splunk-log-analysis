# Custom Field Extractions

## What I practiced

Explored structured fields within Windows Filtering Platform events, including `Source_Address`, `Destination_Address`, `Source_Port`, `Destination_Port`, and `EventCode`. The screenshot demonstrates field discovery and filtering. A saved custom extraction rule is not independently shown.

## Example SPL

```spl
index=* sourcetype="WinEventLog:Security" (EventCode=5156 OR EventCode=5157 OR EventCode=5158 OR EventCode=5159)
| table _time EventCode Source_Address Source_Port Destination_Address Destination_Port Direction Application_Name
```

## Lab evidence

![Custom Field Extractions](../screenshots/02-custom-field-extractions.png)

## SOC relevance

This step helps analysts turn event telemetry into searchable context, identify patterns, and decide what requires deeper investigation. High event volume alone does not establish malicious behavior.
