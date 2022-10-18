# Splunk

## Detectar enumeração utilizando ferramentas como bloodhound ou similares

`index=idx_windows source="XmlWinEventLog:Security" ( EventCode IN (4799, 4798) ) SubjectUserName!=*$ 
| bin span=2m _time 
| stats values(TargetUserName) as TargetUserName dc(TargetUserName) as count by _time CallerProcessName SubjectUserName 
| where count > 2 
| append 
    [| search index=idx_windows source="XmlWinEventLog:Security" EventCode IN (5145) RelativeTargetName IN ("srvsvc", "lsarpc", "samr") SubjectUserName!=*$ 
    | bin span=1m _time 
    | stats count by _time src_ip SubjectUserName 
    | where count > 3] 
| stats values() as * by SubjectUserName 
| eval count = tostring(count) 
| eventstats sum(count) as count 
| eval TargetUserName = mvjoin(TargetUserName, ", ") 
| eval CallerProcessName = mvjoin(CallerProcessName, ", ") 
| fillnull value="NULL"`
