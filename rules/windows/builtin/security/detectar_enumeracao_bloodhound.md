# Splunk

### Detectar enumeração utilizando bloodhound ou ferramentas similares

```Splunk
index=idx_windows source="XmlWinEventLog:Security" ( EventCode IN (4799, 4798) ) SubjectUserName!=*$ 
| bin span=2m _time 
| stats values(TargetUserName) as TargetUserName dc(TargetUserName) as count by _time CallerProcessName SubjectUserName 
| where count > 2 
| append 
    [| search index=idx_windows source="XmlWinEventLog:Security" EventCode IN (5145) RelativeTargetName IN ("srvsvc", "lsarpc", "samr") SubjectUserName!=*$ 
    | bin span=2m _time 
    | stats count by _time src_ip SubjectUserName 
    | where count > 2] 
| stats values() as * by SubjectUserName 
| eval count = tostring(count) 
| eventstats sum(count) as count 
| eval TargetUserName = mvjoin(TargetUserName, ", ") 
| eval CallerProcessName = mvjoin(CallerProcessName, ", ") 
| fillnull value="NULL"
```

Obs: Os eventos 4799 e 4798 são gerados por padrão em controladores de domínio da versão `Windows Server 2016`, para versões anteriores, utilizamos o evento 5145, que não é vem habilitado por padrão, para habilitá-lo, diretamente no controlador de domínio, acesse `Local Security Policy > Local Policies > Audit Policy > Audit object access Properties` e selecione `Success`

![Screenshot](https://raw.githubusercontent.com/SecurityEveryDay/secday/main/rules/img/AuditObjectAccessSuccess.png)

Obs2: Dependendo do ambiente, 5145 eventos podem gerar milhares de registros, pós qualquer acesso será registrado, para evitar isso você pode criar uma regex para indexar apenas os eventos 5145 que interessam (Se você tem licença e espaço em disco suficiente, é interessante manter o evento para outros casos de uso e forense, essa dica é para evitar custos extras), sugestão de regex:
* `EventID\>5145.+RelativeTargetName\'\>(srvsvc|lsarpc|samr)`

Obs3: Você pode e deve ajustar o `span=2m` e `where count > 3` para o intervalo que faça sentido para o seu ambiente, não envie a regra diretamente para produção, deixe algum tempo na homologação para entender o comportamento normal do seu ambiente.


