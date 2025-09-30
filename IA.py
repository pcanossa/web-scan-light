from ollama import Client
import subprocess
import sys

if len(sys.argv) < 2:
    print("Erro: Forneça a URL alvo como argumento.", file=sys.stderr)
    print(f"Uso: python {sys.argv[0]} <URL_ALVO>", file=sys.stderr)
    sys.exit(1)

target_url = sys.argv[1]
client = Client()

prompt= """
Analise o seguinte conteúdo e cabeçalho HTTP.
Seu objetivo é retornar um relatório de análise de vulnerabilidades úteis para um pentest. 
O relatório, deve estar na lingua portuguesa (BR).
Forneça um resumo executivo em bullet points destacando:
1. Analisar os **pontos críticos** da **resposta HTTP get** do website alvo. 
2. Analisar os **cabeçalhos HTTP** para **identificar possíveis vulnerabilidades** encontradas. 
3. Fornecer um **relatório detalhado** com as **vulnerabilidades encontradas** e recomendações de mitigação. 4. Responder de **forma concisa e direta**, evitando informações desnecessárias.''
4. Responder de **forma concisa e direta**, evitando informações desnecessárias.

##MODELO DE RESPOSTA##

- **Pontos críticos da resposta HTTP** – Código 200 com conteúdo HTML grande (≈150 KB) e compressão **gzip**. A presença de numerosos scripts de terceiros (Google Tag Manager, DoubleClick, tags.globo.com, etc.) aumenta a superfície de ataque.  
- **Cabeçalhos de segurança insuficientes** – CSP limitada a `upgrade‑insecure‑requests`; ausentes **Strict‑Transport‑Security**, **X‑Frame‑Options**, **Permissions‑Policy**, **Referrer‑Policy** e **Content‑Security‑Policy** com diretivas de origem.  
- **Info leakage** – Headers internos (`X‑Request‑Id`, `X‑Bip`, `X‑Thanos`, `Show‑Page‑Version`, `X‑Served‑From`, `Via`) revelam detalhes de infraestrutura e podem ser usados para fingerprinting ou exploração de vulnerabilidades conhecidas.  
- **Risco de XSS/CSRF** – Scripts de terceiros e ausência de políticas CSP restritivas favorecem injeção de código e cross‑site scripting.  
- **Risco de downgrade / sniffing** – Falta de HSTS permite ataques de força‑bruta de HTTP/HTTPS e de downgrade.  

---

## Relatório Detalhado  

### 1. Análise da Resposta HTTP (Body)  
| Observação | Impacto | Comentário |
|------------|---------|------------|
| **Tamanho do payload (151 KB)** | Médio | Maior consumo de banda e aumento da janela de ataque para compressão (BREACH) caso dados sensíveis sejam refletidos. |
| **Uso de scripts de terceiros** (gpt.js, tags.globo.com, tiqcdn.com, etc.) | Alto | Cada recurso externo pode ser comprometido ou servir como vetor de XSS/supply‑chain. |
| **Presença de variáveis globais (`window.cdaaas`, `window.utag_data`)** | Médio | Se controláveis por parâmetros de query ou cabeçalhos, podem ser manipuladas para injeção de código. |
| **Falta de marcação de CSP no HTML** | Crítico | Sem `script-src`, `style-src`, `object-src` etc., o navegador aceita qualquer origem que o script indique, facilitando XSS. |

### 2. Análise dos Cabeçalhos HTTP  

| Header | Avaliação | Vulnerabilidade / Risco | Recomendação |
|--------|-----------|--------------------------|--------------|
| **Content‑Security‑Policy: upgrade‑insecure‑requests** | Parcial | Não define fontes confiáveis (`default-src`, `script-src`, etc.). Permite execução de scripts de qualquer origem. | Adotar CSP completa com `default-src 'self'`; usar `script-src 'self' 'nonce-<value>'` e `object-src 'none'`. |
| **X‑Content‑Type‑Options: nosniff** | Positivo | Boa prática contra MIME‑sniffing. | Manter. |
| **X‑XSS‑Protection: 1; mode=block** | Obsoleto | Navegadores modernos ignoram; não substitui CSP. | Remover ou complementar com CSP. |
| **Strict‑Transport‑Security (HSTS)** | **Ausente** | Permite downgrade para HTTP e ataques de SSL‑strip. | Incluir `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. |
| **X‑Frame‑Options** | **Ausente** | Possibilidade de click‑jacking (a página pode ser embutida em iframes de sites mal‑iciosos). | Definir `X‑Frame‑Options: SAMEORIGIN` ou `DENY`. |
| **Permissions‑Policy (ex‑Feature‑Policy)** | **Ausente** | Exposição desnecessária de APIs do navegador (geolocation, camera, etc.). | Definir políticas restritivas, ex.: `Permissions-Policy: geolocation=(), microphone=(), camera=()`. |
| **Referrer‑Policy** | **Ausente** | Referer completo pode vazar URLs internas. | Definir `Referrer-Policy: no-referrer-when-downgrade` ou mais restrita (`strict-origin-when-cross-origin`). |
| **Cache‑Control: max-age=10** | Adequado | Curto, mas ainda permite cache temporário. | Mantido. |
| **Expires** | Compatível com Cache‑Control | OK. |
| **X‑Request‑Id, X‑Bip, X‑Thanos, Show‑Page‑Version, X‑Served‑From, Via** | **Informação interna** | Facilita fingerprinting e pode ajudar na enumeração de versões ou componentes vulneráveis. | Remover ou mascarar informações internas; usar cabeçalhos genéricos ou nada. |
| **Content‑Encoding: gzip** | Positivo | Reduz tamanho da resposta; porém pode ser vetado a ataques de compressão (BREACH) se houver reflexão de dados sensíveis. | Desativar gzip para respostas que contenham dados de usuário refletidos ou usar técnicas de mitigação (randomização, limite de tamanho). |
| **Server** (não exibido) | **Possível vazamento** | Caso exista, pode revelar tecnologia/versão. | Remover ou setar para valor genérico (`Server: hidden`). |

### 3. Vulnerabilidades Identificadas  

| Vulnerabilidade | Severidade | Descrição | Exploração provável |
|-----------------|------------|-----------|---------------------|
| **CSP Fraca / Inexistente** | **Crítica** | Apenas `upgrade-insecure-requests`; permite scripts de qualquer origem. | XSS por injeção em parâmetros refletidos ou por comprometimento de recursos de terceiros. |
| **Ausência de HSTS** | **Alta** | Conexões podem ser forçadas a HTTP, permitindo SSL‑strip. | Ataque man‑in‑the‑middle (MITM) em redes não seguras. |
| **Falta de X‑Frame‑Options** | **Alta** | Página pode ser carregada em iframe de site atacante (click‑jacking). | Enganar usuário a clicar em elementos ocultos. |
| **Exposição de headers internos** | **Média** | `X‑Request‑Id`, `X‑Bip`, etc., revelam detalhes da infraestrutura. | Reconhecimento avançado e busca por vulnerabilidades específicas de componentes internos. |
| **Dependência de scripts de terceiros sem SRI** | **Alta** | Bibliotecas carregadas de domínios externos sem Subresource Integrity (SRI). | Comprometimento do CDN ou inserção de código malicioso. |
| **Possível vulnerabilidade BREACH** | **Média** | Resposta gzipada e potencialmente refletindo dados do usuário. | Extrair segredos via compressão se houver parâmetros refletidos. |
| **Headers de segurança obsoletos** (`X‑XSS‑Protection`) | **Baixa** | Não substitui CSP e pode gerar comportamento inesperado em alguns browsers. | Não explorável, mas indica falta de atualização de políticas. |

### 4. Recomendações de Mitigação  

| Área | Ação | Prioridade |
|------|------|------------|
| **Política de CSP** | Implementar CSP completa: `default-src 'self'; script-src 'self' 'nonce-…' https://securepubads.g.doubleclick.net; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'self'; base-uri 'self';` | Alta |
| **HSTS** | Incluir `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` e registrar domínio no preload list. | Alta |
| **Click‑jacking** | Adicionar `X-Frame-Options: SAMEORIGIN` (ou `DENY`). | Alta |
| **Permissions‑Policy** | Definir políticas restritivas para recursos não usados (ex.: `Permissions-Policy: geolocation=(), microphone=(), camera=()` ). | Média |
| **Referrer‑Policy** | Definir `Referrer-Policy: strict-origin-when-cross-origin`. | Média |
| **Remoção/mascaramento de headers internos** | Eliminar ou substituir por valores genéricos: `X-Request-Id`, `X-Bip`, `X-Thanos`, `Show-Page-Version`, `X-Served-From`, `Via`. | Média |
| **Subresource Integrity (SRI)** | Aplicar SRI aos scripts externos (ex.: `<script src="..." integrity="sha384-…" crossorigin="anonymous"></script>`). | Média |
| **Mitigar BREACH** | Evitar refletir dados sensíveis em respostas gzipadas ou usar técnicas de randomização e fragmentação; limitar compressão a conteúdos estáticos. | Média |
| **Server Header** | Remover ou definir como genérico (`Server: hidden`). | Baixa |
| **Atualização de dependências** | Verificar versões de bibliotecas de terceiros (Google Tag Manager, DoubleClick, etc.) e aplicar patches. | Alta |
| **Teste de Penetração Contínuo** | Executar scans regulares (OWASP ZAP, Burp) e auditorias de código front‑end para identificar pontos de injeção. | Contínua |

---  

**Conclusão**
A aplicação apresenta **defesas básicas** (nosniff, X‑XSS‑Protection) porém carece de uma **política de segurança robusta**. A combinação de CSP fraca, ausência de HSTS e headers informativos expõe o site a ataques de XSS, downgrade, click‑jacking e reconnaissance avançado. A implementação das recomendações acima reduz significativamente a superfície de ataque e eleva o nível de segurança do portal.
"""

process = subprocess.run([sys.executable, 'request.py', target_url], capture_output=True, text=True, check=False)

if process.returncode != 0:
    print(f"Erro ao executar request.py:\n{process.stderr}")
    sys.exit(1)

http_content = process.stdout

message = [
    {
        'role': 'system',
        'content': '# Você é um analista de segurança cibernética especializado em testes de penetração e análise de vulnerabilidades. '
    },
    {
        'role': 'user',
        'content': prompt
    },
    {
      'role': 'user',
      'content': http_content
    }
]

for part in client.chat('gpt-oss:120b-cloud', messages=message, stream=True):
  print(part['message']['content'], end='', flush=True)
