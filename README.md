# Web Scan Light - Analisador de Segurança Web com IA 🔍

**Web Scan Light** é uma ferramenta de linha de comando simples, projetada para realizar uma análise de segurança preliminar em websites. A ferramenta utiliza um modelo de linguagem grande (LLM) através do [Ollama](https://ollama.com/) para analisar os cabeçalhos HTTP e o conteúdo inicial de uma página, identificando potenciais vulnerabilidades e más configurações de segurança.

## ⚠️ Disclaimer

**ESTA FERRAMENTA É DESTINADA EXCLUSIVAMENTE PARA FINS EDUCACIONAIS E TESTES DE PENETRAÇÃO AUTORIZADOS.**

- **Uso Ético**: Utilize este script apenas em sistemas e websites para os quais você possui autorização explícita por escrito.
- **Responsabilidade**: O uso não autorizado ou mal-intencionado desta ferramenta é de sua inteira responsabilidade. O desenvolvedor não se responsabiliza por qualquer dano ou consequência legal resultante do uso indevido.

---

## Funcionalidades

- **Análise Automatizada**: Executa uma requisição GET no alvo para coletar cabeçalhos e conteúdo.
- **Integração com IA**: Envia os dados coletados para um modelo de IA local (via Ollama) para uma análise de segurança detalhada.
- **Relatórios em Markdown**: Gera um relatório completo em formato Markdown (`.md`) com as vulnerabilidades encontradas, riscos associados e recomendações de mitigação.
- **Simplicidade**: Fácil de usar, exigindo apenas uma URL como argumento.

## Tecnologias Utilizadas

Este projeto é construído sobre as seguintes tecnologias e ferramentas:

- **Python**: Linguagem de programação principal para a criação dos scripts.
- **Ollama**: Ferramenta que permite executar modelos de linguagem grandes (LLMs) localmente. É o motor que potencializa a análise de IA.
- **gpt-oss:120b-cloud**: O modelo de linguagem utilizado para a análise de segurança. É um modelo robusto, capaz de interpretar os dados HTTP e gerar relatórios detalhados.
- **Requests**: Biblioteca Python para realizar as requisições HTTP de forma simples e eficiente.

## Arquitetura

O fluxo de trabalho da ferramenta é direto:

1.  O script principal `IA.py` é executado com uma URL alvo.
2.  Ele invoca o `request.py`, que realiza uma requisição HTTP GET para a URL.
3.  `request.py` captura os cabeçalhos da resposta e uma porção truncada do corpo HTML.
4.  `IA.py` formata um prompt detalhado, combinando as instruções de análise com os dados coletados.
5.  A requisição é enviada para o modelo de IA configurado no Ollama.
6.  A resposta da IA é exibida em tempo real no console e salva em um arquivo de relatório `.md` (ex: `relatorio_exemplo_com.md`).

## Pré-requisitos

Antes de executar, garanta que você tenha os seguintes componentes instalados e configurados:

1.  **Python 3.x**
2.  **Bibliotecas Python**:
    ```bash
    pip install requests ollama
    ```
3.  **Ollama**:
    - Faça o download e instale o Ollama.
    - Baixe um modelo de linguagem robusto. O modelo `gpt-oss:120b-cloud` foi usado no desenvolvimento, mas outros modelos grandes também podem funcionar.
      ```bash
      ollama pull gpt-oss:120b-cloud
      ```
    - Certifique-se de que o serviço do Ollama esteja em execução antes de rodar o script.

## Como Usar

1.  **Clone o repositório** (ou certifique-se de que todos os arquivos estejam no mesmo diretório).

2.  **Instale as dependências**:
    ```bash
    pip install -r requirements.txt
    ```
    *(Nota: Você pode precisar criar um arquivo `requirements.txt` com `requests` e `ollama`)*

3.  **Execute o script de análise**:
    Passe a URL completa do alvo como um argumento de linha de comando.
    ```bash
    python IA.py https://alvo-autorizado.com
    ```

4.  **Verifique o resultado**:
    A análise será exibida no terminal. Ao final, um arquivo chamado `relatorio_alvo-autorizado_com.md` será criado no mesmo diretório, contendo o relatório completo.

## Exemplo de Saída (Estrutura do Relatório)

O relatório gerado em Markdown seguirá uma estrutura similar a esta:

```markdown
**Resumo Executivo (bullet points)**

- **Pontos críticos da resposta HTTP**: Análise do código de status, tamanho e conteúdo.
- **Cabeçalhos de segurança insuficientes**: Lista de cabeçalhos ausentes ou mal configurados (HSTS, CSP, X-Frame-Options, etc.).
- **Info leakage**: Identificação de cabeçalhos que vazam informações da infraestrutura.

---

## Relatório Detalhado

### 1. Análise da Resposta HTTP (Body)
| Observação | Impacto | Comentário |
|------------|---------|------------|
| ...        | ...     | ...        |

### 2. Análise dos Cabeçalhos HTTP
| Header | Avaliação | Vulnerabilidade / Risco | Recomendação |
|--------|-----------|--------------------------|--------------|
| ...    | ...       | ...                      | ...          |

### 3. Vulnerabilidades Identificadas
| Vulnerabilidade | Severidade | Descrição | Exploração provável |
|-----------------|------------|-----------|---------------------|
| ...             | ...        | ...       | ...                 |

### 4. Recomendações de Mitigação
| Área | Ação | Prioridade |
|------|------|------------|
| ...  | ...  | ...        |
```