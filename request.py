import requests
import sys

if len(sys.argv) < 2:
    print("Erro: URL alvo não fornecida.", file=sys.stderr)
    print("Uso: python request.py <URL>", file=sys.stderr)
    sys.exit(1)

url_alvo = sys.argv[1]

headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

try:
    resposta = requests.get(url_alvo, headers=headers, timeout=10)
    if resposta.status_code==200:
        print(f"Conexão bem-sucedida! Código de status: {resposta.status_code}")
        print("Conteúdo da resposta:")
        print(resposta.text[:4000],'... (conteúdo truncado)\n')
        headers=resposta.headers
        print("Cabeçalhos da resposta:")
        for chave, valor in headers.items():
            print(f"{chave}: {valor}")
    else:
        print(f"Falha na conexão. Código de status: {resposta.status_code}")
except requests.exceptions.Timeout:
    print("[!] DIAGNÓSTICO: O servidor não respondeu em 10 segundos. O alvo provavelmente está usando uma proteção anti-bot avançada (como um desafio de JavaScript). -> **Reportar erro no relatório, e informar presença de WAF e sistema antibot avançado.** / **Não criar relatório de análise de vulnerabilidades. Apenas reportar proteção anti-bot avançada (como um desafio de JavaScript).**")
except requests.exceptions.RequestException as e:
    print(f"Erro na conexão: {e}")