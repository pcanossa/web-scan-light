import requests
import sys

if len(sys.argv) < 2:
    print("Erro: URL alvo não fornecida.", file=sys.stderr)
    print("Uso: python request.py <URL>", file=sys.stderr)
    sys.exit(1)

url_alvo = sys.argv[1]

try:
    resposta = requests.get(url_alvo)
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
except requests.exceptions.RequestException as e:
    print(f"Erro na conexão: {e}")