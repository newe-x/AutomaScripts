# AutomaScripts

Coleção de scripts para automatizar tarefas do dia a dia — monitoramento, relatórios, integrações e utilitários diversos.

## Estrutura

Cada script fica em sua própria pasta, com o código e, quando necessário, um workflow do GitHub Actions para rodar automaticamente.

```
.
├── dailyvun/
│   ├── vuln_monitor.py
│   └── README.md
├── outro-script/
│   └── ...
└── .github/
    └── workflows/
        ├── vuln-report.yml
        └── ...
```

## Scripts disponíveis

| Script | Descrição | Execução |
|---|---|---|
| [`dailyvun`](./dailyvun) | Busca vulnerabilidades das últimas 24h (NVD + NPM/GitHub Advisory) e envia relatório por email | Diário, 6h (GitHub Actions) |

## Convenções

- **Sem credenciais no código.** Toda credencial (senha, token, chave de API) fica em GitHub Secrets e é lida via variável de ambiente (`os.getenv`).
- **Python 3.12+** como padrão, dependências listadas em `requirements.txt` por script quando houver mais de uma.
- Cada script novo deve ter um README curto explicando o que faz, como configurar e como rodar localmente.

## Rodando localmente

```bash
git clone <repo>
cd <repo>/<nome-do-script>
pip install -r requirements.txt   # se houver
export VAR1="..." VAR2="..."
python3 script.py
```

## Automação (GitHub Actions)

Scripts agendados ficam em `.github/workflows/`. Para configurar os secrets necessários: **Settings → Secrets and variables → Actions** no repositório.
