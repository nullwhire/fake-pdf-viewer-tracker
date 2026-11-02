# Fake 'PDF Viewer' / Remote-Access Agent — IOC Tracker

Hunt: [Fake 'PDF Viewer' page that pushes an Acrobat Reader installer which is really a remote-access agent](https://scanmalware.com/h/333)

Feed: `https://scanmalware.com/api/v1/hunts/f58cdf91-d99c-43a5-854b-e337666756d2/feed.atom`

GitHub Action a correr de hora a hora que lê o feed do ScanMalware, extrai os domínios que deram match
na hunting rule e acumula-os em `data/domains.txt`, com log de cada novo domínio em `data/history.csv`.
Quando aparecem domínios novos, envia alerta para o Telegram (secrets `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID`).

## Estrutura

- `scripts/fetch_iocs.py` — recolhe e processa o feed
- `data/domains.txt` — lista acumulada de domínios (um por linha)
- `data/history.csv` — histórico com timestamp, domínio, entry id e link do resultado
- `.github/workflows/collect.yml` — automação

