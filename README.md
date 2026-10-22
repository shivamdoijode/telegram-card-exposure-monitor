# Telegram Card Exposure Monitor

A cyber threat intelligence (CTI) tool that monitors Telegram carding channels for exposed payment cards
linked to a watchlist of **BINs and bank names**, then produces a **masked CSV** and an **analyst report**.

Built with Python, [Telethon](https://docs.telethon.dev) and [Streamlit](https://streamlit.io).

> **Responsible use:** this tool is for defensive monitoring and reporting only. It never tests, validates
> against payment systems, or uses any card. Findings are meant to be passed to the affected issuing bank.

## Features

- **Fast search**: uses Telegram's own search per keyword, so only matching messages are downloaded.
  A deep-scan mode reads every message when you need full coverage.
- **Watchlist**: add many BINs and bank names at once. Bank names are matched ignoring case and punctuation.
- **Targets**: scan a list of channels, or every channel and group you have joined (optionally private chats and bots).
- **Tolerant parser**: handles many bot message formats, odd separators, spaced numbers and fancy Unicode fonts.
- **Luhn validation** discards fake or random numbers.
- **Masking by design**: only the BIN (first 6), last 4 digits, expiry and a salted hash are kept.
  Full card numbers and CVVs are never stored or written to disk.
- **Deduplication** of reposted cards using the salted hash.
- **Outputs**: a CSV and a printable HTML report (executive summary, top BINs, issuers, timeline, recommendations).
- **Dashboard**: filters, charts, per-channel scan diagnostics and report preview.
- **MITRE ATT&CK** tag on findings: T1657 (Financial Theft).

## How it works

```
Telegram channels --> search / read messages --> regex extraction --> Luhn check
      --> watchlist match (BIN or bank) --> mask + hash --> dedupe --> CSV + HTML report
```

| File | Purpose |
|------|---------|
| `app.py` | Streamlit dashboard |
| `monitor_core.py` | Telegram scanning logic (shared by dashboard and CLI) |
| `card_parser.py` | Extraction, Luhn check, masking, watchlist matching |
| `report.py` | CSV and HTML report generation |
| `telegram_card_monitor.py` | Command-line runner |
| `tests/` | Unit tests (public test card numbers only) |

## Setup

Requires Python 3.10+ and a Telegram account.

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
py -m pip install -r requirements.txt        # Windows
# python3 -m pip install -r requirements.txt # macOS / Linux
```

1. Get an `api_id` and `api_hash` at <https://my.telegram.org> > *API development tools*.
2. Copy `.env.example` to `.env` and fill in your values.
3. Copy `channels.example.txt` to `channels.txt` and list the channels to monitor (one link per line).
   Private invite links only work if your account has already joined that channel.
4. Log in once (Telegram sends a code to your app):

```bash
py telegram_card_monitor.py --login-only
```

## Usage

Dashboard:

```bash
py -m streamlit run app.py
```

Command line:

```bash
# fast search for a BIN and a bank name, all history
py telegram_card_monitor.py --keywords "431226; Example Bank" --days 0

# read every message instead of using Telegram search
py telegram_card_monitor.py --keywords "Example Bank" --deep
```

Results are saved to `output/` as `card_findings_<time>.csv` and `card_report_<time>.html`.
Open the HTML report in a browser and use *Print > Save as PDF* if you need a PDF.

## Tests

```bash
python -m unittest discover -s tests
```

## Limitations

- Telegram search matches words, so use short distinctive keywords (for example `Mega`) or BIN prefixes in fast mode.
- Regex extraction depends on message format; unusual formats may be missed. The dashboard shows masked samples
  of messages it could not parse.
- The issuer name comes only from the message text. There is no external BIN lookup yet.
- Full-history scans of very busy channels are slow and can hit Telegram rate limits.

## Roadmap

- BIN lookup enrichment (issuer, country, card type)
- Email or Slack alert when a watchlist hit appears
- Scheduled monitoring runs
- Exportable STIX bundle of findings

## Security and privacy

- Never commit `.env`, `*.session`, `channels.txt` or the `output/` folder. They are listed in `.gitignore`.
- Do not post real findings publicly. Use synthetic data for screenshots and demos.
- Respect Telegram's Terms of Service and the laws that apply to you.

## License

MIT, see [LICENSE](LICENSE).
