"""
report.py - build the CSV + HTML report for a scan.
The report contains masked data only (BIN, last 4, expiry, hash).
Open the HTML in a browser and use Print > Save as PDF if you need a PDF.
"""
import csv
import os
from collections import Counter
from datetime import datetime
from html import escape

from monitor_core import COLUMNS

IDX = {c: i for i, c in enumerate(COLUMNS)}


class _Raw(str):
    """Marks a string that is already safe HTML."""


def _table(headers, body_rows):
    head = "".join(f"<th>{escape(str(h))}</th>" for h in headers)
    body = ""
    for r in body_rows:
        cells = "".join(f"<td>{c if isinstance(c, _Raw) else escape(str(c))}</td>" for c in r)
        body += f"<tr>{cells}</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _date_key(d):  # DD-MM-YYYY -> sortable
    dd, mm, yy = d.split("-")
    return (int(yy), int(mm), int(dd))


def build_report_html(rows, stats, params):
    col = lambda name: [r[IDX[name]] for r in rows]
    total = len(rows)
    unexpired = sum(1 for r in rows if not r[IDX["Expired"]])
    bins = Counter(col("BIN"))
    issuers = Counter(i for i in col("Issuer") if i != "--")
    brands = Counter(b for b in col("Brand") if b != "--")
    chans = Counter(col("Channel"))
    months = Counter(d[3:] for d in col("Date"))
    dates = sorted(col("Date"), key=_date_key)
    scanned = sum(s["scanned"] for s in stats.values())

    # ---- executive summary
    if total:
        summary = (
            f"The scan covered {len(stats)} channel(s) and {scanned:,} messages ({escape(params['window'])}). "
            f"It identified <b>{total:,}</b> unique, Luhn-valid payment cards, of which "
            f"<b>{unexpired:,}</b> are unexpired and therefore higher risk. "
            f"The cards map to <b>{len(bins):,}</b> unique BINs. "
            f"Most active channel: <b>{escape(chans.most_common(1)[0][0])}</b> "
            f"({chans.most_common(1)[0][1]} cards). Most frequent BIN: "
            f"<b>{escape(bins.most_common(1)[0][0])}</b> ({bins.most_common(1)[0][1]} cards). "
            f"Posts range from {dates[0]} to {dates[-1]}."
        )
    else:
        summary = (f"The scan covered {len(stats)} channel(s) and {scanned:,} messages "
                   f"({escape(params['window'])}). No cards matching the watchlist were found.")

    watch = ", ".join(params["watchlist"]) if params["watchlist"] else "None (all valid cards reported)"

    meta = _table(["Item", "Value"], [
        ["Scan date", params["ran_at"]],
        ["Time window", params["window"]],
        ["Message limit per channel", params["limit"]],
        ["Watchlist (BINs / banks)", watch],
        ["Channels scanned", len(stats)],
        ["Messages scanned", f"{scanned:,}"],
    ])

    chan_tbl = _table(["Channel", "Messages scanned", "Oldest message scanned", "Valid cards seen", "Matched watchlist", "Status"],
                      [[n, f"{s['scanned']:,}", s.get("oldest", "-"), s.get("detected", 0), s["found"], s["status"]]
                       for n, s in stats.items()])

    sections = ""
    if total:
        month_rows = sorted(months.items(), key=lambda kv: (int(kv[0][3:]), int(kv[0][:2])))
        sections += "<h2>3. Top BINs</h2>" + _table(["BIN", "Cards"], bins.most_common(15))
        sections += "<h2>4. Issuers and card brands</h2>"
        sections += _table(["Issuer", "Cards"], issuers.most_common(15)) if issuers else "<p>No issuer names found in messages.</p>"
        sections += _table(["Brand", "Cards"], brands.most_common()) if brands else ""
        sections += "<h2>5. Activity by month</h2>" + _table(["Month (MM-YYYY)", "Cards posted"], month_rows)

        shown = sorted(rows, key=lambda r: _date_key(r[IDX["Date"]]), reverse=True)[:500]
        find_rows = [[r[IDX["Date"]], r[IDX["Channel"]], r[IDX["BIN"]], r[IDX["Last4"]], r[IDX["Expiry"]],
                      "Yes" if r[IDX["Expired"]] else "No", r[IDX["Issuer"]], r[IDX["Brand"]],
                      r[IDX["RiskScore"]],
                      _Raw(f'<a href="{escape(r[IDX["MessageLink"]], quote=True)}">open</a>')]
                     for r in shown]
        sections += "<h2>6. Findings (masked)</h2>"
        if total > 500:
            sections += "<p>Showing the 500 most recent findings. The full list is in the CSV.</p>"
        sections += _table(["Date", "Channel", "BIN", "Last 4", "Expiry", "Expired", "Issuer", "Brand", "Risk", "Source"], find_rows)

    top_bins = ", ".join(b for b, _ in bins.most_common(5)) or "n/a"
    recs = [
        "Share the BIN, last 4 digits and expiry of each finding with the affected issuing banks so cards can be blocked or reissued.",
        f"Prioritise the {unexpired:,} unexpired card(s); expired cards carry little immediate fraud risk.",
        f"Highest-frequency BINs to flag to issuers first: {escape(top_bins)}.",
        "Keep monitoring the channels with hits and extend the watchlist with new BINs and bank names.",
        "Record channel names and message links as evidence for takedown or abuse reports.",
    ]
    recs_html = "".join(f"<li>{r}</li>" for r in recs)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Card Exposure Report</title>
<style>
 body {{font-family: Segoe UI, Arial, sans-serif; color:#1b2733; max-width:1000px; margin:30px auto; padding:0 20px; line-height:1.5;}}
 header {{background:linear-gradient(120deg,#0f2027,#2c5364); color:#fff; padding:24px 28px; border-radius:12px;}}
 header h1 {{margin:0 0 4px 0; font-size:26px;}} header p {{margin:0; color:#c5d3dc;}}
 h2 {{margin-top:32px; border-bottom:2px solid #e3e9ee; padding-bottom:6px; color:#203a43;}}
 .cards {{display:flex; gap:12px; margin:18px 0; flex-wrap:wrap;}}
 .card {{flex:1; min-width:150px; background:#f4f7f9; border:1px solid #dde5ea; border-radius:10px; padding:12px 16px;}}
 .card b {{display:block; font-size:26px; color:#203a43;}}
 table {{border-collapse:collapse; width:100%; margin:10px 0; font-size:13px;}}
 th {{background:#203a43; color:#fff; text-align:left; padding:7px 9px;}}
 td {{padding:6px 9px; border-bottom:1px solid #e3e9ee;}}
 tr:nth-child(even) td {{background:#f8fafb;}}
 .note {{font-size:12px; color:#5b6b77; margin-top:30px; border-top:1px solid #e3e9ee; padding-top:10px;}}
 @media print {{ header {{-webkit-print-color-adjust:exact; print-color-adjust:exact;}} }}
</style></head><body>
<header><h1>Telegram Card Exposure Report</h1>
<p>Cyber Threat Intelligence | Generated {escape(params['ran_at'])} | MITRE ATT&amp;CK T1657 - Financial Theft</p></header>

<div class="cards">
 <div class="card"><b>{total:,}</b>Unique cards</div>
 <div class="card"><b>{unexpired:,}</b>Unexpired (high risk)</div>
 <div class="card"><b>{len(bins):,}</b>Unique BINs</div>
 <div class="card"><b>{len(chans)}</b>Channels with hits</div>
</div>

<h2>1. Executive summary</h2><p>{summary}</p>
<h2>2. Scan details</h2>{meta}
<h3>Channel results</h3>{chan_tbl}
{sections}
<h2>7. Recommendations</h2><ul>{recs_html}</ul>

<p class="note">Method: messages were read from the listed Telegram channels, card patterns were extracted and kept only
if they passed the Luhn check, then matched against the watchlist and deduplicated by salted hash. Only the BIN, last 4
digits, expiry and a hash are stored. Full card numbers and CVVs are never saved. Cards are not tested or used; findings
are for reporting to the affected banks. Regex extraction depends on message format, so some cards may be missed.</p>
</body></html>"""


def save_outputs(rows, report_html, out_dir="output"):
    """Write the CSV and the HTML report with a shared timestamp. Returns both paths."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.abspath(os.path.join(out_dir, f"card_findings_{stamp}.csv"))
    html_path = os.path.abspath(os.path.join(out_dir, f"card_report_{stamp}.html"))
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(COLUMNS)
        w.writerows(rows)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(report_html)
    return csv_path, html_path
