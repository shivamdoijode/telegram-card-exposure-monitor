"""
app.py - Streamlit dashboard for the Telegram card exposure monitor.

Run:  py -m streamlit run app.py
First log in once:  py telegram_card_monitor.py --login-only
"""
import asyncio
import time
from datetime import datetime
from html import escape
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from monitor_core import COLUMNS, parse_channels, parse_watchlist, scan
from report import build_report_html, save_outputs

def _default_channels() -> str:
    """Channel list comes from channels.txt (kept out of git), else channels.example.txt."""
    for name in ("channels.txt", "channels.example.txt"):
        path = Path(__file__).parent / name
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    return ""


DEFAULT_CHANNELS = _default_channels()

ACCENT, DANGER, MUTED = "#3b9ddd", "#e4572e", "#7a8b99"

st.set_page_config(page_title="Card Exposure Monitor", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.block-container {padding-top: 1.8rem; max-width: 1450px;}
footer {visibility: hidden;}
.hero {
    padding: 1.7rem 2.1rem; border-radius: 18px; margin-bottom: 1.1rem;
    background: radial-gradient(circle at 85% 20%, rgba(59,157,221,.35), transparent 45%),
                linear-gradient(120deg, #0b1820 0%, #1a3340 55%, #2c5364 100%);
    border: 1px solid rgba(255,255,255,0.08); box-shadow: 0 10px 30px rgba(0,0,0,.25);
}
.hero h1 {margin: 0; font-size: 2.05rem; color: #fff; letter-spacing: .2px;}
.hero p {margin: .45rem 0 0 0; color: #b8c7d1; font-size: .97rem; max-width: 850px;}
.badge {
    display: inline-block; padding: 3px 12px; margin: 10px 8px 0 0; border-radius: 999px;
    font-size: .76rem; background: rgba(255,255,255,0.10); color: #dbe7ee;
    border: 1px solid rgba(255,255,255,0.16);
}
.chip {
    display: inline-block; padding: 4px 13px; margin: 0 8px 10px 0; border-radius: 999px; font-size: .8rem;
    background: rgba(59,157,221,.12); border: 1px solid rgba(59,157,221,.40);
}
.step {
    border: 1px solid rgba(128,128,128,.28); border-radius: 16px; padding: 20px 22px;
    background: rgba(128,128,128,.06); min-height: 150px;
}
.step .n {font-size: 1.7rem; font-weight: 700; color: #3b9ddd;}
.step b {font-size: 1.05rem; display: block; margin: 2px 0 6px 0;}
[data-testid="stMetric"] {
    background: rgba(128,128,128,0.08); border: 1px solid rgba(128,128,128,0.25);
    border-radius: 16px; padding: 16px 20px;
}
[data-testid="stMetricValue"] {font-size: 1.95rem;}
[data-testid="stMetricLabel"] {opacity: .8;}
button[kind="primary"], button[data-testid="stBaseButton-primary"] {
    background: linear-gradient(90deg, #1f8ef1, #00c6a7) !important; border: 0 !important;
    font-weight: 600 !important; border-radius: 12px !important; padding: .55rem 1rem !important;
}
section[data-testid="stSidebar"] {border-right: 1px solid rgba(128,128,128,.22);}
section[data-testid="stSidebar"] details {border-radius: 12px;}
button[data-baseweb="tab"] {font-size: .96rem; padding: 10px 14px;}
</style>
<div class="hero">
  <h1>🛡️ Telegram Card Exposure Monitor</h1>
  <p>Cyber threat intelligence tool that watches Telegram carding channels for exposed payment cards
  linked to your watchlist of BINs and banks, then produces a masked CSV and an analyst report.</p>
  <span class="badge">🔒 Masked data only</span>
  <span class="badge">✅ Luhn validated</span>
  <span class="badge">♻️ Deduplicated</span>
  <span class="badge">⚡ Fast search</span>
  <span class="badge">🧭 MITRE T1657</span>
</div>
""", unsafe_allow_html=True)

# ================================================================= sidebar
with st.sidebar:
    st.markdown("### 🛰️ Scan console")

    with st.expander("📡 Targets", expanded=True):
        channels_text = st.text_area(
            "Channel links, one per line", value=DEFAULT_CHANNELS, height=175,
            help="Only these channels are scanned. Private invite links (t.me/+...) work only if your Telegram "
                 "account has already joined that channel. Leave the box empty to scan everything you have joined.",
        )
        channel_list = parse_channels(channels_text)
        include_private = st.checkbox(
            "Also scan private chats and bots", value=False, disabled=bool(channel_list),
            help="Only available when the channel box is empty. Reads your personal chats and bots too. "
                 "Only masked card matches are saved, never message text.",
        )
        include_private = include_private and not channel_list
        if channel_list:
            st.caption(f"✅ {len(channel_list)} channel(s) will be scanned")
        else:
            st.caption("📭 Box empty: all joined channels and groups"
                       + (" + private chats and bots" if include_private else ""))

    with st.expander("🎯 Watchlist", expanded=True):
        keywords_text = st.text_area(
            "BINs and/or bank names", height=105,
            placeholder="431226\n472670\nMega\nHDFC",
            help="One per line, or separated by commas / semicolons. In fast search use short distinctive words "
                 "(e.g. 'Mega') or BIN prefixes. Leave empty to report every valid card.",
        )
        watchlist = parse_watchlist(keywords_text)
        if watchlist:
            n_bins = sum(k.isdigit() for k in watchlist)
            st.caption(f"✅ {n_bins} BIN(s) · {len(watchlist) - n_bins} bank name(s)")
        else:
            st.caption("No watchlist: every valid card will be reported (deep scan).")

    with st.expander("⏱️ Scope", expanded=True):
        fast = st.checkbox("⚡ Fast search (recommended)", value=True,
                           help="Uses Telegram's own search for each watchlist entry, so only matching messages are "
                                "downloaded. Untick for a slow deep scan that reads every message.")
        window = st.radio("Look back", ["All available history", "Last N days"], horizontal=True)
        days = None
        if window == "Last N days":
            days = st.number_input("Days", min_value=1, max_value=36500, value=365, step=30)
        no_limit = st.checkbox("No message limit", value=False,
                               help="Reading a whole busy channel can take a long time and hit Telegram rate limits.")
        limit = None
        if not no_limit:
            limit = st.number_input("Max messages per channel (per keyword in fast mode)",
                                    min_value=100, max_value=1_000_000, value=10000, step=1000)

    run = st.button("🚀 Run scan", type="primary", use_container_width=True)

# ================================================================= run scan
if run:
    t0 = time.time()
    status = st.status("Scanning Telegram...", expanded=True)
    live = status.empty()

    def on_progress(name, scanned, found):
        live.markdown(f"🔎 **{name}** · {scanned:,} messages read · {found} match(es) · ⏱️ {time.time() - t0:.0f}s")

    try:
        rows, stats = asyncio.run(scan(
            watchlist, days, limit, channel_list, on_progress=on_progress,
            interactive_login=False, fast_search=fast, include_private=include_private,
        ))
    except Exception as e:
        status.update(label="Scan failed", state="error")
        st.error(str(e))
        st.stop()
    status.update(label=f"Scan complete in {time.time() - t0:.0f}s", state="complete", expanded=False)

    if channel_list:
        targets = f"{len(channel_list)} channel(s)"
    else:
        targets = "all joined channels" + (" + private chats" if include_private else "")
    params = {
        "ran_at": datetime.now().strftime("%d-%m-%Y %H:%M"),
        "window": "all available history" if days is None else f"last {days} days",
        "limit": "no limit" if limit is None else f"{limit:,}",
        "watchlist": watchlist, "channels": channel_list,
        "targets": targets, "fast": bool(fast and watchlist),
    }
    report_html = build_report_html(rows, stats, params)
    csv_path, report_path = save_outputs(rows, report_html)
    st.session_state.update(rows=rows, stats=stats, params=params, report_html=report_html,
                            csv_path=csv_path, report_path=report_path)

rows = st.session_state.get("rows")

# ================================================================= empty state
if rows is None:
    c1, c2, c3 = st.columns(3)
    c1.markdown('<div class="step"><div class="n">1</div><b>Pick your targets</b>'
                'Paste the channel links in the sidebar, or leave the box empty to scan every channel you joined.</div>',
                unsafe_allow_html=True)
    c2.markdown('<div class="step"><div class="n">2</div><b>Build your watchlist</b>'
                'Add BINs and bank names. Add as many as you like, one per line.</div>', unsafe_allow_html=True)
    c3.markdown('<div class="step"><div class="n">3</div><b>Run the scan</b>'
                'Get a masked CSV, an analyst report and live charts. Files are saved to the output folder.</div>',
                unsafe_allow_html=True)
    st.caption("First time? Log in to Telegram once with: py telegram_card_monitor.py --login-only")
    st.stop()

# ================================================================= results
stats = st.session_state["stats"]
params = st.session_state["params"]
report_html = st.session_state["report_html"]
df = pd.DataFrame(rows, columns=COLUMNS)
total_scanned = sum(s["scanned"] for s in stats.values())

chips = [f"📡 {params.get('targets', '')}",
         f"🎯 {len(params['watchlist'])} watchlist entr{'y' if len(params['watchlist']) == 1 else 'ies'}"
         if params["watchlist"] else "🎯 no watchlist",
         f"🗓️ {params['window']}",
         "⚡ fast search" if params.get("fast") else "🐢 deep scan",
         f"📨 {total_scanned:,} messages read",
         f"🕒 {params['ran_at']}"]
st.markdown("".join(f'<span class="chip">{escape(c)}</span>' for c in chips), unsafe_allow_html=True)

with st.container(border=True):
    st.markdown(f"💾 **Saved automatically**  \nCSV: `{st.session_state['csv_path']}`  \n"
                f"Report: `{st.session_state['report_path']}`")
    d1, d2, _ = st.columns([1, 1, 3])
    d1.download_button("⬇️ Download CSV", df.to_csv(index=False).encode("utf-8-sig"),
                       "card_findings.csv", "text/csv", use_container_width=True)
    d2.download_button("📄 Download report", report_html.encode("utf-8"),
                       "card_report.html", "text/html", use_container_width=True)

if not df.empty:
    df["_date"] = pd.to_datetime(df["Date"], format="%d-%m-%Y")
    live_n = int((~df["Expired"]).sum())
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Unique cards", f"{len(df):,}")
    m2.metric("Live (unexpired)", f"{live_n:,}", f"{live_n / len(df):.0%} of total", delta_color="off")
    m3.metric("Unique BINs", f"{df['BIN'].nunique():,}")
    m4.metric("Channels with hits", df["Channel"].nunique())
    m5.metric("Latest post", df["_date"].max().strftime("%d-%m-%Y"))
else:
    seen_total = sum(s.get("detected", 0) for s in stats.values())
    if total_scanned == 0:
        st.warning("No messages were read. Open the Channel report tab: channels may not be joined or the search found nothing.")
    elif seen_total == 0:
        st.warning("Messages were read but no valid cards were detected. Open the Channel report tab and check "
                   "'Oldest message scanned' and the masked samples.")
    else:
        st.warning(f"{seen_total:,} valid card(s) were seen but none matched your watchlist. "
                   "Check the spelling of the bank name or the BIN.")

tab_find, tab_an, tab_ch, tab_rep, tab_about = st.tabs(
    ["📋 Findings", "📊 Analytics", "📡 Channel report", "📄 Report preview", "ℹ️ Method"])


def hbar(series, color=ACCENT):
    d = series.rename_axis("label").reset_index(name="cards")
    d.columns = ["label", "cards"]
    return (alt.Chart(d).mark_bar(cornerRadiusEnd=4, color=color)
            .encode(x=alt.X("cards:Q", title=None), y=alt.Y("label:N", sort="-x", title=None),
                    tooltip=["label", "cards"])
            .properties(height=max(150, 30 * len(d))))


# ----------------------------------------------------------------- findings
with tab_find:
    if df.empty:
        st.info("No findings to show.")
    else:
        f1, f2, f3, f4 = st.columns([2, 2, 1.5, 2])
        sel_channels = f1.multiselect("Channel", sorted(df["Channel"].unique()))
        sel_brands = f2.multiselect("Brand", sorted(b for b in df["Brand"].unique() if b != "--"))
        bin_search = f3.text_input("BIN starts with")
        status_pick = f4.radio("Status", ["All", "Live only", "Expired only"], horizontal=True)

        view = df
        if sel_channels:
            view = view[view["Channel"].isin(sel_channels)]
        if sel_brands:
            view = view[view["Brand"].isin(sel_brands)]
        if bin_search:
            view = view[view["BIN"].str.startswith(bin_search.strip())]
        if status_pick == "Live only":
            view = view[~view["Expired"]]
        elif status_pick == "Expired only":
            view = view[view["Expired"]]

        view = view.sort_values("_date", ascending=False).copy()
        view.insert(0, "Status", view["Expired"].map({True: "⚪ Expired", False: "🔴 Live"}))
        shown = ["Status", "Date", "Channel", "BIN", "Last4", "Expiry", "Issuer", "Brand", "CardType",
                 "MatchedKeyword", "RiskScore", "MessageLink", "MITRE", "CardHash"]
        st.write(f"Showing **{len(view):,}** of {len(df):,} findings")
        st.dataframe(
            view[shown], use_container_width=True, hide_index=True,
            column_config={
                "MessageLink": st.column_config.LinkColumn("Source", display_text="Open ↗"),
                "RiskScore": st.column_config.ProgressColumn("Risk", min_value=0, max_value=5, format="%d"),
            },
        )

# ----------------------------------------------------------------- analytics
with tab_an:
    if df.empty:
        st.info("No data to chart.")
    else:
        a1, a2 = st.columns([2, 1])
        with a1:
            st.markdown("##### Findings over time")
            daily = df.groupby("_date").size().reset_index(name="cards").rename(columns={"_date": "date"})
            st.altair_chart(
                alt.Chart(daily).mark_area(line={"color": ACCENT}, color=ACCENT, opacity=0.3)
                .encode(x=alt.X("date:T", title=None), y=alt.Y("cards:Q", title=None),
                        tooltip=[alt.Tooltip("date:T", title="Date"), "cards"])
                .properties(height=260), use_container_width=True)
        with a2:
            st.markdown("##### Live vs expired")
            donut = pd.DataFrame({"status": ["Live (unexpired)", "Expired"],
                                  "cards": [live_n, len(df) - live_n]})
            st.altair_chart(
                alt.Chart(donut).mark_arc(innerRadius=60)
                .encode(theta="cards:Q",
                        color=alt.Color("status:N", legend=alt.Legend(title=None, orient="bottom"),
                                        scale=alt.Scale(domain=["Live (unexpired)", "Expired"],
                                                        range=[DANGER, MUTED])),
                        tooltip=["status", "cards"])
                .properties(height=260), use_container_width=True)

        b1, b2, b3 = st.columns(3)
        with b1:
            st.markdown("##### Top BINs")
            st.altair_chart(hbar(df["BIN"].value_counts().head(10)), use_container_width=True)
        with b2:
            st.markdown("##### Issuers")
            issuers = df[df["Issuer"] != "--"]["Issuer"].value_counts().head(10)
            if issuers.empty:
                st.caption("No issuer names in the messages.")
            else:
                st.altair_chart(hbar(issuers, "#00a98f"), use_container_width=True)
        with b3:
            st.markdown("##### Brands")
            brands = df[df["Brand"] != "--"]["Brand"].value_counts()
            if brands.empty:
                st.caption("No brand info in the messages.")
            else:
                st.altair_chart(hbar(brands, "#8e6bd8"), use_container_width=True)

        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### Hits per channel")
            st.altair_chart(hbar(df["Channel"].value_counts(), "#f0a202"), use_container_width=True)
        with c2:
            st.markdown("##### Expiry year")
            ey = df["Expiry"].str[-4:].value_counts().sort_index().rename_axis("year").reset_index(name="cards")
            st.altair_chart(
                alt.Chart(ey).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, color=ACCENT)
                .encode(x=alt.X("year:N", title=None), y=alt.Y("cards:Q", title=None), tooltip=["year", "cards"])
                .properties(height=max(150, 30 * 5)), use_container_width=True)

# ----------------------------------------------------------------- channel report
with tab_ch:
    st.markdown("##### Per-channel scan summary")
    ch = pd.DataFrame([
        {"Channel": n, "Messages read": s["scanned"], "Oldest message read": s.get("oldest", "-"),
         "Valid cards seen": s.get("detected", 0), "Matched watchlist": s["found"], "Status": s["status"]}
        for n, s in stats.items()])
    st.dataframe(ch, use_container_width=True, hide_index=True)
    st.caption("'Oldest message read' shows how far back the scan reached. Private invite links show 'Not joined' "
               "until your Telegram account joins that channel. In fast search, the counts cover only messages "
               "Telegram returned for your keywords.")
    for n, s in stats.items():
        if s.get("samples"):
            with st.expander(f"🧪 {n}: {len(s['samples'])} message(s) with a card-sized number that did not parse"):
                st.caption("Card numbers and CVVs are masked. This shows the format the parser could not read.")
                for smp in s["samples"]:
                    st.code(smp, language=None)

# ----------------------------------------------------------------- report preview
with tab_rep:
    components.html(report_html, height=900, scrolling=True)

# ----------------------------------------------------------------- method
with tab_about:
    st.markdown("""
**How it works**
1. Reads messages from your selected Telegram channels (or every channel you joined).
2. Fast search asks Telegram to find your keywords. Deep scan reads every message.
3. Extracts card-like patterns and keeps only numbers that pass the **Luhn check**.
4. Matches findings against your watchlist (BIN prefix or bank name).
5. **Masks** every card: only the BIN (6), last 4 digits, expiry and a salted hash are kept. Full numbers and CVVs are never stored.
6. **Deduplicates** reposted cards using the hash.
7. Scores risk (unexpired cards rank higher) and tags findings with MITRE ATT&CK **T1657 - Financial Theft**.
8. Saves a CSV and an HTML report in the `output` folder.

**Ethics and limits**
- Monitoring and reporting only. Cards are never tested, validated against payment systems or used.
- Findings are meant to be passed to the affected bank for card blocking.
- Regex extraction depends on message format, so some cards can be missed.
""")
