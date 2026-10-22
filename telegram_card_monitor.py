"""
telegram_card_monitor.py - command-line runner for the Telegram card monitor.

Examples:
  py telegram_card_monitor.py --login-only
  py telegram_card_monitor.py --channels "example_channel_one,example_channel_two" --days 0 --limit 0
  py telegram_card_monitor.py --keywords "457173,Example Bank" --days 30

--days 0 = no date limit.   --limit 0 = no message limit.
Saves a CSV and an HTML report in the output folder.
Config (.env): TG_API_ID, TG_API_HASH, TG_PHONE, CARD_HASH_SALT
"""
import argparse
import asyncio
import logging
from datetime import datetime

from monitor_core import login, parse_channels, parse_watchlist, scan
from report import build_report_html, save_outputs

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def main():
    p = argparse.ArgumentParser(description="Telegram carding-channel monitor (masked output)")
    p.add_argument("--keywords", default="", help="BINs / bank names, comma or semicolon separated (empty = all cards)")
    p.add_argument("--channels", default="", help="Channel links or usernames, comma separated")
    p.add_argument("--days", type=int, default=0, help="Look back N days (0 = no limit, default)")
    p.add_argument("--limit", type=int, default=10000, help="Max messages per channel (0 = no limit)")
    p.add_argument("--out-dir", default="output")
    p.add_argument("--deep", action="store_true", help="Read every message instead of using Telegram search (slow)")
    p.add_argument("--include-private", action="store_true",
                   help="With no --channels: also scan private chats and bots")
    p.add_argument("--login-only", action="store_true", help="Just log in to Telegram and exit")
    args = p.parse_args()

    if args.login_only:
        asyncio.run(login())
        print("Logged in. You can now use the dashboard.")
        return

    keywords = parse_watchlist(args.keywords)
    channels = parse_channels(args.channels)
    rows, stats = asyncio.run(scan(
        keywords, args.days, args.limit, channels, fast_search=not args.deep, include_private=args.include_private,
        on_progress=lambda n, s, f: print(f"  {n}: {s} messages scanned, {f} cards found"),
    ))

    params = {
        "ran_at": datetime.now().strftime("%d-%m-%Y %H:%M"),
        "window": "all available history" if not args.days else f"last {args.days} days",
        "limit": "no limit" if not args.limit else f"{args.limit:,}",
        "watchlist": keywords, "channels": channels,
    }
    csv_path, html_path = save_outputs(rows, build_report_html(rows, stats, params), args.out_dir)
    print(f"Done. {len(rows)} unique findings.\n  CSV:    {csv_path}\n  Report: {html_path}")
    for name, s in stats.items():
        print(f"  {name}: {s['scanned']} scanned, {s['found']} found - {s['status']}")


if __name__ == "__main__":
    main()
