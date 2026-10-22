"""
monitor_core.py - shared scanning logic for the CLI and the Streamlit UI.
Only masked data (BIN, last4, expiry, hash) is ever returned or stored.
"""
import asyncio
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from telethon import TelegramClient
from telethon.errors import ChannelPrivateError, FloodWaitError
from telethon.tl.functions.messages import CheckChatInviteRequest
from telethon.tl.types import ChatInviteAlready

from card_parser import analyze, debug_sample, has_digit_run, matches_watchlist

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

log = logging.getLogger("card_monitor")

COLUMNS = [
    "Date", "Channel", "MessageLink", "MatchedKeyword", "BIN", "Last4",
    "Expiry", "Expired", "Issuer", "CardType", "Brand", "CardHash",
    "RiskScore", "MITRE",
]
MITRE_TAG = "T1657 - Financial Theft"


def risk_score(expired: bool) -> int:
    # Starting point: unexpired cards are higher risk.
    return 2 if expired else 4


def normalize_channel(ref: str) -> str:
    """name / @name / t.me/name -> 'name'. Private invite links stay as full URLs."""
    ref = ref.strip()
    if re.search(r"t\.me/(\+|joinchat/)", ref):
        return ref if ref.startswith("http") else "https://" + ref
    ref = re.sub(r"^https?://(www\.)?t\.me/", "", ref)
    return ref.lstrip("@").split("/")[0].split("?")[0]


def parse_watchlist(text: str):
    """Split on new lines, commas or semicolons (bank names may contain spaces)."""
    seen, items = set(), []
    for k in re.split(r"[\n,;]+", text or ""):
        k = k.strip()
        if k and k.lower() not in seen:
            seen.add(k.lower())
            items.append(k)
    return items


def parse_channels(text: str):
    """Split on whitespace, new lines or commas."""
    return [c for c in re.split(r"[\s,]+", text or "") if c]


def invite_hash(ref: str):
    """Return the hash of a private invite link (t.me/+HASH or t.me/joinchat/HASH), else None."""
    m = re.search(r"t\.me/(?:\+|joinchat/)([\w-]+)", ref or "")
    return m.group(1) if m else None


def message_link(entity, message_id: int) -> str:
    username = getattr(entity, "username", None)
    if username:
        return f"https://t.me/{username}/{message_id}"
    if getattr(entity, "first_name", None) is not None:  # a user or bot without a public username
        return "Private chat"
    return f"https://t.me/c/{entity.id}/{message_id}"


def _client():
    api_id = os.getenv("TG_API_ID")
    api_hash = os.getenv("TG_API_HASH")
    phone = os.getenv("TG_PHONE")
    if not (api_id and api_hash and phone):
        raise RuntimeError("Set TG_API_ID, TG_API_HASH and TG_PHONE in your .env file.")
    return TelegramClient(os.getenv("TG_SESSION", "monitor_session"), int(api_id), api_hash), phone


async def login():
    """One-time interactive Telegram login (asks for the code in the terminal)."""
    client, phone = _client()
    await client.start(phone=phone)
    await client.disconnect()


async def scan(keywords, days=30, limit=2000, channels=None, on_progress=None,
               interactive_login=True, fast_search=True, include_private=False):
    """
    Scan channels and return (rows, stats).
      keywords : list of BINs / bank names. Empty list = report every valid card.
      days     : look-back window; None or 0 = no date limit.
      limit    : max messages per channel; None or 0 = no limit.
      channels : list of channel links/usernames. Empty = all joined channels/groups.
      include_private : only used when channels is empty; also scans private chats and bots.
      on_progress(name, scanned, found) : optional callback for live status.
      fast_search : True = ask Telegram to search for each keyword (fast, like a normal Telegram search).
                    False = download and read every message (slow but catches everything).
                    Ignored when the watchlist is empty (everything has to be read).
    """
    client, phone = _client()
    cutoff = datetime.now(timezone.utc) - timedelta(days=days) if days else None
    seen_hashes, rows, stats = set(), [], {}

    if interactive_login:
        await client.start(phone=phone)
    else:
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise RuntimeError(
                "Not logged in to Telegram yet. Run: py telegram_card_monitor.py --login-only"
            )

    use_fast = bool(fast_search and keywords)

    async def message_source(entity):
        """Yield messages: Telegram server-side search per keyword (fast) or every message (deep)."""
        if use_fast:
            seen_ids = set()
            for kw in keywords:
                async for msg in client.iter_messages(entity, search=kw, limit=limit or None):
                    if cutoff and msg.date < cutoff:
                        break
                    if msg.id in seen_ids:
                        continue
                    seen_ids.add(msg.id)
                    yield msg
        else:
            async for msg in client.iter_messages(entity, limit=limit or None):
                if cutoff and msg.date < cutoff:
                    break  # newest-first, so everything after is older
                yield msg

    async def scan_entity(entity, name):
        scanned = detected = rejected = found = 0
        oldest = None
        samples = []
        stats[name] = {"scanned": 0, "detected": 0, "rejected": 0, "found": 0,
                       "oldest": "-", "status": "OK", "samples": []}
        try:
            async for msg in message_source(entity):
                scanned += 1
                oldest = msg.date if oldest is None or msg.date < oldest else oldest
                if on_progress and scanned % 50 == 0:
                    on_progress(name, scanned, found)
                if not msg.message:
                    continue
                findings, n_candidates = analyze(msg.message)
                detected += len(findings)
                rejected += max(n_candidates - len(findings), 0)
                if not findings and len(samples) < 5 and has_digit_run(msg.message):
                    samples.append(debug_sample(msg.message))
                for finding in findings:
                    hit = matches_watchlist(finding, msg.message, keywords) if keywords else "(all)"
                    if not hit or finding.card_hash in seen_hashes:
                        continue
                    seen_hashes.add(finding.card_hash)
                    found += 1
                    rows.append([
                        msg.date.strftime("%d-%m-%Y"), name,
                        message_link(entity, msg.id), hit, finding.bin6,
                        finding.last4, finding.expiry, finding.expired,
                        finding.issuer, finding.card_type, finding.brand,
                        finding.card_hash[:16], risk_score(finding.expired), MITRE_TAG,
                    ])
        except ChannelPrivateError:
            stats[name]["status"] = "Private - join the channel first"
        except FloodWaitError as e:
            stats[name]["status"] = f"Rate limited ({e.seconds}s) - partial results"
            await asyncio.sleep(min(e.seconds, 60))
        except Exception as e:
            log.exception("Failed scanning %s", name)
            stats[name]["status"] = f"Error: {e}"
        st = stats[name]
        st.update(scanned=scanned, detected=detected, rejected=rejected, found=found, samples=samples,
                  oldest=oldest.astimezone().strftime("%d-%m-%Y %H:%M") if oldest else "-")
        if not use_fast and limit and scanned >= limit and st["status"] == "OK":
            st["status"] = "OK - message limit reached, older messages NOT scanned"
        if on_progress:
            on_progress(name, scanned, found)

    try:
        if channels:
            for ref in channels:
                ihash = invite_hash(ref)
                if ihash:
                    # Private invite link: only scan it if this account is already a member.
                    label = f"private invite +{ihash[:6]}..."
                    try:
                        res = await client(CheckChatInviteRequest(ihash))
                    except Exception as e:
                        stats[label] = {"scanned": 0, "found": 0, "status": f"Invalid/expired invite: {e}"}
                        continue
                    if isinstance(res, ChatInviteAlready):
                        await scan_entity(res.chat, getattr(res.chat, "title", label))
                    else:
                        stats[label] = {"scanned": 0, "found": 0,
                                        "status": "Not joined - join it in the Telegram app, then rescan"}
                    continue
                handle = normalize_channel(ref)
                if not handle:
                    continue
                try:
                    entity = await client.get_entity(handle)
                except Exception as e:
                    msg = str(e)
                    if "not part of" in msg or "Join the group" in msg:
                        status = "Not joined - join this private channel in Telegram, then rescan"
                    else:
                        status = f"Not found: {msg}"
                    stats[handle] = {"scanned": 0, "found": 0, "status": status}
                    continue
                await scan_entity(entity, getattr(entity, "title", handle))
        else:
            async for dialog in client.iter_dialogs():
                if dialog.is_channel or dialog.is_group or include_private:
                    await scan_entity(dialog.entity, dialog.name)
    finally:
        await client.disconnect()
    return rows, stats
