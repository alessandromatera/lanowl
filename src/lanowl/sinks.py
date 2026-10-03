"""Output + passive-input sinks.

MqttBridge: publishes lanowl's results to an MQTT broker and passively subscribes to
existing topics (Shelly / alarm / Reolink / HA) to keep a last-seen cache that the model
can read via the `mqtt_last` tool. Subscriptions are read-only. MQTT is optional.

Telegram: lanowl speaks for itself — `telegram_direct` posts to the Bot API from this
process, with a deadline, retries on transient failures, and the outbox behind it for
anything that cannot leave the network right now. Every message is ALSO published to MQTT
(<base_topic>/critical, <base_topic>/digest) for anything else that listens. The one
message lanowl cannot send is "lanowl is down": that is a watchdog's job, on another
machine, reading the retained <base_topic>/heartbeat.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import time
from typing import Optional

log = logging.getLogger("lanowl.sinks")

try:
    import paho.mqtt.client as mqtt  # type: ignore
except Exception:  # pragma: no cover
    mqtt = None


class MqttBridge:
    def __init__(self, cfg: dict):
        self.cfg = cfg.get("mqtt", {})
        self.base = self.cfg.get("base_topic", "lanowl")
        # optional: no broker configured, no MQTT (everything else works without it)
        self.enabled = mqtt is not None and bool(self.cfg.get("host"))
        self.connected = False
        self._last: dict[str, dict] = {}   # topic -> {payload, ts}
        self.client = None
        self.on_command = None             # callable(payload) invoked on <base>/cmd (paho thread)
        self.on_ask = None                 # callable(payload) invoked on <base>/ask (paho thread)

    def start(self):
        if not self.enabled:
            if self.cfg.get("host"):
                log.warning("paho-mqtt not installed; MQTT disabled.")
            else:
                log.info("no mqtt.host configured; MQTT off.")
            return
        try:
            try:
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)  # paho 2.x
            except Exception:
                self.client = mqtt.Client()                                   # paho 1.x
            user = self.cfg.get("username") or ""
            if user:
                self.client.username_pw_set(user, self.cfg.get("password") or "")
            if self.cfg.get("tls"):
                self.client.tls_set()
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_message = self._on_message
            self.client.connect(self.cfg.get("host"),
                                 int(self.cfg.get("port", 1883)), keepalive=60)
            self.client.loop_start()
        except Exception as e:
            log.warning("MQTT connect failed (%s); continuing without MQTT.", e)
            self.enabled = False

    def _on_connect(self, client, userdata, flags, rc, *a):
        self.connected = rc == 0
        log.info("MQTT connected rc=%s", rc)
        subs = list(self.cfg.get("subscribe", []) or [])
        subs.append(f"{self.base}/cmd")     # 'Check now' command topic
        subs.append(f"{self.base}/ask")     # the dashboard's Ask box
        for topic in subs:
            try:
                client.subscribe(topic)
            except Exception as e:
                log.warning("subscribe %s failed: %s", topic, e)

    def _on_disconnect(self, client, userdata, rc, *a):
        self.connected = False
        log.warning("MQTT disconnected rc=%s", rc)

    def healthy(self) -> bool:
        return bool(self.enabled and self.connected)

    def _on_message(self, client, userdata, msg):
        try:
            payload = msg.payload.decode("utf-8", errors="ignore")
        except Exception:
            payload = ""
        if msg.topic == f"{self.base}/cmd":
            if self.on_command:
                try:
                    self.on_command(payload)
                except Exception as e:
                    log.warning("on_command failed: %s", e)
            return
        if msg.topic == f"{self.base}/ask":
            if self.on_ask and not msg.retain:     # a retained question is an old question
                try:
                    self.on_ask(payload)
                except Exception as e:
                    log.warning("on_ask failed: %s", e)
            return
        self._last[msg.topic] = {"payload": payload, "ts": time.time()}

    # --- publish -----------------------------------------------------------
    def publish(self, suffix: str, obj, retain: bool = True, qos: int = 0):
        if not (self.enabled and self.client):
            log.debug("MQTT disabled; would publish %s/%s", self.base, suffix)
            return
        topic = f"{self.base}/{suffix}"
        payload = obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, default=str)
        try:
            self.client.publish(topic, payload, qos=qos, retain=retain)
        except Exception as e:
            log.warning("publish %s failed: %s", topic, e)

    # --- read for the LLM tool --------------------------------------------
    def last(self, pattern: str, max_items: int = 20) -> list[dict]:
        out = []
        for topic, rec in self._last.items():
            if fnmatch.fnmatch(topic, pattern):
                out.append({"topic": topic, "payload": rec["payload"][:200],
                            "age_s": round(time.time() - rec["ts"], 1)})
        out.sort(key=lambda r: r["age_s"])
        return out[:max_items]

    def stop(self):
        if self.client:
            try:
                self.client.loop_stop()
                self.client.disconnect()
            except Exception:
                pass


class TelegramOutbox:
    """Persistent queue for messages that could not be delivered.

    Telegram needs internet: an alert raised during a total outage (e.g. the gap
    between the main link dying and the backup taking over) would otherwise be lost.
    The same queue catches a send that failed after `telegram_direct` gave up
    retrying. Queued messages survive restarts (JSON file) and are flushed as soon
    as a sweep sees the WAN back, marked as delayed and carrying their original
    queue time. A message Telegram itself REJECTS (`TelegramRejected`) is dropped
    with an error in the log rather than left at the head of the queue blocking
    everything behind it."""

    def __init__(self, path: str = "tg_outbox.json", limit: int = 50):
        self.path = os.path.expanduser(path)
        self.limit = limit
        self._items: list = []
        try:
            with open(self.path, "r") as f:
                self._items = json.load(f)[-limit:]
            if self._items:
                log.info("telegram outbox: %d undelivered message(s) from a previous run",
                         len(self._items))
        except FileNotFoundError:
            pass
        except Exception as e:
            log.warning("telegram outbox load failed: %s", e)

    @property
    def pending(self) -> int:
        return len(self._items)

    def _save(self):
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._items, f, ensure_ascii=False)
            os.replace(tmp, self.path)
        except Exception as e:
            log.warning("telegram outbox save failed: %s", e)

    def add(self, text: str, key: str = "", keys=None):
        """`key` is the alert-gate issue key this message is about, when there is one.

        It is what lets `flush` tell the difference between "this is still happening" and
        "this was over before we could speak" — see the banner logic there. `keys` is every
        incident a batched message covers; it is what lets a diagnosis that arrives while
        the message is still queued be added to it (see `annotate`)."""
        self._items.append({"ts": time.time(), "text": text, "key": key,
                            "keys": list(keys or ([key] if key else []))})
        self._items = self._items[-self.limit:]
        self._save()
        log.warning("telegram outbox: message queued for delayed delivery (%d pending)",
                    len(self._items))

    def rekey(self, fn) -> None:
        """A device renamed while its alert waits here (names.py): the queued message
        keeps its incident, under the new key."""
        if not self._items:
            return
        for it in self._items:
            if it.get("key"):
                it["key"] = fn(it["key"])
            it["keys"] = [fn(k) for k in it.get("keys") or []]
        self._save()

    def annotate(self, key: str, note: str) -> bool:
        """Append `note` to a queued message about incident `key`. True if one was found.

        The incident triage finishes a couple of minutes after the alert. If the alert is
        still waiting for the internet to come back, the diagnosis rides along with it
        instead of being edited in afterwards."""
        hit = False
        for it in self._items:
            if key and key in (it.get("keys") or [it.get("key")]) and note not in it["text"]:
                it["text"] = f"{it['text']}{note}"
                hit = True
        if hit:
            self._save()
        return hit

    async def flush(self, cfg: dict, open_keys=None, on_sent=None) -> int:
        """Send oldest-first; stop at the first failure (retried next sweep).

        `open_keys` is the set of incident keys still open at this instant. A queued alert
        whose incident has since closed is not wrong to send — a WAN outage long enough to
        page is worth knowing about after the fact — but it IS wrong to send it in the
        present tense. Everything here was queued precisely because there was no way out of
        the network, so by definition the news is late; when it is also over, the banner says
        so rather than leaving the reader to check whether the internet is currently down."""
        sent = 0
        while self._items:
            it = self._items[0]
            queued = time.strftime("%H:%M:%S", time.localtime(it["ts"]))
            key = it.get("key") or ""
            resolved = bool(key) and open_keys is not None and key not in open_keys
            if resolved:
                banner = (f"<i>⏳ delayed — queued at {queued} while Telegram could not be "
                          f"reached. ✅ It had already recovered by the time this could be sent.</i>")
            else:
                banner = (f"<i>⏳ delayed delivery — queued at {queued} "
                          f"while Telegram could not be reached</i>")
            ids: list = []
            text = f"{it['text']}\n{banner}"
            try:
                ok = await telegram_direct(cfg, text, ids=ids)
            except TelegramRejected as e:
                # Telegram will never accept this one; keeping it would block the queue.
                log.error("telegram outbox: message rejected by Telegram, dropped (%s): %.120s",
                          e, it["text"])
                ok = None
            if ok is False:
                break
            self._items.pop(0)
            self._save()
            if ok:
                sent += 1
                if on_sent is not None and ids:
                    try:
                        on_sent(it.get("keys") or ([key] if key else []), ids[0], text)
                    except Exception as e:
                        log.warning("telegram outbox: on_sent failed: %s", e)
        if sent:
            log.info("telegram outbox: delivered %d delayed message(s), %d still pending",
                     sent, len(self._items))
        return sent


def resolve_tg_token(cfg: dict) -> str:
    """Token from env (LANOWL_TG_TOKEN) first, else from a protected file
    (telegram.token_file, default `.tg_token` in the working dir)."""
    tg = cfg.get("telegram", {})
    tok = os.environ.get(tg.get("bot_token_env", "LANOWL_TG_TOKEN"), "")
    if tok:
        return tok.strip()
    tf = tg.get("token_file", ".tg_token")
    if tf:
        try:
            with open(os.path.expanduser(tf), "r") as f:
                return f.read().strip()
        except Exception:
            pass
    return ""


# Telegram's own limit on one message. Longer text is split on line boundaries.
TG_MAX_LEN = 4096
# Wall-clock deadline on ONE request. A request in flight when a WAN failover changes the
# default route gets no answer at all, and a client with no deadline sits on it — for
# minutes (aiohttp's default is 5; some Telegram clients wait ~15). Anything Telegram has
# not answered in 15s is not going to be answered.
TG_TIMEOUT_S = 15
# ...and a request that timed out is retried, because the route flip that ate it is over
# a second later. 3 attempts spaced 2s/4s apart covers a failover comfortably and still
# finishes inside one sweep interval, so messages cannot overtake each other.
TG_ATTEMPTS = 3
_TRANSPORT_ERRORS: tuple = (asyncio.TimeoutError, OSError)


class TelegramRejected(Exception):
    """Telegram refused the MESSAGE (HTTP 400) — retrying cannot help.

    Everything else that goes wrong is about the path, not the message: a timeout, a
    5xx, a 401 from a bad token, 429 from the rate limiter. Those return False and the
    caller queues the text for later. A 400 is Telegram saying the text itself is
    unacceptable, and the one thing worse than losing that message would be leaving it
    at the head of the outbox where it blocks every message behind it."""


def _split(text: str, limit: int = TG_MAX_LEN) -> list:
    """Cut a long message at line boundaries so no part exceeds Telegram's limit."""
    parts = []
    while len(text) > limit:
        cut = text.rfind("\n", 0, limit)
        if cut < limit // 2:            # one enormous line: cut it mid-way rather than fail
            cut = limit
        parts.append(text[:cut])
        text = text[cut:].lstrip("\n")
    parts.append(text)
    return parts


async def _send_part(session, url: str, chat_id: str, text: str, ids=None,
                     extra: Optional[dict] = None) -> bool:
    """One message, at most TG_ATTEMPTS tries. True = delivered, False = give up for now
    (transient), TelegramRejected = Telegram will never take it.

    `ids`, when given, collects the delivered message's id — what lets a critical be
    edited later to carry its diagnosis without a second notification."""
    import aiohttp
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
               "disable_web_page_preview": True, **(extra or {})}
    attempt = 0
    while attempt < TG_ATTEMPTS:
        attempt += 1
        try:
            async with session.post(url, json=payload) as r:
                status = r.status
                body = "" if (status == 200 and ids is None) else await r.text()
        except _TRANSPORT_ERRORS + (aiohttp.ClientError,) as e:
            log.warning("telegram_direct: %s: %s (attempt %d/%d)",
                        type(e).__name__, str(e) or "no answer within deadline",
                        attempt, TG_ATTEMPTS)
            status, body = None, ""
        if status == 200:
            if ids is not None:
                try:
                    ids.append(int(json.loads(body)["result"]["message_id"]))
                except Exception:
                    pass     # delivered is what matters; an id we cannot read is no edit later
            return True
        if status == 400:
            if "parse_mode" in payload:
                # It is the markup Telegram objects to (an unbalanced <b>, a stray '<' in
                # a device name), not the network. Ugly text on the phone beats no text —
                # and this is not a retry of the same request, so it costs no attempt.
                log.warning("telegram_direct: HTML rejected (%s) — resending as plain text",
                            body[:160])
                payload.pop("parse_mode")
                attempt -= 1
                continue
            raise TelegramRejected(f"HTTP 400: {body[:200]}")
        if status == 429:
            # rate-limited: Telegram says how long to wait
            try:
                wait = float(json.loads(body)["parameters"]["retry_after"])
            except Exception:
                wait = 2.0 * attempt
            log.warning("telegram_direct: rate-limited, retrying in %.0fs", wait)
            await asyncio.sleep(min(wait, 30.0))
            continue
        if status is not None:
            log.warning("telegram_direct: HTTP %s (attempt %d/%d): %s",
                        status, attempt, TG_ATTEMPTS, body[:160])
        if attempt < TG_ATTEMPTS:
            await asyncio.sleep(2.0 * attempt)
    return False


async def telegram_direct(cfg: dict, text: str, ids=None, chat_id: str = "",
                          extra: Optional[dict] = None) -> bool:
    """Send `text` to the configured chat from this process.

    Returns True when every part was delivered, False when the path failed (the caller
    queues the message for the outbox), and raises TelegramRejected when the message
    itself is unacceptable to Telegram. Long text is split at TG_MAX_LEN. `ids` collects
    the message id of each part delivered."""
    import aiohttp
    token = resolve_tg_token(cfg)
    chat_id = chat_id or cfg.get("telegram", {}).get("chat_id", "")
    if not token or not chat_id:
        log.warning("telegram_direct: missing token/chat_id")
        return False
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    timeout = aiohttp.ClientTimeout(total=TG_TIMEOUT_S)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        for part in _split(text):
            if not await _send_part(s, url, chat_id, part, ids=ids, extra=extra):
                return False
    return True


async def telegram_call(cfg: dict, method: str, payload: dict,
                        timeout_s: float = TG_TIMEOUT_S) -> Optional[dict]:
    """One Bot API call, no retries: the decoded reply, or None if the path failed.

    For the calls where a retry buys nothing — an edit that can simply wait for the next
    diagnosis, a 'typing…' indicator, a long poll that is re-issued anyway."""
    import aiohttp
    token = resolve_tg_token(cfg)
    if not token:
        return None
    url = f"https://api.telegram.org/bot{token}/{method}"
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_s)) as s:
            async with s.post(url, json=payload) as r:
                body = await r.text()
        return json.loads(body)
    except _TRANSPORT_ERRORS + (aiohttp.ClientError, ValueError) as e:
        log.debug("telegram %s: %s: %s", method, type(e).__name__, e)
        return None


async def telegram_edit(cfg: dict, message_id: int, text: str,
                        reply_markup: Optional[dict] = None) -> bool:
    """Replace the text of a message this bot already sent. Edits never notify.

    That is the whole point: an alert goes out the moment the sweep confirms it, and the
    model's diagnosis arrives a couple of minutes later. Sent as a second message it would
    buzz the phone twice for one incident; edited into the first, it is simply there the
    next time the message is looked at.

    `reply_markup` replaces the message's buttons (actions.py); an edit WITHOUT it
    removes them, which is what happens to a proposal once it has been answered."""
    chat_id = cfg.get("telegram", {}).get("chat_id", "")
    if not chat_id or not message_id:
        return False
    payload = {"chat_id": chat_id, "message_id": int(message_id), "text": text[:TG_MAX_LEN],
               "parse_mode": "HTML", "disable_web_page_preview": True}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    for attempt in range(2):
        r = await telegram_call(cfg, "editMessageText", payload)
        if r is None:
            return False
        if r.get("ok"):
            return True
        desc = str(r.get("description", ""))
        if "not modified" in desc:
            return True
        if "parse" in desc and "parse_mode" in payload:
            payload.pop("parse_mode")          # same fallback as a send: plain beats nothing
            continue
        log.warning("telegram edit refused: %s", desc[:160])
        return False
    return False


class TelegramPoller:
    """The bot's inbound half: the owner can ASK lanowl things.

    lanowl needs a bot of its own: Telegram allows one long-poller per token (a second one
    gets 409 Conflict), so a bot something else already polls can only be spoken through,
    never listened to.

    Only the configured chat is listened to. The bot is findable by name, and anything it
    answers comes from the network's own data, so every other sender is ignored (logged once
    per chat, never answered). `on_message(text, chat_id)` is awaited for each message in
    order; `persist(offset)` keeps the position across restarts, so a question asked while
    the container was being rebuilt is answered when it comes back, not dropped."""

    def __init__(self, cfg: dict, on_message, persist=None, offset: int = 0,
                 on_callback=None):
        self.cfg = cfg
        t = cfg.get("telegram", {}) or {}
        c = t.get("chat") or {}
        self.enabled = bool(c.get("enabled", False))
        self.allowed = {str(x) for x in (c.get("allowed_chat_ids") or [t.get("chat_id")]) if x}
        # Who may press a button. In the owner's private chat the chat id IS their user id;
        # in a group anybody in it could press, so a group needs this set explicitly.
        self.allowed_users = {str(x) for x in (c.get("allowed_user_ids") or self.allowed) if x}
        # `on_callback(data) -> toast text`: an Approve/Reject button (actions.py)
        self.on_callback = on_callback
        self.poll_timeout = int(c.get("poll_timeout_s", 50))
        self.on_message = on_message
        self.persist = persist
        self.offset = int(offset or 0)
        self._stop = False
        self._ignored: set = set()

    def stop(self):
        self._stop = True

    async def run(self):
        if not self.enabled or not resolve_tg_token(self.cfg):
            log.info("telegram chat disabled (telegram.chat.enabled=false or no token)")
            return
        log.info("telegram chat: listening for questions from chat(s) %s",
                 ", ".join(sorted(self.allowed)))
        backoff = 5.0
        while not self._stop:
            r = await telegram_call(
                self.cfg, "getUpdates",
                {"offset": self.offset, "timeout": self.poll_timeout,
                 "allowed_updates": ["message", "callback_query"]},
                timeout_s=self.poll_timeout + 15)
            if not r or not r.get("ok"):
                # No internet, Telegram down, or a 409 because someone else is polling this
                # token. None of it is urgent: back off and try again, quietly.
                if r and r.get("error_code") == 409:
                    log.warning("telegram chat: another client is polling this bot (409)")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 300.0)
                continue
            backoff = 5.0
            for u in r.get("result") or []:
                self.offset = max(self.offset, int(u.get("update_id", 0)) + 1)
                if self.persist is not None:
                    try:
                        self.persist(self.offset)
                    except Exception:
                        pass
                if u.get("callback_query"):
                    await self._button(u["callback_query"])
                    continue
                m = u.get("message") or {}
                chat = str((m.get("chat") or {}).get("id", ""))
                text = (m.get("text") or "").strip()
                if not chat or not text:
                    continue
                if chat not in self.allowed:
                    if chat not in self._ignored:
                        self._ignored.add(chat)
                        log.warning("telegram chat: ignoring messages from unknown chat %s "
                                    "(@%s)", chat, (m.get("from") or {}).get("username", "?"))
                    continue
                try:
                    await self.on_message(text, chat)
                except Exception:
                    log.exception("telegram chat: handling %r failed", text[:60])

    async def _button(self, cq: dict):
        """A button pressed under one of our messages. Answered always — an unanswered
        callback leaves the button spinning on the phone — but acted on only when it came
        from the owner, in the owner's chat."""
        chat = str(((cq.get("message") or {}).get("chat") or {}).get("id", ""))
        user = str((cq.get("from") or {}).get("id", ""))
        text = "Not allowed."
        if chat in self.allowed and user in self.allowed_users and self.on_callback is not None:
            try:
                text = await self.on_callback(str(cq.get("data") or ""))
            except Exception:
                log.exception("telegram chat: button %r failed", str(cq.get("data"))[:40])
                text = "That did not work — see lanowl's log."
        else:
            log.warning("telegram chat: ignoring a button from chat %s user %s", chat, user)
        await telegram_call(self.cfg, "answerCallbackQuery",
                            {"callback_query_id": cq.get("id"), "text": str(text)[:190]},
                            timeout_s=10)
