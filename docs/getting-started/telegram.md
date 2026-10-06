# Telegram

Telegram is how lanowl reaches you: alerts, digests, the weekly review, proposals with their
Approve and Reject buttons, and answers to your questions. It uses a bot of its own, which
only talks to your chat.

## Make the bot

In Telegram, open a chat with **@BotFather**, send `/newbot`, and follow its two questions (a
display name, then a username ending in `bot`). BotFather answers with a token like
`123456:ABC-DEF…`.

## Give it to lanowl

On the dashboard, in the first-run setup's **Telegram** step. Later, the same step is in
Settings → Add from the router's list (**Use another bot or chat**); Settings → Secrets
replaces the token alone, and keeps the chat.

1. Paste the token and **Check the token**: lanowl asks Telegram which bot it is and shows its
   name.
2. From the phone you want the alerts on, send `/start` to your bot. The page lists the chat
   that wrote, within seconds (it listens for five minutes).
3. **Use this chat**: the bot says hello there, and the setup's last step writes the token into
   `secrets.yaml` (never shown again) and the chat into `config.yaml` (`telegram.chat_id`).

The settings that go with it, in `config.yaml` (Settings → Telegram):

```yaml
telegram:
  chat_id: "100000001"
  chat:
    enabled: true                 # answer questions and /commands
    allowed_chat_ids: []          # empty: only chat_id
```

### By hand

The token goes in `config/secrets.yaml`:

```yaml
tokens:
  telegram: "123456:ABC-DEF..."
```

or in the environment as `LANOWL_TG_TOKEN` (or `LANOWL_TG_TOKEN_FILE`, a file holding it,
which is how Docker secrets arrive). For the chat id, before lanowl runs: send `/start` to the
bot, open `https://api.telegram.org/bot<token>/getUpdates` in a browser, and find
`"chat":{"id":…`. Once lanowl runs, it reads the bot's updates itself, and a second reader
gets an error instead (lanowl logs it as "another client is polling this bot").

## Who is listened to

Only the chats in `telegram.chat.allowed_chat_ids` (by default, `chat_id` alone) are
answered. A message from anyone else is ignored and logged once per chat; the bot never
replies to strangers, because everything it says comes from your network.

The Approve and Reject buttons are pressed by a person, not a chat. In your private chat with
the bot, your chat id is your user id, so nothing more is needed. **In a group**, anyone in
it could press them: list who may in `telegram.chat.allowed_user_ids`.

## What arrives, and when

| Message | When |
|---|---|
| 🔴 **CRITICAL** | At once, for a device of `criticality: critical`, a whole group gone dark, or the internet. One per incident. |
| 🟢 **RECOVERED** | When it has stayed fine for 15 minutes (`alerts.recovery_confirm_s`), with how long it lasted. |
| ⚪🟡🟠 **lanowl digest** | After the hourly audit, only when something new opened that is not critical, or the owl's reviews found something. Never "all is well". |
| 🛠 **Proposals** | A fix the owl proposes, with Approve and Reject. On the incident's own alert when there is one. |
| 🛡 **Updates and security** | After the morning check, only what is new and matters. |
| 🆕 **New device** | A device never seen on your router's DHCP before: listed when it joins (`discovery.notify_new_devices`), and once more with the owl's reading when it thought it worth a word. |
| 📅 **Week in review** | Sundays at 10:00 (`weekly`). |

How the gate decides what is worth a message: [How alerts work](../using/alerts.md).

## When the internet is down

An alert that cannot leave the network is kept in an outbox (`telegram.outbox_file`, kept
across restarts) and sent, in order, as soon as the internet answers again, marked
"⏳ delayed delivery" with the time it was queued. One about something that has meanwhile
recovered says that too.

## Commands

Send `/help` for the list. The full reference: [Telegram commands](../using/telegram-commands.md).
Anything that is not a command is a question for the owl: [Asking the owl](../using/asking.md).
