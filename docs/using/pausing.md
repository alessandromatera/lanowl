# Pausing a device

A device you switched off on purpose (the TV for the summer, the cabin's heater, a camera you
unplugged) should not page you. Taking it out of the inventory loses the way back, and
`expect_offline` is for gear that sleeps every day, not for a holiday. So pause it.

- **Telegram:** `/pause tv`, or several at once: `/pause tv, boiler, garage door`.
- **Dashboard:** the device's sheet, Manage, the **Alerts** switch.

A paused device is still pinged and graphed, so its history stays true, but nothing about it
alerts you: no alert, no problem in the digest, no finding from the owl, no share of a group's
majority. The dashboard shows it as **Paused — no alerts**, and its switch on the device's page is
called **Alerts**.

Pausing closes its open incident without a "back online": it is off on purpose, not fixed.

## Ending a pause

Only by hand: `/resume tv`, `/resume all`, or its **Alerts** switch again. A device that comes
back never decides for you that its alerts are back on. The digests and the weekly review list
every pause ("⏸ Paused, no alerts"), so none is forgotten. `/paused` lists them now, with whether each one answers.

## Every pause is told

Every pause and resume, from Telegram or the dashboard, is said on Telegram. A pause nobody
heard about would be the quietest way to stop lanowl watching the alarm or the cameras.

## Pausing the owl

The model has a switch of its own: `/model off`, or the switch on the Ask tab. Detection and
alerts go on without it ([The model](../setup/model.md)).
