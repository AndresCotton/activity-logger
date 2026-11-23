# Activity Logger

A tiny macOS app that logs what's in front of you (app, window title, Chrome tab) to
`~/personal-tools/data/activity-logger/YYYY-MM-DD.jsonl.enc`. Raw data only, for analyzing
later (for example by pasting a week of logs into Claude).

This fork of [Julian-Moncarz/activity-logger](https://github.com/Julian-Moncarz/activity-logger)
adds two things:

- **Logs are encrypted on disk.** Nothing is stored as plain text. Reading them back takes one
  command and Touch ID (or your password).
- **Only one Chrome profile is logged.** Windows of any other profile, and Incognito windows,
  are recorded as "Google Chrome" with no title and no URL.

Nothing leaves your Mac. There is no network code.

## Install

Needs macOS 14+ and the Xcode command line tools (`xcode-select --install`).

```bash
git clone https://github.com/AndresCotton/activity-logger.git
cd activity-logger && ./install.sh
```

The installer creates the encryption key, asks which Chrome profile to log, and starts the
logger (it also starts at login). Then allow **Accessibility** when prompted (for window
titles, which is also how the Chrome profile is recognized), and click OK when asked to let it
control Chrome (for tab URLs).

Uninstall with `./uninstall.sh` (your encrypted logs and their key are kept).

## Reading your logs

```bash
activity-logger export --days 7 --copy
```

Approve with Touch ID, then paste into Claude. Without `--copy` the rows print to the terminal,
so `activity-logger export --days 7 > week.jsonl` writes a plain-text file if you want one
(delete it afterwards). Other ranges are `--from 2026-11-01 --to 2026-11-07` and `--all`.

In Claude Code you can ask Claude to run `activity-logger export --days 7` and analyze the
result. You get the Touch ID prompt, so nothing is decrypted without you. Note that the
decrypted rows then sit in that session's transcript on your Mac.

If `activity-logger` isn't found, use the full path `~/.local/bin/activity-logger`.

## Choosing the Chrome profile

```bash
activity-logger profiles
```

```bash
activity-logger set-profile 2
```

`set-profile` takes the number from the list, the profile's name, its email or its domain
(`set-profile example.org`). `set-profile --all` logs every profile again. Changes apply within
a second, with no restart.

How it works: when you have more than one profile, Chrome ends each window's title with the
profile's name ("Inbox - Google Chrome - Work"). The logger reads that label and only logs a
window whose label belongs to the chosen profile. When it can't tell (no Accessibility
permission, a single-profile Chrome, an unexpected label), it records Chrome without details
instead of guessing.

If your chosen profile shows up as `"private": true` in the logs, run `activity-logger status`.
It lists the labels Chrome is using. Pass the right one with
`activity-logger set-profile --label "<label>"`.

Other browsers are not filtered. Their window titles (which usually contain the page title) are
logged as before.

## How the encryption works

- `setup` creates a key pair. The **public** key goes in `config.json` next to the logs. The
  **private** key goes in your login Keychain as "Activity Logger log decryption key".
- The logger only has the public key, so it can add rows but can't read any back. Each row is
  sealed on its own (HPKE with X25519, HKDF-SHA256 and ChaCha20-Poly1305, from Apple's
  CryptoKit) and written as one base64 line.
- `export` asks for Touch ID or your login password, reads the private key and prints the rows.
  Any other app that tries to read the key gets macOS's own Keychain password prompt.
- After a rebuild (running `./install.sh` again), macOS may ask for your login password the
  first time `export` reads the key. Choose "Always Allow".
- The key is only in this Mac's Keychain. If you erase the Mac or delete the key, the logs
  can't be decrypted.
- `errors.log` in the same folder stays plain text. It only holds notes from the logger
  (Chrome profile names at most), never titles or URLs.

## Output

Each row is a stretch of time where nothing changed: `start`, `end`, `duration_s`,
`status` (`active`, `idle`, `locked`, `asleep`), `app`, `bundle_id`, `window_title`, `url`,
`tab_title`, `private`. Example of exported rows:

```json
{"app":"Google Chrome","bundle_id":"com.google.Chrome","duration_s":42.3,"end":"2026-10-16T09:14:42.300-04:00","private":false,"start":"2026-10-16T09:14:00.000-04:00","status":"active","tab_title":"Hacker News","type":"segment","url":"https://news.ycombinator.com/","window_title":"Hacker News - Google Chrome - Work"}
{"app":"Google Chrome","bundle_id":"com.google.Chrome","duration_s":118.0,"end":"2026-10-16T09:16:40.300-04:00","private":true,"start":"2026-10-16T09:14:42.300-04:00","status":"active","tab_title":null,"type":"segment","url":null,"window_title":null}
{"app":"Notes","bundle_id":"com.apple.Notes","duration_s":300.0,"end":"2026-10-16T09:21:40.300-04:00","private":false,"start":"2026-10-16T09:16:40.300-04:00","status":"idle","tab_title":null,"type":"segment","url":null,"window_title":"Grocery list"}
```

## Tests

`./build.sh && build/ActivityLogger.app/Contents/MacOS/ActivityLogger selftest` checks the
encryption round trip and the profile-label matching.
