import Cocoa
import CryptoKit

// Command-line side of the app: setup, choosing the Chrome profile, and reading logs back.
// Running the binary with no arguments starts the logger itself (see main.swift).

func say(_ s: String) { FileHandle.standardOutput.write(Data((s + "\n").utf8)) }
func warn(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }
func fail(_ s: String) -> Never { warn(s); exit(1) }

let usage = """
Activity Logger

  activity-logger export [--days N | --from YYYY-MM-DD [--to YYYY-MM-DD] | --all] [--copy]
      Decrypt logs and print them (default: the last 7 days). Asks for Touch ID or your
      password first. --copy puts them on the clipboard instead, ready to paste into Claude.
  activity-logger profiles
      List this Mac's Chrome profiles.
  activity-logger set-profile <number | name | email | domain>
      Log only that Chrome profile. Other profiles and Incognito are recorded as
      "Google Chrome" with no title or URL.
  activity-logger set-profile --label "<label>"
      Same, by the exact label Chrome shows at the end of that profile's window titles.
  activity-logger set-profile --all
      Log every Chrome profile.
  activity-logger status
      Show the current setup and any recent problems.
  activity-logger setup
      Create the encryption key, choose a Chrome profile, encrypt any old plain-text logs.
"""

func runCLI(_ args: [String]) -> Never {
    let rest = Array(args.dropFirst())
    switch args[0] {
    case "setup": cmdSetup()
    case "profiles": cmdProfiles()
    case "set-profile": cmdSetProfile(rest)
    case "export": cmdExport(rest)
    case "migrate": cmdMigrate()
    case "status": cmdStatus()
    case "selftest": cmdSelfTest()
    case "help", "-h", "--help": say(usage)
    default: warn(usage); exit(2)
    }
    exit(0)
}

// MARK: - Key

/// Makes sure a key pair exists: private half in the Keychain, public half in config.json.
func ensureKey() {
    var cfg = LoggerConfig.load()
    do {
        if let priv = try KeyStore.load() {
            let pub = priv.publicKey.rawRepresentation.base64EncodedString()
            if cfg.publicKey != pub {
                if cfg.publicKey != nil {
                    warn("Note: config.json named a different key than the one in your Keychain. Using the Keychain's.")
                }
                cfg.publicKey = pub
                try cfg.save()
            }
            say("Encryption key: already in your Keychain.")
            return
        }
        let priv = Curve25519.KeyAgreement.PrivateKey()
        try KeyStore.save(priv)
        if cfg.publicKey != nil {
            warn("Note: the old key is gone from your Keychain, so logs written before now can't be decrypted.")
        }
        cfg.publicKey = priv.publicKey.rawRepresentation.base64EncodedString()
        try cfg.save()
        say("Encryption key: created and saved in your Keychain (\"Activity Logger log decryption key\").")
    } catch {
        fail("Couldn't set up the encryption key: \(error)")
    }
}

// MARK: - Chrome profile

func printProfiles(_ profiles: [ChromeProfile]) {
    for (i, p) in profiles.enumerated() { say("  \(i + 1)) \(p.display)") }
}

func cmdProfiles() {
    let profiles = loadChromeProfiles()
    if profiles.isEmpty { fail("No Chrome profiles found on this Mac.") }
    printProfiles(profiles)
    let cfg = LoggerConfig.load()
    say(cfg.chromeProfileLabels == nil ? "Currently logging: every profile."
        : "Currently logging only: \(cfg.chromeProfile ?? "?")")
}

func applyProfile(_ p: ChromeProfile, among all: [ChromeProfile]) {
    let labels = uniqueLabels(for: p, among: all)
    if labels.isEmpty {
        fail("\"\(p.display)\" can't be told apart from another profile by name. Rename it in Chrome (Settings > You and Google > Customize your Chrome profile) and try again.")
    }
    var cfg = LoggerConfig.load()
    cfg.chromeProfile = p.display
    cfg.chromeProfileLabels = labels
    do { try cfg.save() } catch { fail("Couldn't save config.json: \(error)") }
    say("Chrome: logging only \(p.display). Other profiles and Incognito are recorded without titles or URLs.")
    if all.count < 2 {
        warn("Note: Chrome only labels its windows when there is more than one profile. With a single profile, every Chrome window is recorded without details.")
    }
}

func cmdSetProfile(_ args: [String]) {
    guard let first = args.first else { fail("Say which profile. Run `activity-logger profiles` to list them.") }
    var cfg = LoggerConfig.load()
    if first == "--all" {
        cfg.chromeProfile = nil
        cfg.chromeProfileLabels = nil
        do { try cfg.save() } catch { fail("Couldn't save config.json: \(error)") }
        say("Chrome: logging every profile.")
        return
    }
    if first == "--label" {
        let labels = Array(args.dropFirst()).filter { $0 != "--label" && !$0.isEmpty }
        if labels.isEmpty { fail("Give the label, for example: activity-logger set-profile --label \"Work\"") }
        cfg.chromeProfile = labels[0]
        cfg.chromeProfileLabels = labels
        do { try cfg.save() } catch { fail("Couldn't save config.json: \(error)") }
        say("Chrome: logging only windows labelled \(labels.joined(separator: " or ")).")
        return
    }
    let profiles = loadChromeProfiles()
    let query = args.joined(separator: " ")
    if let n = Int(query), n >= 1, n <= profiles.count {
        applyProfile(profiles[n - 1], among: profiles)
        return
    }
    let q = query.lowercased()
    let hits = profiles.filter {
        [$0.directory, $0.name, $0.email, $0.domain].contains { !$0.isEmpty && $0.lowercased() == q }
    }
    if hits.count == 1 { applyProfile(hits[0], among: profiles); return }
    warn(hits.isEmpty ? "No Chrome profile matches \"\(query)\". The profiles are:" : "More than one profile matches \"\(query)\":")
    printProfiles(hits.isEmpty ? profiles : hits)
    exit(1)
}

// MARK: - Setup

func cmdSetup() {
    Paths.ensureLogDir()
    ensureKey()
    let cfg = LoggerConfig.load()
    if let name = cfg.chromeProfile, cfg.chromeProfileLabels != nil {
        say("Chrome: logging only \(name). Change it with `activity-logger set-profile`.")
    } else {
        let profiles = loadChromeProfiles()
        if profiles.count > 1 && isatty(STDIN_FILENO) != 0 {
            say("\nWhich Chrome profile should be logged?")
            say("  0) every profile")
            printProfiles(profiles)
            FileHandle.standardOutput.write(Data("Number: ".utf8))
            let answer = (readLine() ?? "").trimmingCharacters(in: .whitespaces)
            if let n = Int(answer), n >= 1, n <= profiles.count {
                applyProfile(profiles[n - 1], among: profiles)
            } else {
                say("Chrome: logging every profile. Change it with `activity-logger set-profile`.")
            }
        } else {
            say("Chrome: logging every profile. Change it with `activity-logger set-profile`.")
        }
    }
    cmdMigrate()
}

// MARK: - Files

struct DayFile {
    let day: String
    let url: URL
}

func dayFiles(in dir: URL, suffix: String) -> [DayFile] {
    let names = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
    return names.filter { $0.hasSuffix(suffix) && $0.count == 10 + suffix.count }
        .sorted()
        .map { DayFile(day: String($0.prefix(10)), url: dir.appendingPathComponent($0)) }
}

/// Appends one sealed row to a day's file, creating it (owner-only) if needed.
func appendEncryptedRow(_ row: Data, to file: URL, key: Curve25519.KeyAgreement.PublicKey) throws {
    var line = try LogCrypto.encryptLine(row, to: key)
    line.append(0x0A)
    let fm = FileManager.default
    if !fm.fileExists(atPath: file.path) {
        fm.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600])
    }
    let handle = try FileHandle(forWritingTo: file)
    defer { try? handle.close() }
    handle.seekToEndOfFile()
    handle.write(line)
}

/// Decrypts every row of the given files. Returns plain JSONL and the number of unreadable rows.
func decryptFiles(_ files: [DayFile], key: Curve25519.KeyAgreement.PrivateKey) -> (Data, Int) {
    var out = Data()
    var bad = 0
    for f in files {
        guard let data = try? Data(contentsOf: f.url) else { continue }
        for line in data.split(separator: 0x0A) where !line.isEmpty {
            if let row = try? LogCrypto.decryptLine(Data(line), with: key) {
                out.append(row)
                out.append(0x0A)
            } else {
                bad += 1
            }
        }
    }
    return (out, bad)
}

// MARK: - Export

func cmdExport(_ args: [String]) {
    var days = 7
    var from: String?
    var to: String?
    var all = false
    var copy = false
    var i = 0
    func value() -> String {
        i += 1
        guard i < args.count else { fail("\(args[i - 1]) needs a value.") }
        return args[i]
    }
    while i < args.count {
        switch args[i] {
        case "--days":
            guard let n = Int(value()), n >= 1 else { fail("--days needs a whole number, like --days 7.") }
            days = n
        case "--from": from = value()
        case "--to": to = value()
        case "--all": all = true
        case "--copy": copy = true
        default: fail("Unknown option \(args[i]).\n\n\(usage)")
        }
        i += 1
    }
    let today = dayFormatter.string(from: Date())
    if !all && from == nil {
        let start = Calendar.current.date(byAdding: .day, value: -(days - 1), to: Date()) ?? Date()
        from = dayFormatter.string(from: start)
    }
    let files = dayFiles(in: Paths.logDir, suffix: Paths.encryptedSuffix).filter {
        (from == nil || $0.day >= from!) && $0.day <= (to ?? today)
    }
    if files.isEmpty { fail("No logs in that range in \(Paths.logDir.path).") }

    guard KeyStore.isThrowaway || confirmUserPresence(reason: "decrypt your activity logs (\(files.first!.day) to \(files.last!.day))") else {
        fail("Not decrypted.")
    }
    let key: Curve25519.KeyAgreement.PrivateKey
    do {
        guard let k = try KeyStore.load() else { fail("The decryption key isn't in your Keychain.") }
        key = k
    } catch { fail("Couldn't read the decryption key: \(error)") }

    let (data, bad) = decryptFiles(files, key: key)
    if bad > 0 { warn("\(bad) row(s) couldn't be decrypted and were skipped.") }
    if copy {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(String(decoding: data, as: UTF8.self), forType: .string)
        let rows = data.split(separator: 0x0A).count
        say("Copied \(rows) rows (\(files.first!.day) to \(files.last!.day)) to the clipboard. Paste them into Claude.")
    } else {
        FileHandle.standardOutput.write(data)
    }
}

// MARK: - Migrate

/// Encrypts any plain-text day files left by the original logger, then deletes them.
func cmdMigrate() {
    let plain = dayFiles(in: Paths.logDir, suffix: Paths.plainSuffix)
    if plain.isEmpty { return }
    guard let b64 = LoggerConfig.load().publicKey, let key = LogCrypto.publicKey(base64: b64) else {
        fail("No encryption key yet. Run `activity-logger setup` first.")
    }
    for f in plain {
        guard let data = try? Data(contentsOf: f.url) else { continue }
        let target = Paths.logDir.appendingPathComponent(f.day + Paths.encryptedSuffix)
        let existing = (try? Data(contentsOf: target)) ?? Data()
        var out = Data()
        do {
            for line in data.split(separator: 0x0A) where !line.isEmpty {
                out.append(try LogCrypto.encryptLine(Data(line), to: key))
                out.append(0x0A)
            }
            out.append(existing)   // older rows first, anything already encrypted after
            try out.write(to: target, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
            try FileManager.default.removeItem(at: f.url)
        } catch {
            fail("Couldn't encrypt \(f.url.lastPathComponent): \(error). It was left as it is.")
        }
    }
    say("Encrypted \(plain.count) plain-text log file(s) and removed the originals.")
}

// MARK: - Status

func cmdStatus() {
    let cfg = LoggerConfig.load()
    say("Log folder: \(Paths.logDir.path)")
    let pub = cfg.publicKey.flatMap { LogCrypto.publicKey(base64: $0) }
    var keyLine = pub == nil ? "NOT SET UP (nothing is being logged). Run `activity-logger setup`." : "on"
    if pub != nil {
        if let priv = try? KeyStore.load() {
            if priv.publicKey.rawRepresentation != pub!.rawRepresentation {
                keyLine = "on, but the Keychain key doesn't match config.json. Run `activity-logger setup`."
            }
        } else {
            keyLine = "on, but the decryption key is missing from your Keychain, so logs can't be read back."
        }
    }
    say("Encryption: \(keyLine)")
    if let labels = cfg.chromeProfileLabels {
        say("Chrome: only \(cfg.chromeProfile ?? "?") (window labels: \(labels.joined(separator: ", ")))")
    } else {
        say("Chrome: every profile")
    }
    let enc = dayFiles(in: Paths.logDir, suffix: Paths.encryptedSuffix)
    say("Encrypted days: \(enc.count)" + (enc.isEmpty ? "" : " (\(enc.first!.day) to \(enc.last!.day))"))
    let plain = dayFiles(in: Paths.logDir, suffix: Paths.plainSuffix)
    if !plain.isEmpty { say("Plain-text days still on disk: \(plain.count). Run `activity-logger setup` to encrypt them.") }
    let errors = Paths.logDir.appendingPathComponent("errors.log")
    if let text = try? String(contentsOf: errors, encoding: .utf8) {
        let lines = text.split(separator: "\n").suffix(8)
        if !lines.isEmpty {
            say("Recent notes from the logger:")
            lines.forEach { say("  \($0)") }
        }
    }
}

// MARK: - Self-test

func cmdSelfTest() {
    var failures = 0
    func check(_ ok: Bool, _ what: String) {
        say((ok ? "ok    " : "FAIL  ") + what)
        if !ok { failures += 1 }
    }

    // Window title parsing
    check(chromeProfileLabel(fromWindowTitle: "Inbox - Google Chrome - Work") == "Work", "label after the page title")
    check(chromeProfileLabel(fromWindowTitle: "Inbox - Google Chrome") == "", "no label with a single profile")
    check(chromeProfileLabel(fromWindowTitle: "Inbox") == nil, "no marker gives nil")
    check(chromeProfileLabel(fromWindowTitle: "x - Google Chrome - Work - Google Chrome - Home") == "Home",
          "a page can't fake a label in its title")
    check(chromeProfileLabel(fromWindowTitle: "a - b - Google Chrome - Ana (work.org)") == "Ana (work.org)", "label with brackets")
    check(chromeProfileLabel(fromWindowTitle: "x - Google Chromecast help") == nil, "marker must be followed by a label")

    // Labels that tell profiles apart
    let home = ChromeProfile(directory: "Profile 1", name: "Andrés", givenName: "Andrés", fullName: "Andrés C",
                             email: "a@example.com", enterpriseLabel: "")
    let work = ChromeProfile(directory: "Profile 2", name: "work.org", givenName: "Andres", fullName: "Andres C",
                             email: "a@work.org", enterpriseLabel: "")
    let twin = ChromeProfile(directory: "Profile 3", name: "Andrés", givenName: "", fullName: "", email: "", enterpriseLabel: "")
    let w = uniqueLabels(for: work, among: [home, work])
    check(w.contains("Andres (work.org)") && w.contains("work.org") && w.contains("Andres"), "work profile labels")
    check(!w.contains("Andrés"), "accented and unaccented names stay distinct")
    check(!uniqueLabels(for: home, among: [home, twin]).contains("Andrés"), "a label shared with another profile is dropped")

    // Row encryption
    do {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        let other = Curve25519.KeyAgreement.PrivateKey()
        let row = Data(#"{"app":"Notes","window_title":"Café ☕ list"}"#.utf8)
        let line = try LogCrypto.encryptLine(row, to: priv.publicKey)
        check(!String(decoding: line, as: UTF8.self).contains("Notes"), "sealed row has no plain text")
        check(try LogCrypto.decryptLine(line, with: priv) == row, "row decrypts with the right key")
        check((try? LogCrypto.decryptLine(line, with: other)) == nil, "row doesn't decrypt with another key")
        var raw = Data(base64Encoded: line)!
        raw[raw.count - 1] ^= 1
        check((try? LogCrypto.decryptLine(raw.base64EncodedData(), with: priv)) == nil, "tampered row is rejected")
        let again = try LogCrypto.encryptLine(row, to: priv.publicKey)
        check(again != line, "the same row never encrypts to the same bytes")

        // Files
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("al-selftest-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let f1 = dir.appendingPathComponent("2026-01-01" + Paths.encryptedSuffix)
        let f2 = dir.appendingPathComponent("2026-01-02" + Paths.encryptedSuffix)
        try appendEncryptedRow(Data(#"{"n":1}"#.utf8), to: f1, key: priv.publicKey)
        try appendEncryptedRow(Data(#"{"n":2}"#.utf8), to: f1, key: priv.publicKey)
        try appendEncryptedRow(Data(#"{"n":3}"#.utf8), to: f2, key: priv.publicKey)
        try Data("not a row\n".utf8).write(to: dir.appendingPathComponent("errors.log"))
        let files = dayFiles(in: dir, suffix: Paths.encryptedSuffix)
        check(files.map(\.day) == ["2026-01-01", "2026-01-02"], "day files are found in order")
        let (plain, bad) = decryptFiles(files, key: priv)
        check(String(decoding: plain, as: UTF8.self) == "{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n" && bad == 0, "files decrypt back to JSONL")
        let perms = (try FileManager.default.attributesOfItem(atPath: f1.path)[.posixPermissions] as? NSNumber)?.intValue
        check(perms == 0o600, "log files are readable by the owner only")
        check(decryptFiles(files, key: other).1 == 3, "another key reads nothing")
    } catch {
        check(false, "encryption threw: \(error)")
    }

    say(failures == 0 ? "All checks passed." : "\(failures) check(s) failed.")
    exit(failures == 0 ? 0 : 1)
}
