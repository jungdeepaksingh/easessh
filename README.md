# easessh

A simple, fast SSH manager for your terminal.
Save your servers once, then connect with a single key press.

- 🔐 All saved servers are encrypted with one master password
- 🔑 Log in with a password, a key file, or ssh-agent
- ⚡ Recent servers first, quick search, connect with `1`–`9`
- 🛡️ Warns you if a server's identity changes
- 🔒 Locks itself when you're away

---

## Build

You need [Go](https://go.dev/dl/) 1.27.2 or newer.

```sh
git clone https://github.com/jungdeepaksingh/easessh.git
cd easessh
go install .
```

That's it. Now run it from **any folder**:

```sh
easessh
```

The first time, you'll be asked to create a master password.

<details>
<summary><b>"easessh: command not found"?</b></summary>

Go puts the program in `~/go/bin`, which may not be on your PATH yet. Add it once:

```sh
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc   # use ~/.zshrc on macOS
source ~/.bashrc
```

On Windows, `go install` uses `%USERPROFILE%\go\bin`. The Go installer usually adds it to PATH already.
</details>

**Update later:** `git pull` then `go install .` again.

**Uninstall:** `rm ~/go/bin/easessh` (your saved servers are kept; see [Security](#security) for where).

---

## Usage

```sh
easessh              # open the server list
easessh myserver     # connect straight to a saved server
easessh -l           # list saved servers
easessh --passwd     # change the master password
```

### Keys

| Key | Action |
|-----|--------|
| `Enter` or `1`–`9` | Connect |
| `/` | Search |
| `a` | Add a server |
| `e` | Edit |
| `c` | Copy |
| `d` | Delete |
| `i` | Import from `~/.ssh/config` |
| `Ctrl+L` | Lock |
| `q` | Quit |

**Adding a server:** move between fields with `Tab`, use `←`/`→` to pick the login type,
then `Enter` to save. You can type `user@host:port` in the Host field to fill in all three at once.

Leave the password empty if you'd rather be asked each time you connect.

---

## Security

- Your server list is stored encrypted (Argon2id + AES-256-GCM) in `hosts.json`:
  - Linux: `~/.config/easessh/`
  - macOS: `~/Library/Application Support/easessh/`
  - Windows: `%AppData%\easessh\`

  Run `easessh -h` to see the exact path.
- **Don't forget your master password.** There is no way to recover it.
- The app locks after 10 minutes of inactivity.
  Change this with `EASESSH_AUTOLOCK=30` (minutes) or turn it off with `EASESSH_AUTOLOCK=0`.
- Server identities are checked against `~/.ssh/known_hosts`, the same file OpenSSH uses.

---

## Tests

```sh
go test ./...
```

---

## License

Public domain ([Unlicense](LICENSE)). Use it however you like, at your own risk.
