# ktman

A small Kerberos **keytab tool**: list a keytab, get a TGT from it, and get a
service ticket — on the command line or in a terminal UI.

It is built on the [`github.com/go-krb5/krb5`](https://github.com/go-krb5/krb5)
library, is **pure Go (no cgo)**, and opens **no network listeners**. Any
traffic goes only to the KDC named in the `krb5.conf` you pass.

## Build

```sh
cd ktman.git
go build -o ktman .
```

The module uses a local checkout of the krb5 library via a `replace` directive
(see [Dependencies](#dependencies)), so `../krb5.git` must exist next to this
directory.

## Usage

```
ktman -k PATH [-l]
ktman -k PATH -p PRINCIPAL [-r REALM] [-c krb5.conf] [-spn SERVICE/fqdn]
ktman -k PATH -ui
```

### Flags

| Flag                  | Meaning                                                             |
| --------------------- | ------------------------------------------------------------------- |
| `-k`, `-keytab PATH`  | keytab file (default: `$KRB5_KTNAME`; **required** unless `-ui`)    |
| `-l`                  | list the keytab's entries and exit (no KDC or config needed)        |
| `-ui`                 | start the terminal UI (a `-k` that does not exist yet starts a new keytab, created there on save) |
| `-p`, `-principal`    | principal to log in as (default: the keytab's **first** entry)      |
| `-r`, `-realm`        | realm (default: the chosen entry's realm, else `default_realm`)     |
| `-c`, `-config PATH`  | `krb5.conf` path (default: `$KRB5_CONFIG`, else `/etc/krb5.conf`)   |
| `-spn SERVICE/fqdn`   | after login, get a service ticket for this SPN                      |
| `-negotiate`          | with `-spn`: also print an `Authorization: Negotiate` header for it |
| `-decode`             | with `-spn`: show the ticket field by field (its encrypted part and PAC too, given the service's key) |
| `-skt PATH`           | with `-decode`: a keytab holding the service's key, if `-k` does not |
| `-print_key`          | with `-decode`: also print the session key's bytes (as `klist -K`) |

With no action flag and no `-p`/`-spn`, ktman lists the keytab (same as `-l`).

The standard Kerberos environment variables fill in for missing flags:

| Variable      | Used for                                                                 |
| ------------- | ------------------------------------------------------------------------ |
| `KRB5_CONFIG` | `-c`. MIT allows a list (`a.conf:b.conf`) and merges it; ktman loads the first that exists |
| `KRB5_KTNAME` | `-k`: `PATH` or `FILE:PATH` (`WRFILE:` too); other keytab types are refused |
| `KRB5_TRACE`  | a file to append the Kerberos exchanges' debug log to, as MIT writes its trace (`KRB5_TRACE=/dev/stderr`); with `-ui` it must not be the terminal |

With neither `-c`, `$KRB5_CONFIG` nor `/etc/krb5.conf`, the KDCs come from DNS
SRV records. There is no default keytab: ktman writes keytabs, so it never
picks `/etc/krb5.keytab` on its own.

A principal may be given with or without an `@REALM` suffix; the suffix fills
`-r` when `-r` is not set. The name passed to the KDC never includes the realm.

### Examples

**List a keytab** (needs neither a KDC nor a `krb5.conf`):

```sh
ktman -k /etc/krb5.keytab -l
```

```
PRINCIPAL               KVNO  TIMESTAMP            ENCTYPE
HTTP/svc.a.test@A.TEST  2     2026-11-05 23:25:07  aes256-cts-hmac-sha1-96
host/svc.a.test@A.TEST  2     2026-11-05 23:25:07  aes256-cts-hmac-sha1-96
```

**Get a TGT from the keytab:**

```sh
ktman -k svc.keytab -p HTTP/svc.a.test -r A.TEST -c krb5.conf
```

```
TGT OK: HTTP/svc.a.test@A.TEST -> krbtgt/A.TEST@A.TEST
  valid 2026-11-06 22:54:35 GMT .. 2026-11-07 08:54:35 GMT (renewable until 2026-11-07 22:54:35 GMT)
  flags: FORWARDABLE RENEWABLE INITIAL ENC-PA-REP
```

**Get a service ticket** for an SPN (`SERVICE/fqdn`) after the TGT:

```sh
ktman -k svc.keytab -p HTTP/svc.a.test -r A.TEST -c krb5.conf -spn host/svc.a.test
```

```
Service ticket: host/svc.a.test@A.TEST
  enctype: aes256-cts-hmac-sha1-96 (18), kvno 2, session key type 18
  valid 2026-11-06 22:54:35 GMT .. 2026-11-07 08:54:35 GMT
  flags: FORWARDABLE TRANSITED-POLICY-CHECKED ENC-PA-REP
```

**An HTTP Negotiate header** for that service, to paste into curl or an HTTP
client: add `-negotiate`, and the header is printed last, on a line of its own.
It wraps the ticket in a SPNEGO token: the service accepts it once (it keeps a
replay cache), within its clock skew (about five minutes), so make a new one
per request.

```sh
curl -H "$(ktman -k u.keytab -p alice -r A.TEST -c krb5.conf -spn HTTP/web.a.test -negotiate | tail -1)" https://web.a.test/
```

**Decode the service ticket** with `-decode`. The ticket's outer part (realm,
sname, the enc-part's etype and kvno) is in the clear and always shown. Its
encrypted part (client name and realm, flags, times, transited realms,
authorization data) and the Microsoft PAC in it (user and group SIDs, logon
domain, UPN, delegation info, signatures) need the *service's* key: give a
keytab holding it with `-skt`, or have it in `-k`. For an AD account, that key's
salt is the realm and the account's sAMAccountName (e.g. `-salt
EXAMPLE.TESTsvc-web` with `-n`). The PAC's server signature is verified with
that key; its KDC signature cannot be (that needs the krbtgt key). The session
key is shown as its type and length; `-print_key` prints its bytes too.

```sh
ktman -k u.keytab -p alice -r A.TEST -c krb5.conf -spn HTTP/web.a.test -decode -skt web.keytab
```

**Terminal UI:**

```sh
ktman -k svc.keytab -ui -c krb5.conf
```

In the UI:

- `↑`/`↓` (or `k`/`j`) — move the selection in the entry list
- `Enter` on the list — get a TGT for the selected entry
- `Tab` / `Shift+Tab` — move focus between the entry list, the realm field, and
  the SPN field
- type an SPN, then `Enter` in the SPN field — get a service ticket
- `Ctrl+Y` after a service ticket — copy a fresh `Negotiate <token>` (an
  `Authorization` header's value) to the clipboard (pbcopy, wl-copy, xclip or
  xsel, else the terminal's OSC 52)
- `Esc` — return focus to the list
- `q` (on the list) or `Ctrl+C` — quit

Results and errors appear in the status line. Network calls (login, service
ticket) run in the background so the UI stays responsive.

## Dependencies

`ktman` imports `github.com/go-krb5/krb5` from a **local checkout**, wired in
`go.mod`:

```
replace github.com/go-krb5/krb5 => ../krb5.git
```

The library's own dependency `github.com/go-krb5/x` is a published module
(`v0.3.2`) and needs no `replace` — this mirrors what `krb5.git` itself does.

The terminal UI uses the Charm stack:

- `github.com/charmbracelet/bubbletea`
- `github.com/charmbracelet/bubbles`
- `github.com/charmbracelet/lipgloss`

## Layout

```
main.go              CLI: flag parsing, list / login / service-ticket output
internal/kt/         core: keytab rows, config path chain, login, service ticket
internal/tui/        Bubble Tea model over internal/kt
```

All Kerberos work lives in `internal/kt`; the CLI and the TUI are thin layers
over the same functions, so they behave identically.
