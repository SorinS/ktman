// Command ktman is a Kerberos keytab tool: create a keytab, list it, get a TGT
// from it, and get a service ticket, on the command line or in a terminal UI.
//
// It is built on github.com/SorinS/krb5 and is pure Go (no cgo). It opens no
// network listeners; any traffic goes to the KDC named in the krb5.conf given.
//
//	ktman -k /etc/krb5.keytab -l
//	echo $PW | ktman -n -k svc.keytab -p HTTP/svc.a.test -r A.TEST
//	ktman -k svc.keytab -p HTTP/svc.a.test -r A.TEST -c krb5.conf -svc_ticket -spn HTTP/host.a.test
//	ktman -ui
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/SorinS/krb5/keytab"

	"sorins/ktman/internal/kt"
	"sorins/ktman/internal/tui"
)

func main() {
	var (
		ktPath    = flag.String("k", "", "path to the keytab file (default: $KRB5_KTNAME)")
		list      = flag.Bool("l", false, "list the keytab's entries and exit")
		ui        = flag.Bool("ui", false, "start the terminal UI")
		newKt     = flag.Bool("n", false, "create (or append to) the keytab: add an entry for -p@-r")
		tgt       = flag.Bool("tgt", false, "get a TGT for -p (default: the keytab's first entry)")
		principal = flag.String("p", "", "principal (default on login: the keytab's first entry)")
		realm     = flag.String("r", "", "realm (default on login: the chosen entry's realm, else default_realm)")
		cfgPath   = flag.String("c", "", "krb5.conf path (default: $KRB5_CONFIG, else "+kt.DefaultConfigPath+")")
		svcTicket = flag.Bool("svc_ticket", false, "get a TGT, then a service ticket for -spn")
		spn       = flag.String("spn", "", "the service, SERVICE/fqdn, for -svc_ticket")
		negotiate = flag.Bool("negotiate", false, "with -svc_ticket: also print an HTTP Authorization: Negotiate header for it")
		decode    = flag.Bool("decode", false, "with -svc_ticket: show the ticket's fields; its encrypted part and PAC too if a keytab holds the service's key")
		svcKtPath = flag.String("skt", "", "with -decode: a keytab holding the service's key, if -k does not")
		showKeys  = flag.Bool("print_key", false, "with -decode: also print the session key's bytes (as klist -K)")
		salt      = flag.String("salt", "", "create: explicit salt (AD salts differ from the default); empty for the default")
		etypes    = flag.String("e", "", "create: comma-separated encryption types (default aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96)")
		kvno      = flag.Uint("kvno", 1, "create: the key version")
		ldapAddr  = flag.String("ldap", "", "AD LDAP address HOST:PORT, for the TUI's Get-KVNO-from-AD (ctrl+k)")
		dcHost    = flag.String("dc", "", "AD DC host name (ldap/<host>), paired with -ldap")
	)

	flag.BoolVar(newKt, "new", false, "alias for -n")
	flag.StringVar(ktPath, "keytab", "", "alias for -k")
	flag.StringVar(principal, "principal", "", "alias for -p")
	flag.StringVar(realm, "realm", "", "alias for -r")
	flag.StringVar(cfgPath, "config", "", "alias for -c")

	flag.Usage = usage
	flag.Parse()

	if err := checkFlags(); err != nil {
		fmt.Fprintf(os.Stderr, "ktman: %v\n", err)
		os.Exit(2)
	}

	var err error
	if *ktPath, err = kt.ResolveKeytabPath(*ktPath); err != nil {
		fatal("%v", err)
	}

	traceFile, err := kt.OpenTrace()
	if err != nil {
		fatal("%v", err)
	}

	if traceFile != nil {
		defer traceFile.Close()

		// The TUI owns the terminal: a trace written to it would garble it.
		if *ui && onTerminal(traceFile) {
			fatal("$%s is the terminal, which -ui draws on: give it a file", kt.EnvTrace)
		}
	}

	// The TUI does not require a keytab: with none it opens a create-or-open
	// screen. This must come before the -k requirement check below.
	if *ui {
		if err := tui.Run(*ktPath, *principal, *realm, *cfgPath, *ldapAddr, *dcHost, *svcKtPath, *showKeys); err != nil {
			fatal("%v", err)
		}

		return
	}

	if *ktPath == "" {
		fmt.Fprintln(os.Stderr, "ktman: a keytab is required (-k PATH or $KRB5_KTNAME), or use -ui")
		flag.Usage()
		os.Exit(2)
	}

	if *newKt {
		if err := runCreate(*ktPath, *principal, *realm, *salt, *etypes, uint32(*kvno)); err != nil {
			fatal("%v", err)
		}

		return
	}

	ktab, err := kt.Load(*ktPath)
	if errors.Is(err, fs.ErrNotExist) {
		fatal("keytab %q does not exist: create it with -n -p PRINCIPAL -r REALM, or in -ui", *ktPath)
	} else if err != nil {
		fatal("could not load keytab %q: %v", *ktPath, err)
	}

	// A list (or no action requested) needs no config and no KDC.
	if *list || !*tgt && !*svcTicket {
		listKeytab(ktab)
		return
	}

	var svcKt *keytab.Keytab
	if *svcKtPath != "" {
		if svcKt, err = kt.Load(*svcKtPath); err != nil {
			fatal("could not load the service keytab %q: %v", *svcKtPath, err)
		}
	}

	dec := decodeOpts{on: *decode, showKeys: *showKeys, svcKt: svcKt}

	if err := runLogin(ktab, *principal, *realm, *cfgPath, *spn, *negotiate, dec); err != nil {
		fatal("%v", err)
	}
}

// flagAliases maps each long alias to the flag it stands for.
var flagAliases = map[string]string{"new": "n", "keytab": "k", "principal": "p", "realm": "r", "config": "c"}

// checkFlags refuses combinations ktman would otherwise act on silently: more
// than one action (-l, -n, -tgt or -spn, -ui), and an option given without the
// action it belongs to. -tgt and -svc_ticket may be given together (a service
// ticket needs the TGT anyway).
func checkFlags() error {
	set := map[string]bool{}

	flag.Visit(func(f *flag.Flag) {
		name := f.Name
		if a, ok := flagAliases[name]; ok {
			name = a
		}

		set[name] = true
	})

	var actions []string

	for _, a := range []string{"l", "n", "ui"} {
		if set[a] {
			actions = append(actions, "-"+a)
		}
	}

	if set["tgt"] || set["svc_ticket"] {
		actions = append(actions, "-tgt/-svc_ticket")
	}

	if len(actions) > 1 {
		return fmt.Errorf("%s: choose one", strings.Join(actions, ", "))
	}

	// option, the actions it belongs to (any of), and how to say them.
	needs := []struct {
		opt  string
		with []string
		say  string
	}{
		{"salt", []string{"n"}, "-n"},
		{"e", []string{"n"}, "-n"},
		{"kvno", []string{"n"}, "-n"},
		{"spn", []string{"svc_ticket"}, "-svc_ticket"},
		{"negotiate", []string{"svc_ticket"}, "-svc_ticket"},
		{"decode", []string{"svc_ticket"}, "-svc_ticket"},
		{"skt", []string{"decode", "ui"}, "-decode or -ui"},
		{"print_key", []string{"decode", "ui"}, "-decode or -ui"},
		{"ldap", []string{"ui"}, "-ui"},
		{"dc", []string{"ui"}, "-ui"},
	}

	for _, n := range needs {
		if !set[n.opt] {
			continue
		}

		ok := false
		for _, w := range n.with {
			ok = ok || set[w]
		}

		if !ok {
			return fmt.Errorf("-%s needs %s", n.opt, n.say)
		}
	}

	if set["svc_ticket"] && !set["spn"] {
		return errors.New("-svc_ticket needs -spn SERVICE/fqdn")
	}

	if (set["p"] || set["r"] || set["c"]) && len(actions) == 0 {
		return errors.New("-p, -r and -c need an action: -tgt to log in, -svc_ticket for a service ticket, -n to create, or -ui")
	}

	if set["c"] && (set["l"] || set["n"]) {
		return errors.New("-c is for -tgt, -svc_ticket and -ui (-l and -n need no KDC)")
	}

	if (set["p"] || set["r"]) && set["l"] {
		return errors.New("-l lists every entry: -p and -r are not used")
	}

	return nil
}

// runCreate adds an entry for principal@realm to the keytab at ktPath, creating
// the file or appending to an existing one. The password is read securely.
func runCreate(ktPath, principal, realm, salt, etypes string, kvno uint32) error {
	name, rlm := kt.NormalizePrincipal(principal, realm)
	if name == "" || rlm == "" {
		return fmt.Errorf("create needs a principal and realm (-p NAME -r REALM)")
	}

	ets, err := kt.ParseETypes(etypes)
	if err != nil {
		return err
	}

	for _, e := range ets {
		if kt.WeakEType(e) {
			fmt.Fprintf(os.Stderr, "ktman: note: %s is deprecated (RFC 8429); use it only for services that need it\n", kt.EtypeName(e))
		}
	}

	password, err := readPassword(fmt.Sprintf("Password for %s@%s: ", name, rlm))
	if err != nil {
		return err
	}

	ktab, added, err := kt.CreateEntry(kt.CreateOptions{
		Path:      ktPath,
		Principal: name,
		Realm:     rlm,
		Password:  password,
		Salt:      salt,
		KVNO:      kvno,
		ETypes:    ets,
	})
	if err != nil {
		return fmt.Errorf("could not write keytab %q: %w", ktPath, err)
	}

	fmt.Printf("added %d key(s) for %s@%s to %s (%d entries total)\n",
		added, name, rlm, ktPath, len(ktab.Entries))

	return nil
}

// readPassword reads a password without echoing it when stdin is a terminal,
// and otherwise reads a single line from stdin (for piped input, as
// keytab-make does). The value is never echoed or logged.
func readPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())

	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)

		b, err := term.ReadPassword(fd)

		fmt.Fprintln(os.Stderr)

		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}

		pw := strings.TrimSpace(string(b))
		if pw == "" {
			return "", fmt.Errorf("empty password")
		}

		return pw, nil
	}

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("no password on stdin: %w", err)
	}

	pw := strings.TrimSpace(line)
	if pw == "" {
		return "", fmt.Errorf("empty password")
	}

	return pw, nil
}

// listKeytab prints one aligned row per keytab entry.
func listKeytab(ktab *keytab.Keytab) {
	rows := kt.Rows(ktab)
	if len(rows) == 0 {
		fmt.Println("keytab has no entries")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "PRINCIPAL\tKVNO\tTIMESTAMP\tENCTYPE")

	for _, r := range rows {
		ts := "-"
		if !r.Timestamp.IsZero() {
			ts = r.Timestamp.Format("2006-01-02 15:04:05")
		}

		fmt.Fprintf(w, "%s\t%d\t%s\t%s\n", r.Principal, r.KVNO, ts, r.EType)
	}

	w.Flush()
}

// runLogin gets a TGT from the keytab and, if an SPN is given, a service ticket.
// decodeOpts are -decode's: whether to, whether to show the session key, and a
// keytab holding the service's key besides -k's.
type decodeOpts struct {
	on       bool
	showKeys bool
	svcKt    *keytab.Keytab
}

// With dec.on, it shows the ticket decoded; with negotiate, it also prints an
// HTTP Negotiate header for the service, last and on a line of its own, to copy.
func runLogin(ktab *keytab.Keytab, principal, realm, cfgPath, spn string, negotiate bool, dec decodeOpts) error {
	cfg, err := kt.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("could not load krb5.conf (%s): %w", kt.ResolveConfigPath(cfgPath), err)
	}

	if principal == "" {
		principal, realm = defaultedPrincipal(ktab, realm)
	}

	cl, tgt, err := kt.Login(ktab, principal, realm, cfg)
	if err != nil {
		return fmt.Errorf("login failed for %q: %w", principal, err)
	}

	defer cl.Destroy()

	fmt.Printf("TGT OK: %s@%s -> %s\n", tgt.Principal, tgt.Realm, tgt.SName)
	fmt.Printf("  valid %s .. %s", fmtTime(tgt.StartTime), fmtTime(tgt.EndTime))

	if !tgt.RenewTill.IsZero() && tgt.RenewTill.After(tgt.EndTime) {
		fmt.Printf(" (renewable until %s)", fmtTime(tgt.RenewTill))
	}

	fmt.Println()

	if len(tgt.Flags) > 0 {
		fmt.Printf("  flags: %s\n", strings.Join(tgt.Flags, " "))
	}

	if spn == "" {
		return nil
	}

	svc, err := kt.ServiceTicket(cl, spn)
	if err != nil {
		return fmt.Errorf("could not get service ticket for %q: %w", spn, err)
	}

	fmt.Printf("\nService ticket: %s@%s\n", svc.SName, svc.Realm)
	fmt.Printf("  enctype: %s (%d), kvno %d, session key type %d\n",
		svc.ETypeName, svc.EType, svc.KVNO, svc.SessionKeyType)
	fmt.Printf("  valid %s .. %s\n", fmtTime(svc.StartTime), fmtTime(svc.EndTime))

	if len(svc.Flags) > 0 {
		fmt.Printf("  flags: %s\n", strings.Join(svc.Flags, " "))
	}

	if dec.on {
		fmt.Println()
		kt.DecodeTicket(os.Stdout, svc, dec.showKeys, dec.svcKt, ktab)
	}

	if !negotiate {
		return nil
	}

	token, err := kt.NegotiateToken(cl, spn)
	if err != nil {
		return err
	}

	fmt.Printf("\nNegotiate header (one use, within about 5 minutes):\n")
	fmt.Printf("Authorization: Negotiate %s\n", token)

	return nil
}

func defaultedPrincipal(ktab *keytab.Keytab, realm string) (string, string) {
	p, r := kt.DefaultPrincipal(ktab)
	if realm != "" {
		r = realm
	}

	return p, r
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	return t.Local().Format("2006-01-02 15:04:05 MST")
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ktman: "+format+"\n", a...)
	os.Exit(1)
}

// onTerminal is whether f is the terminal ktman's stdout or stderr is.
func onTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}

	for _, std := range []*os.File{os.Stdout, os.Stderr} {
		if si, err := std.Stat(); err == nil && os.SameFile(fi, si) && si.Mode()&os.ModeCharDevice != 0 {
			return true
		}
	}

	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `ktman - Kerberos keytab tool

Usage:
  ktman -k PATH [-l]
  ktman -n -k PATH -p PRINCIPAL -r REALM [-e ENCTYPES] [-kvno N] [-salt SALT]
  ktman -k PATH -tgt [-p PRINCIPAL] [-r REALM] [-c krb5.conf]
  ktman -k PATH -svc_ticket -spn SERVICE/fqdn [-p PRINCIPAL] [-r REALM] [-c krb5.conf]
        [-negotiate] [-decode [-skt PATH] [-print_key]]
  ktman -ui [-k PATH]

Flags:
  -k, -keytab PATH      keytab file (default: $KRB5_KTNAME; required unless -ui)
  -l                    list the keytab's entries and exit (no KDC needed)
  -n, -new              create/append: add an entry for -p@-r to the keytab
  -ui                   start the terminal UI (no -k needed; a -k that does not
                        exist yet starts a new keytab, created on save)
  -tgt                  get a TGT (login) for -p, by default the first entry
  -svc_ticket           get a TGT, then a service ticket for -spn
  -p, -principal NAME   principal (-n: required; -tgt/-svc_ticket: default first
                        entry)
  -r, -realm REALM      realm (-n: required; -tgt/-svc_ticket: default entry's
                        realm)
  -c, -config PATH      krb5.conf (default: $KRB5_CONFIG, else /etc/krb5.conf;
                        none there: KDCs from DNS)
  -spn SERVICE/fqdn     with -svc_ticket: the service
  -negotiate            with -svc_ticket: also print an "Authorization: Negotiate"
                        header for it (one use, within about 5 minutes)
  -decode               with -svc_ticket: show the ticket field by field; its encrypted
                        part and PAC too when -skt or -k holds the service's key
  -skt PATH             with -decode (or -ui's ctrl+x): keytab with the
                        service's key
  -print_key            with -decode (or -ui's ctrl+x): also print the session
                        key's bytes
  -e ENCTYPES           with -n: comma-separated enctypes, one key each
                        (default aes256-cts,aes128-cts, as MIT's ktadd;
                        rc4-hmac and des3-cbc-sha1-kd on request)
  -kvno N               with -n: key version (default 1)
  -salt SALT            with -n: explicit salt (empty for the default; for an
                        AD account: REALM + its sAMAccountName)

Environment:
  KRB5_CONFIG           krb5.conf, when no -c (a list: the first that exists)
  KRB5_KTNAME           keytab, when no -k (PATH or FILE:PATH)
  KRB5_TRACE            a file to append the Kerberos exchanges' debug log to
                        (e.g. /dev/stderr; with -ui, not the terminal)

The create password is read from a no-echo prompt, or from stdin if piped.
It is never taken from a flag.

Examples:
  ktman -k /etc/krb5.keytab -l
  echo s3cret | ktman -n -k svc.keytab -p HTTP/svc.a.test -r A.TEST
  ktman -n -k svc.keytab -p host/svc.a.test -r A.TEST -e aes256-cts,camellia256-cts-cmac -kvno 3
  ktman -k svc.keytab -tgt -c krb5.conf
  ktman -k svc.keytab -p HTTP/svc.a.test -r A.TEST -c krb5.conf -svc_ticket -spn host/svc.a.test
  curl -H "$(ktman -k u.keytab -p alice -r A.TEST -svc_ticket -spn HTTP/web.a.test -negotiate | tail -1)" https://web.a.test/
  ktman -ui
`)
}
