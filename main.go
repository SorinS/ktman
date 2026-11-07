// Command ktman is a Kerberos keytab tool: create a keytab, list it, get a TGT
// from it, and get a service ticket, on the command line or in a terminal UI.
//
// It is built on github.com/go-krb5/krb5 and is pure Go (no cgo). It opens no
// network listeners; any traffic goes to the KDC named in the krb5.conf given.
//
//	ktman -k /etc/krb5.keytab -l
//	echo $PW | ktman -n -k svc.keytab -p HTTP/svc.a.test -r A.TEST
//	ktman -k svc.keytab -p HTTP/svc.a.test -r A.TEST -c krb5.conf -spn HTTP/host.a.test
//	ktman -ui
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/go-krb5/krb5/keytab"

	"sorins/ktman/internal/kt"
	"sorins/ktman/internal/tui"
)

func main() {
	var (
		ktPath    = flag.String("k", "", "path to the keytab file")
		list      = flag.Bool("l", false, "list the keytab's entries and exit")
		ui        = flag.Bool("ui", false, "start the terminal UI")
		newKt     = flag.Bool("n", false, "create (or append to) the keytab: add an entry for -p@-r")
		principal = flag.String("p", "", "principal (default on login: the keytab's first entry)")
		realm     = flag.String("r", "", "realm (default on login: the chosen entry's realm, else default_realm)")
		cfgPath   = flag.String("c", "", "krb5.conf path (default: $KRB5_CONFIG, else "+kt.DefaultConfigPath+")")
		spn       = flag.String("spn", "", "service to get a ticket for, format SERVICE/fqdn (implies a login)")
		salt      = flag.String("salt", "", "create: explicit salt (AD salts differ from the default); empty for the default")
		etypes    = flag.String("e", "", "create: encryption type (default aes256-cts-hmac-sha1-96); one per entry")
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

	// The TUI does not require a keytab: with none it opens a create-or-open
	// screen. This must come before the -k requirement check below.
	if *ui {
		if err := tui.Run(*ktPath, *principal, *realm, *cfgPath, *ldapAddr, *dcHost); err != nil {
			fatal("%v", err)
		}

		return
	}

	if *ktPath == "" {
		fmt.Fprintln(os.Stderr, "ktman: a keytab is required (-k PATH), or use -ui")
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
	if err != nil {
		fatal("could not load keytab %q: %v", *ktPath, err)
	}

	// A bare list (or no action requested) needs no config and no KDC.
	if *list || (*principal == "" && *spn == "") {
		listKeytab(ktab)
		return
	}

	if err := runLogin(ktab, *principal, *realm, *cfgPath, *spn); err != nil {
		fatal("%v", err)
	}
}

// runCreate adds an entry for principal@realm to the keytab at ktPath, creating
// the file or appending to an existing one. The password is read securely.
func runCreate(ktPath, principal, realm, salt, etypes string, kvno uint32) error {
	name, rlm := kt.NormalizePrincipal(principal, realm)
	if name == "" || rlm == "" {
		return fmt.Errorf("create needs a principal and realm (-p NAME -r REALM)")
	}

	et := kt.SupportedETypes[0]

	if strings.TrimSpace(etypes) != "" {
		id, err := kt.ParseEType(etypes)
		if err != nil {
			return err
		}

		et = id
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
		ETypes:    []int32{et},
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
func runLogin(ktab *keytab.Keytab, principal, realm, cfgPath, spn string) error {
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

func usage() {
	fmt.Fprint(os.Stderr, `ktman - Kerberos keytab tool

Usage:
  ktman -k PATH [-l]
  ktman -n -k PATH -p PRINCIPAL -r REALM [-e ENCTYPES] [-kvno N] [-salt SALT]
  ktman -k PATH -p PRINCIPAL [-r REALM] [-c krb5.conf] [-spn SERVICE/fqdn]
  ktman -ui [-k PATH]

Flags:
  -k, -keytab PATH      keytab file (required unless -ui)
  -l                    list the keytab's entries and exit (no KDC needed)
  -n, -new              create/append: add an entry for -p@-r to the keytab
  -ui                   start the terminal UI (no -k needed; opens create-or-open)
  -p, -principal NAME   principal (create: required; login: default first entry)
  -r, -realm REALM      realm (create: required; login: default entry's realm)
  -c, -config PATH      krb5.conf (default: $KRB5_CONFIG, else /etc/krb5.conf)
  -spn SERVICE/fqdn     get a service ticket for this SPN after login
  -e ENCTYPES           create: comma-separated enctypes (default aes256-cts,aes128-cts)
  -kvno N               create: key version (default 1)
  -salt SALT            create: explicit salt (empty for the default)

The create password is read from a no-echo prompt, or from stdin if piped.
It is never taken from a flag.

Examples:
  ktman -k /etc/krb5.keytab -l
  echo s3cret | ktman -n -k svc.keytab -p HTTP/svc.a.test -r A.TEST
  ktman -n -k svc.keytab -p host/svc.a.test -r A.TEST -e aes256-cts,rc4-hmac -kvno 3
  ktman -k svc.keytab -p HTTP/svc.a.test -r A.TEST -c krb5.conf -spn host/svc.a.test
  ktman -ui
`)
}
