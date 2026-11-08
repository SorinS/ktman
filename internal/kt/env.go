package kt

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/SorinS/krb5/client"
)

// The standard Kerberos environment variables ktman reads (as MIT does).
const (
	EnvConfig = "KRB5_CONFIG" // krb5.conf path, or a list of them
	EnvKeytab = "KRB5_KTNAME" // the default keytab, PATH or FILE:PATH
	EnvTrace  = "KRB5_TRACE"  // a file for the Kerberos exchanges' debug log
)

// EnvOrDefaultStr returns the value of the environment variable name, or def
// when it is unset or empty.
func EnvOrDefaultStr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}

	return def
}

// ResolveKeytabPath picks the keytab path: the flag if given, else
// $KRB5_KTNAME, else "" (there is no default keytab: ktman writes keytabs,
// and must not write the system's unasked). A FILE: or WRFILE: prefix is
// dropped; other keytab types (MEMORY:, KEYRING:, ...) are not files, and an
// error.
func ResolveKeytabPath(flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}

	name := EnvOrDefaultStr(EnvKeytab, "")

	typ, rest, ok := strings.Cut(name, ":")
	if !ok || filepath.VolumeName(name) != "" {
		return name, nil
	}

	switch strings.ToUpper(typ) {
	case "FILE", "WRFILE":
		return rest, nil
	case "MEMORY", "MEMORY_MAP", "KEYRING", "KDB", "ANY":
		return "", fmt.Errorf("$%s is a %s keytab, not a file", EnvKeytab, typ)
	}

	return name, nil
}

// configFromEnv is the krb5.conf $KRB5_CONFIG names, "" if none. MIT takes a
// list (separated as PATH is) and merges the files; ktman loads one: the
// first that exists, else the first named, so that its absence is reported.
func configFromEnv() string {
	list := filepath.SplitList(EnvOrDefaultStr(EnvConfig, ""))
	for _, p := range list {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	for _, p := range list {
		if p != "" {
			return p
		}
	}

	return ""
}

// trace is the debug log KRB5_TRACE asked for, nil without.
var trace *log.Logger

// OpenTrace starts the debug log if $KRB5_TRACE names a file, as MIT writes
// its trace there (KRB5_TRACE=/dev/stderr is the usual): every Kerberos client
// ktman makes then logs its exchanges to it. The file is appended to. It
// returns the file, nil without $KRB5_TRACE, for the caller to close.
func OpenTrace() (*os.File, error) {
	name := EnvOrDefaultStr(EnvTrace, "")
	if name == "" {
		return nil, nil
	}

	f, err := os.OpenFile(name, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("$%s: %w", EnvTrace, err)
	}

	trace = log.New(f, "krb5: ", log.LstdFlags|log.Lmicroseconds)

	return f, nil
}

// clientSettings are the options every Kerberos client ktman makes gets: the
// debug log, with $KRB5_TRACE.
func clientSettings() []func(*client.Settings) {
	if trace == nil {
		return nil
	}

	return []func(*client.Settings){client.Logger(trace)}
}
