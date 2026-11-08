package kt

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/keytab"
)

// DefaultCreateETypes are the encryption types a create uses when none is given
// explicitly, matching MIT's ktadd default (AES256 then AES128).
var DefaultCreateETypes = []int32{
	etypeID.AES256_CTS_HMAC_SHA1_96,
	etypeID.AES128_CTS_HMAC_SHA1_96,
}

// NormalizePrincipal splits a "name@REALM" principal into its name and realm.
// An explicit realm wins; otherwise the "@REALM" suffix fills it. The returned
// name never carries a realm.
func NormalizePrincipal(principal, realm string) (string, string) {
	if at := strings.LastIndex(principal, "@"); at >= 0 {
		if realm == "" {
			realm = principal[at+1:]
		}

		principal = principal[:at]
	}

	return principal, realm
}

// ParseEType maps a single encryption-type name to its ID, accepting the
// library's names and aliases, and rejects types ktman does not offer (single
// DES, triple DES and RC4). One enctype per entry: to add another, run again.
func ParseEType(name string) (int32, error) {
	id := etypeID.EtypeSupported(strings.TrimSpace(name))
	if id == 0 {
		return 0, fmt.Errorf("unknown enctype %q", name)
	}

	for _, s := range SupportedETypes {
		if s == id {
			return id, nil
		}
	}

	return 0, fmt.Errorf("enctype %q is not supported (single DES, triple DES and RC4 are excluded)", name)
}

// CreateOptions describes an entry to add to a keytab.
type CreateOptions struct {
	Path      string  // keytab file to create or append to
	Principal string  // principal name (an "@REALM" suffix fills Realm if empty)
	Realm     string  // realm
	Password  string  // the account's password; keys are derived from it
	Salt      string  // explicit salt; empty means the principal's default
	KVNO      uint32  // key version (default 1 if zero)
	ETypes    []int32 // encryption-type IDs; empty means DefaultCreateETypes
}

// CreateEntry adds an entry for the principal to the keytab at opts.Path, one
// key per encryption type. If the file exists its entries are kept and the new
// ones appended; otherwise the file is created. The keytab is written back with
// mode 0600 (it holds key material). It returns the resulting keytab and the
// number of keys added.
func CreateEntry(opts CreateOptions) (*keytab.Keytab, int, error) {
	name, realm := NormalizePrincipal(opts.Principal, opts.Realm)
	if name == "" {
		return nil, 0, errors.New("a principal is required")
	}

	if realm == "" {
		return nil, 0, errors.New("a realm is required")
	}

	if opts.Password == "" {
		return nil, 0, errors.New("a password is required")
	}

	etypes := opts.ETypes
	if len(etypes) == 0 {
		etypes = DefaultCreateETypes
	}

	kvno := opts.KVNO
	if kvno == 0 {
		kvno = 1
	}

	ktab, err := loadOrNew(opts.Path)
	if err != nil {
		return nil, 0, err
	}

	ts := time.Now()
	added := 0

	for _, e := range etypes {
		if err := ktab.AddEntryWithSalt(name, realm, opts.Password, opts.Salt, ts, kvno, e); err != nil {
			return nil, added, fmt.Errorf("adding %s key: %w", EtypeName(e), err)
		}

		added++
	}

	if err := writeKeytab(ktab, opts.Path); err != nil {
		return nil, added, err
	}

	return ktab, added, nil
}

// Save writes an in-memory keytab to path (mode 0600; it holds key material).
// It is used by the TUI, which edits a keytab in memory and saves on request.
func Save(ktab *keytab.Keytab, path string) error {
	return writeKeytab(ktab, path)
}

// loadOrNew returns the keytab at path, or a new empty one if path is absent.
func loadOrNew(path string) (*keytab.Keytab, error) {
	_, statErr := os.Stat(path)

	switch {
	case statErr == nil:
		ktab, err := keytab.Load(path)
		if err != nil {
			return nil, fmt.Errorf("could not open existing keytab %q: %w", path, err)
		}

		return ktab, nil
	case errors.Is(statErr, fs.ErrNotExist):
		return keytab.New(), nil
	default:
		return nil, statErr
	}
}

// writeKeytab writes the keytab to path, mode 0600.
func writeKeytab(ktab *keytab.Keytab, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	if _, err := ktab.Write(f); err != nil {
		_ = f.Close()
		return err
	}

	return f.Close()
}
