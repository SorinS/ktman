// Package kt holds the ktman core: reading a keytab, getting a TGT from it,
// and getting a service ticket. These functions are shared by the CLI and the
// TUI so the two paths behave identically.
package kt

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/iana/flags"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/types"
)

// DefaultConfigPath is the last resort for a krb5.conf, MIT's usual location.
const DefaultConfigPath = "/etc/krb5.conf"

// etypeNames maps an encryption-type ID to a single canonical name. The
// library's etypeID.ETypesByName is name->id with several aliases per id, so a
// reverse of it would be non-deterministic; this fixed table keeps listing
// output stable between runs.
var etypeNames = map[int32]string{
	etypeID.DES_CBC_CRC:                "des-cbc-crc",
	etypeID.DES_CBC_MD4:                "des-cbc-md4",
	etypeID.DES_CBC_MD5:                "des-cbc-md5",
	etypeID.DES3_CBC_SHA1_KD:           "des3-cbc-sha1-kd",
	etypeID.AES128_CTS_HMAC_SHA1_96:    "aes128-cts-hmac-sha1-96",
	etypeID.AES256_CTS_HMAC_SHA1_96:    "aes256-cts-hmac-sha1-96",
	etypeID.AES128_CTS_HMAC_SHA256_128: "aes128-cts-hmac-sha256-128",
	etypeID.AES256_CTS_HMAC_SHA384_192: "aes256-cts-hmac-sha384-192",
	etypeID.RC4_HMAC:                   "rc4-hmac",
	etypeID.RC4_HMAC_EXP:               "rc4-hmac-exp",
	etypeID.CAMELLIA128_CTS_CMAC:       "camellia128-cts-cmac",
	etypeID.CAMELLIA256_CTS_CMAC:       "camellia256-cts-cmac",
}

// EtypeName returns a human-readable name for an encryption-type ID, or
// "etype-N" when the ID is unknown.
func EtypeName(id int32) string {
	if n, ok := etypeNames[id]; ok {
		return n
	}

	return fmt.Sprintf("etype-%d", id)
}

// ETypeLabel is "<id> <name>", the number and its text (for display).
func ETypeLabel(id int32) string {
	return fmt.Sprintf("%d %s", id, EtypeName(id))
}

// SupportedETypes are the encryption types ktman offers for new keytab entries,
// strongest first. The deprecated single-DES, triple-DES and RC4 types are left
// out on purpose.
var SupportedETypes = []int32{
	etypeID.AES256_CTS_HMAC_SHA1_96,
	etypeID.AES128_CTS_HMAC_SHA1_96,
	etypeID.AES256_CTS_HMAC_SHA384_192,
	etypeID.AES128_CTS_HMAC_SHA256_128,
	etypeID.CAMELLIA256_CTS_CMAC,
	etypeID.CAMELLIA128_CTS_CMAC,
}

// ticketFlagNames pairs each ticket-flag bit with its name, in bit order.
var ticketFlagNames = []struct {
	bit  int
	name string
}{
	{flags.Forwardable, "FORWARDABLE"},
	{flags.Forwarded, "FORWARDED"},
	{flags.Proxiable, "PROXIABLE"},
	{flags.Proxy, "PROXY"},
	{flags.MayPostDate, "MAY-POSTDATE"},
	{flags.PostDated, "POSTDATED"},
	{flags.Invalid, "INVALID"},
	{flags.Renewable, "RENEWABLE"},
	{flags.Initial, "INITIAL"},
	{flags.PreAuthent, "PRE-AUTHENT"},
	{flags.HWAuthent, "HW-AUTHENT"},
	{flags.TransitedPolicyChecked, "TRANSITED-POLICY-CHECKED"},
	{flags.OKAsDelegate, "OK-AS-DELEGATE"},
	{flags.EncPARep, "ENC-PA-REP"},
}

// FlagNames decodes a ticket's flag bits into their names.
func FlagNames(f asn1.BitString) []string {
	var out []string

	for _, tf := range ticketFlagNames {
		if tf.bit/8 < len(f.Bytes) && types.IsFlagSet(&f, tf.bit) {
			out = append(out, tf.name)
		}
	}

	return out
}

// Row is one keytab entry, reduced to what the listing shows.
type Row struct {
	Principal string
	KVNO      uint32
	Timestamp time.Time
	EType     string
	ETypeID   int32
	KeyHex    string // the derived key, hex-encoded
}

// Rows reduces a keytab's entries to display rows.
func Rows(kt *keytab.Keytab) []Row {
	rows := make([]Row, 0, len(kt.Entries))

	for _, e := range kt.Entries {
		rows = append(rows, Row{
			Principal: e.Principal.String(),
			KVNO:      e.KVNO,
			Timestamp: e.Timestamp,
			EType:     EtypeName(e.Key.KeyType),
			ETypeID:   e.Key.KeyType,
			KeyHex:    hex.EncodeToString(e.Key.KeyValue),
		})
	}

	return rows
}

// Load reads a keytab file.
func Load(path string) (*keytab.Keytab, error) {
	return keytab.Load(path)
}

// ResolveConfigPath picks the krb5.conf path: the flag if given, else
// $KRB5_CONFIG, else DefaultConfigPath. config.Load does not do this fallback
// itself (it fails on an empty path), so we do it here.
func ResolveConfigPath(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}

	if env := os.Getenv("KRB5_CONFIG"); env != "" {
		return env
	}

	return DefaultConfigPath
}

// LoadConfig loads a krb5.conf, resolving the path as ResolveConfigPath does.
//
// A krb5.conf is optional. When none is named (no -c and no $KRB5_CONFIG) and
// the default /etc/krb5.conf is absent, LoadConfig returns DNSConfig, which
// discovers each realm's KDC from DNS — so a login works from a realm name
// alone, with no configuration file. A config named explicitly must exist and
// load; so must a default /etc/krb5.conf that is present but will not load.
func LoadConfig(flagPath string) (*config.Config, error) {
	path := ResolveConfigPath(flagPath)
	explicit := flagPath != "" || os.Getenv("KRB5_CONFIG") != ""

	if _, err := os.Stat(path); err != nil {
		if !explicit && errors.Is(err, fs.ErrNotExist) {
			return DNSConfig(), nil
		}

		return nil, fmt.Errorf("krb5 config %q: %w", path, err)
	}

	return config.Load(path)
}

// DNSConfig is the configuration ktman uses when there is no krb5.conf: each
// realm's KDCs are found from DNS SRV records (dns_lookup_kdc), and a realm is
// found from a host's domain the same way (dns_lookup_realm). It lets login and
// service-ticket requests work from a realm name with no configuration file.
func DNSConfig() *config.Config {
	c := config.New()
	c.LibDefaults.DNSLookupKDC = true
	c.LibDefaults.DNSLookupRealm = true

	return c
}

// DefaultPrincipal returns the principal name (components joined, no realm) and
// realm of the keytab's first entry, the sensible default to log in as.
func DefaultPrincipal(kt *keytab.Keytab) (name, realm string) {
	if len(kt.Entries) == 0 {
		return "", ""
	}

	p := kt.Entries[0].Principal

	return strings.Join(p.Components, "/"), p.Realm
}

// RealmForPrincipal returns the realm of the first keytab entry whose name
// (components joined with "/") equals principal, or "" if none matches. It lets
// a login default the realm from the keytab itself rather than config.
func RealmForPrincipal(kt *keytab.Keytab, principal string) string {
	for _, e := range kt.Entries {
		if strings.Join(e.Principal.Components, "/") == principal {
			return e.Principal.Realm
		}
	}

	return ""
}

// TGTInfo describes a TGT obtained from a keytab.
type TGTInfo struct {
	Principal string
	Realm     string
	SName     string
	StartTime time.Time
	EndTime   time.Time
	RenewTill time.Time
	Flags     []string
}

// Login authenticates as a keytab principal and returns a logged-in client and
// the details of the TGT it got. The caller owns the client and must call
// Destroy on it (NewWithKeytab + Login start background renewal goroutines).
//
// principal is the name without the realm (an "@realm" suffix, if present, is
// stripped and used when realm is empty). An empty realm falls back to that
// suffix, then to krb5.conf's default_realm.
func Login(kt *keytab.Keytab, principal, realm string, cfg *config.Config) (*client.Client, TGTInfo, error) {
	principal, realm = NormalizePrincipal(principal, realm)

	// With no explicit realm, use the realm of the keytab entry that matches
	// this principal, so a keytab holding more than one realm logs in as the
	// right one (not the first entry's realm, nor only default_realm).
	if realm == "" {
		realm = RealmForPrincipal(kt, principal)
	}

	cl := client.NewWithKeytab(principal, realm, kt, cfg)

	if err := cl.Login(); err != nil {
		cl.Destroy()
		return nil, TGTInfo{}, err
	}

	info := TGTInfo{Principal: principal, Realm: realm}

	cc, err := cl.CCache()
	if err != nil {
		return cl, info, fmt.Errorf("got TGT but could not read it back: %w", err)
	}

	for _, e := range cc.GetEntries() {
		ns := e.Server.PrincipalName.NameString
		if len(ns) > 0 && ns[0] == "krbtgt" {
			info.Principal = e.Client.PrincipalName.PrincipalNameString()
			info.Realm = e.Client.Realm
			info.SName = e.Server.PrincipalName.PrincipalNameString() + "@" + e.Server.Realm
			info.StartTime = startOrAuth(e.StartTime, e.AuthTime)
			info.EndTime = e.EndTime
			info.RenewTill = e.RenewTill
			info.Flags = FlagNames(e.TicketFlags)

			break
		}
	}

	return cl, info, nil
}

// startOrAuth returns the ticket start time, falling back to the auth time
// when the KDC omitted a distinct start time (MIT does when they are equal).
func startOrAuth(start, auth time.Time) time.Time {
	if start.IsZero() {
		return auth
	}

	return start
}

// SvcInfo describes a service ticket.
type SvcInfo struct {
	SName          string
	Realm          string
	EType          int32
	ETypeName      string
	KVNO           int
	SessionKeyType int32
	StartTime      time.Time
	EndTime        time.Time
	RenewTill      time.Time
	Flags          []string
}

// ServiceTicket gets a ticket for the SPN (format SERVICE/fqdn) using the
// client's TGT, and returns its details.
func ServiceTicket(cl *client.Client, spn string) (SvcInfo, error) {
	tkt, key, err := cl.GetServiceTicket(spn)
	if err != nil {
		return SvcInfo{}, err
	}

	info := SvcInfo{
		SName:          tkt.SName.PrincipalNameString(),
		Realm:          tkt.Realm,
		EType:          tkt.EncPart.EType,
		ETypeName:      EtypeName(tkt.EncPart.EType),
		KVNO:           tkt.EncPart.KVNO,
		SessionKeyType: key.KeyType,
	}

	// Flags and times come from the credential cache: the ticket itself is
	// sealed with the service's key, so its flags cannot be read from it.
	cc, err := cl.CCache()
	if err == nil {
		want := tkt.SName.PrincipalNameString()
		for _, e := range cc.GetEntries() {
			if e.Server.PrincipalName.PrincipalNameString() == want {
				info.StartTime = startOrAuth(e.StartTime, e.AuthTime)
				info.EndTime = e.EndTime
				info.RenewTill = e.RenewTill
				info.Flags = FlagNames(e.TicketFlags)

				break
			}
		}
	}

	return info, nil
}
