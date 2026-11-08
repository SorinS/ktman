package kt

import (
	"testing"
	"time"

	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/keytab"
)

// With no krb5.conf present, LoadConfig falls back to a DNS-discovery config
// (not nil), so a login works from the realm alone.
func TestLoadConfigFallsBackToDNS(t *testing.T) {
	t.Setenv("KRB5_CONFIG", "") // ensure no explicit config
	cfg, err := LoadConfig("")  // no -c; default /etc/krb5.conf is absent here
	if err != nil {
		// Only acceptable if /etc/krb5.conf actually exists on this box.
		t.Skipf("default config present or unreadable: %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadConfig returned a nil config with no error")
	}
	if !cfg.LibDefaults.DNSLookupKDC {
		t.Fatal("fallback config should enable DNS KDC lookup")
	}
}

// An explicitly named but missing config is an error, not a silent fallback.
func TestLoadConfigExplicitMissingErrors(t *testing.T) {
	if _, err := LoadConfig("/nonexistent/ktman/krb5.conf"); err == nil {
		t.Fatal("an explicitly named missing config should error")
	}
}

// A login with a nil config returns a clean error, not a panic (library guard).
func TestNilConfigLoginNoPanic(t *testing.T) {
	k := keytab.New()
	if err := k.AddEntry("test1", "test.goose.com", "pw", time.Unix(1000, 0), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil-config login panicked: %v", r)
		}
	}()
	cl, _, err := Login(k, "test1", "test.goose.com", nil)
	if cl != nil {
		cl.Destroy()
	}
	if err == nil {
		t.Fatal("nil-config login should return an error")
	}
	t.Logf("nil-config login err = %v", err)
}

// -n's enctypes: none is the default pair (as MIT's ktadd); a list is kept in
// order without repeats; the weak types are made when asked for, and a type
// the library lacks is refused.
func TestParseETypes(t *testing.T) {
	ids, err := ParseETypes("")
	if err != nil || len(ids) != 2 || ids[0] != etypeID.AES256_CTS_HMAC_SHA1_96 || ids[1] != etypeID.AES128_CTS_HMAC_SHA1_96 {
		t.Fatalf("default: %v %v", ids, err)
	}

	ids, err = ParseETypes("aes128-cts, aes256-cts,aes128-cts")
	if err != nil || len(ids) != 2 || ids[0] != etypeID.AES128_CTS_HMAC_SHA1_96 || ids[1] != etypeID.AES256_CTS_HMAC_SHA1_96 {
		t.Fatalf("list: %v %v", ids, err)
	}

	ids, err = ParseETypes("rc4-hmac,des3-cbc-sha1-kd")
	if err != nil || len(ids) != 2 || !WeakEType(ids[0]) || !WeakEType(ids[1]) {
		t.Fatalf("weak types: %v %v", ids, err)
	}

	if _, err := ParseETypes("aes256-cts,des-cbc-md5"); err == nil {
		t.Fatal("single DES accepted")
	}

	if c := ETypeChoices(); len(c) != len(SupportedETypes)+1 || len(c[0]) != 2 {
		t.Fatalf("choices: %v", c)
	}
}
