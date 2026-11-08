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
