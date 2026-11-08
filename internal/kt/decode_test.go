package kt

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/x/encoding/asn1"

	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/types"
)

// A ticket made for a service in a keytab decodes: the outer part always, the
// encrypted part with the service's keytab, and the session key's bytes only
// when asked for.
func TestDecodeTicket(t *testing.T) {
	sname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/web.example.test")
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	skt := keytab.New()
	if err := skt.AddEntry("HTTP/web.example.test", "EXAMPLE.TEST", "pw", time.Unix(1000, 0), 3, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	tkt, skey, err := messages.NewTicket(cname, "OTHER.TEST", sname, "EXAMPLE.TEST", asn1.BitString{Bytes: make([]byte, 4), BitLength: 32},
		skt, etypeID.AES256_CTS_HMAC_SHA1_96, 3, now, now, now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	svc := SvcInfo{Ticket: tkt, SessionKey: skey}
	keyHex := hex.EncodeToString(skey.KeyValue)

	var sealed strings.Builder

	DecodeTicket(&sealed, svc, true, keytab.New())

	for _, want := range []string{"realm:     EXAMPLE.TEST", "HTTP/web.example.test (name-type 1)", "kvno:    3", "sealed: no keytab given holds HTTP/web.example.test@EXAMPLE.TEST kvno 3"} {
		if !strings.Contains(sealed.String(), want) {
			t.Errorf("sealed output lacks %q:\n%s", want, sealed.String())
		}
	}

	var open strings.Builder

	DecodeTicket(&open, svc, false, nil, skt)

	for _, want := range []string{"crealm:    OTHER.TEST", "cname:     alice (name-type 1)", "32 bytes (the session key the KDC gave the client)", "authorization-data: none"} {
		if !strings.Contains(open.String(), want) {
			t.Errorf("decoded output lacks %q:\n%s", want, open.String())
		}
	}

	if strings.Contains(open.String(), keyHex) || strings.Contains(open.String(), "keyvalue") {
		t.Errorf("session key shown without showKeys:\n%s", open.String())
	}

	var keys strings.Builder

	DecodeTicket(&keys, svc, true, skt)

	if !strings.Contains(keys.String(), "keyvalue: "+keyHex) {
		t.Errorf("showKeys did not show the session key:\n%s", keys.String())
	}
}
