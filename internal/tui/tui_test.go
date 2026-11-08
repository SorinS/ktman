package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/go-krb5/x/encoding/asn1"
	"github.com/SorinS/krb5/iana/etypeID"
	"github.com/SorinS/krb5/iana/nametype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/types"

	"sorins/ktman/internal/kt"
)

func testKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()

	k := keytab.New()
	if err := k.AddEntry("HTTP/web", "EXAMPLE.TEST", "pw", time.Unix(1000, 0), 1, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}

	if err := k.AddEntry("host/web", "EXAMPLE.TEST", "pw", time.Unix(1000, 0), 1, etypeID.AES128_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}

	return k
}

// The model renders the two-pane view with the entries table, the help panel
// and the key-hint bar, and the arrow keys move the selection — no terminal or
// KDC needed.
func TestModelRendersAndNavigates(t *testing.T) {
	m := newModel(testKeytab(t), "web.keytab", "", "", "/nonexistent/krb5.conf", "", "")
	m.width, m.height = 120, 30

	view := m.View()
	for _, want := range []string{"ktman", "PRINCIPAL", "HTTP/web@EXAMPLE.TEST", "host/web@EXAMPLE.TEST", "Add entry", "ctrl+a"} {
		if !strings.Contains(view, want) {
			t.Errorf("view missing %q", want)
		}
	}

	if m.cursor != 0 {
		t.Fatalf("cursor should start at 0, got %d", m.cursor)
	}

	m.Update(tea.KeyMsg{Type: tea.KeyDown})
	if m.cursor != 1 {
		t.Fatalf("after down, cursor = %d, want 1", m.cursor)
	}

	m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m.Update(tea.KeyMsg{Type: tea.KeyUp})

	if m.cursor != 0 {
		t.Fatalf("after up, cursor = %d, want 0", m.cursor)
	}
}

// Requesting a service ticket before a TGT is a friendly error, not a crash.
func TestServiceTicketWithoutTGT(t *testing.T) {
	m := newModel(testKeytab(t), "web.keytab", "", "", "/nonexistent/krb5.conf", "", "")
	m.spnInput.SetValue("HTTP/host.example.test")

	if cmd := m.getServiceTicket(); cmd != nil {
		t.Fatal("expected no command when there is no TGT yet")
	}

	if !m.isErr || !strings.Contains(m.status, "TGT first") {
		t.Fatalf("expected a 'get a TGT first' status, got isErr=%v %q", m.isErr, m.status)
	}
}

// A TGT result message updates the model's state and status.
func TestTGTMessageUpdatesState(t *testing.T) {
	m := newModel(testKeytab(t), "web.keytab", "", "", "/nonexistent/krb5.conf", "", "")

	tgt := kt.TGTInfo{
		Principal: "web",
		Realm:     "EXAMPLE.TEST",
		SName:     "krbtgt/EXAMPLE.TEST@EXAMPLE.TEST",
		EndTime:   time.Unix(2000, 0),
	}
	m.Update(tgtMsg{tgt: tgt, err: nil})

	if !m.haveTGT {
		t.Fatal("haveTGT should be true after a successful tgtMsg")
	}

	if m.isErr {
		t.Fatalf("status should not be an error: %q", m.status)
	}

	if !strings.Contains(m.status, "TGT OK") {
		t.Fatalf("status should report TGT OK, got %q", m.status)
	}
}

// A panic inside a command goroutine is recovered and delivered as an error
// message, so a library crash shows in the status line instead of killing the
// whole UI (which would lose unsaved edits).
func TestSafeMsgRecoversPanic(t *testing.T) {
	got := safeMsg(
		func() tea.Msg { panic("boom") },
		func(r any) tea.Msg { return tgtMsg{err: fmt.Errorf("recovered: %v", r)} },
	)

	tm, ok := got.(tgtMsg)
	if !ok {
		t.Fatalf("want tgtMsg from a recovered panic, got %T", got)
	}

	if tm.err == nil || !strings.Contains(tm.err.Error(), "boom") {
		t.Fatalf("recovered error should name the panic, got %v", tm.err)
	}

	// And the recovered message drives the Update loop to a clean error state.
	m := newModel(testKeytab(t), "web.keytab", "", "", "/nonexistent/krb5.conf", "", "")
	m.busy = true
	m.Update(tm)

	if m.busy {
		t.Fatal("busy should clear after a recovered-panic tgtMsg")
	}

	if !m.isErr || !strings.Contains(m.status, "boom") {
		t.Fatalf("status should report the recovered panic, got isErr=%v %q", m.isErr, m.status)
	}
}

// Clone adds a copy of the selected entry with a new kvno; delete removes the
// selected entry. Both mark the keytab unsaved.
func TestCloneAndDelete(t *testing.T) {
	m := newModel(testKeytab(t), "web.keytab", "", "", "/nonexistent/krb5.conf", "", "")

	if len(m.rows) != 2 {
		t.Fatalf("want 2 rows, got %d", len(m.rows))
	}

	m.cursor = 0
	m.doClone(5)

	if len(m.rows) != 3 {
		t.Fatalf("after clone want 3 rows, got %d", len(m.rows))
	}

	if !m.dirty {
		t.Fatal("clone should mark the keytab unsaved")
	}

	if m.rows[2].KVNO != 5 {
		t.Fatalf("cloned entry kvno = %d, want 5", m.rows[2].KVNO)
	}

	if m.rows[2].Principal != "HTTP/web@EXAMPLE.TEST" {
		t.Fatalf("cloned principal = %q", m.rows[2].Principal)
	}

	m.cursor = 2
	m.deleteEntry()

	if len(m.rows) != 2 {
		t.Fatalf("after delete want 2 rows, got %d", len(m.rows))
	}
}

// Opening a path that does not exist yet starts an empty keytab bound to it,
// and saving creates the file there; a file that will not parse is refused.
func TestOpenMissingKeytabCreatesOnSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.keytab")

	m := newModel(nil, "", "", "", "/nonexistent/krb5.conf", "", "")
	m.promptKind = promptOpen
	m.applyPrompt(path)

	if m.isErr || m.ktPath != path || len(m.ktab.Entries) != 0 {
		t.Fatalf("open of a missing path: isErr=%v ktPath=%q entries=%d status=%q",
			m.isErr, m.ktPath, len(m.ktab.Entries), m.status)
	}

	m.ktab = testKeytab(t)
	m.save()

	if m.isErr {
		t.Fatalf("save failed: %s", m.status)
	}

	k, err := kt.Load(path)
	if err != nil || len(k.Entries) != 2 {
		t.Fatalf("saved keytab: err=%v", err)
	}

	bad := filepath.Join(dir, "bad.keytab")
	if err := os.WriteFile(bad, []byte("not a keytab"), 0o600); err != nil {
		t.Fatal(err)
	}

	m.promptKind = promptOpen
	m.applyPrompt(bad)

	if !m.isErr || m.ktPath != path {
		t.Fatalf("open of a bad keytab: isErr=%v ktPath=%q", m.isErr, m.ktPath)
	}
}

// ctrl+x on the test screen shows the service ticket decoded with the open
// keytab's service key, scrolls, and esc goes back.
func TestDecodeView(t *testing.T) {
	k := testKeytab(t)
	sname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/web")
	now := time.Now().UTC()

	tkt, skey, err := messages.NewTicket(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), "EXAMPLE.TEST", sname, "EXAMPLE.TEST",
		asn1.BitString{Bytes: make([]byte, 4), BitLength: 32}, k, etypeID.AES256_CTS_HMAC_SHA1_96, 1, now, now, now.Add(time.Hour), time.Time{})
	if err != nil {
		t.Fatal(err)
	}

	m := newModel(k, "web.keytab", "", "", "/nonexistent/krb5.conf", "", "")
	m.width, m.height = 120, 14
	m.mode = modeTest
	m.haveSvc = true
	m.svc = kt.SvcInfo{SName: "HTTP/web", Realm: "EXAMPLE.TEST", Ticket: tkt, SessionKey: skey}

	m.Update(tea.KeyMsg{Type: tea.KeyCtrlX})

	if m.mode != modeDecode {
		t.Fatalf("ctrl+x: mode %v, status %q", m.mode, m.status)
	}

	if view := m.View(); !strings.Contains(view, "Service ticket, decoded") || !strings.Contains(view, "realm:     EXAMPLE.TEST") {
		t.Errorf("decode view:\n%s", view)
	}

	m.Update(tea.KeyMsg{Type: tea.KeyEnd})

	if m.decodedTop == 0 || !strings.Contains(m.View(), "authorization-data: none") {
		t.Errorf("end did not scroll to the decrypted part (top %d):\n%s", m.decodedTop, m.View())
	}

	m.Update(tea.KeyMsg{Type: tea.KeyEsc})

	if m.mode != modeTest {
		t.Fatalf("esc: mode %v", m.mode)
	}
}
