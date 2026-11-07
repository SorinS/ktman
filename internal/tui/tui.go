// Package tui is ktman's terminal UI, built on Bubble Tea: a two-pane keytab
// manager — an entries table on the left, a help panel on the right, a status
// line and a key-hint bar below. It edits a keytab in memory (add, edit, clone,
// delete) and writes it on ctrl+s, and tests an entry by getting a TGT and a
// service ticket. All Kerberos and keytab work happens in package kt.
package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/go-krb5/krb5/client"
	"github.com/go-krb5/krb5/config"
	"github.com/go-krb5/krb5/keytab"

	"sorins/ktman/internal/kt"
)

type mode int

const (
	modeBrowse mode = iota
	modeForm        // add or edit an entry
	modePrompt      // a one-line prompt (open / save-as / clone kvno)
	modeTest        // get a TGT and a service ticket for an entry
)

// the entry form's fields, in order.
const (
	fPrincipal = iota
	fRealm
	fETypes
	fKVNO
	fPassword
	fFieldCount
)

// what a one-line prompt will do with its value.
type promptKind int

const (
	promptOpen promptKind = iota
	promptSaveAs
	promptCloneKVNO
)

const helpWidth = 30

var (
	barStyle     = lipgloss.NewStyle().Background(lipgloss.Color("24")).Foreground(lipgloss.Color("231")).Bold(true)
	titleStyle   = lipgloss.NewStyle().Background(lipgloss.Color("24")).Foreground(lipgloss.Color("231")).Bold(true)
	sectionStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252")).Bold(true)
	keyStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	descStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("45")).Bold(true)
	selRowStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("16")).Background(lipgloss.Color("212")).Bold(true)
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	okStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	errStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	paneStyle    = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("37")).Padding(0, 1)
	chipKey      = lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true)
	chipLabel    = lipgloss.NewStyle().Background(lipgloss.Color("238")).Foreground(lipgloss.Color("231"))
)

type model struct {
	width, height int

	ktab   *keytab.Keytab
	ktPath string
	dirty  bool

	rows   []kt.Row
	cursor int

	mode   mode
	helpOn bool

	cfg    *config.Config
	cfgErr error

	ldapAddr string // AD LDAP HOST:PORT for ctrl+k (Get KVNO from AD)
	dcHost   string // the DC host name, for the ldap/<dcHost> bind

	// form (add / edit)
	form      [fFieldCount]textinput.Model
	formFocus int
	formEdit  bool
	formIndex int
	etypeIdx  int // index into kt.SupportedETypes, the form's enctype dropdown

	// one-line prompt
	prompt      textinput.Model
	promptKind  promptKind
	promptLabel string

	// test
	spnInput  textinput.Model
	cl        *client.Client
	haveTGT   bool
	tgt       kt.TGTInfo
	testEntry int
	haveSvc   bool
	svc       kt.SvcInfo

	busy   bool
	status string
	isErr  bool
}

type tgtMsg struct {
	cl  *client.Client
	tgt kt.TGTInfo
	err error
}

type svcMsg struct {
	svc kt.SvcInfo
	err error
}

type kvnoMsg struct {
	kvno uint32
	err  error
}

// Run starts the TUI. ktPath may be empty; a given path is loaded, and one that
// will not open starts an empty keytab with the reason shown.
func Run(ktPath, principal, realm, cfgPath, ldapAddr, dcHost string) error {
	var (
		ktab    *keytab.Keytab
		loadErr error
	)

	if ktPath != "" {
		ktab, loadErr = kt.Load(ktPath)
	}

	if ktab == nil {
		ktab = keytab.New()
	}

	m := newModel(ktab, ktPath, principal, realm, cfgPath, ldapAddr, dcHost)

	if loadErr != nil {
		m.isErr = true
		m.status = "could not open " + ktPath + ": " + loadErr.Error()
		m.ktPath = ""
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()

	if m.cl != nil {
		m.cl.Destroy()
	}

	return err
}

func newModel(ktab *keytab.Keytab, ktPath, principal, realm, cfgPath, ldapAddr, dcHost string) *model {
	if ktab == nil {
		ktab = keytab.New()
	}

	m := &model{
		ktab:     ktab,
		ktPath:   ktPath,
		rows:     kt.Rows(ktab),
		mode:     modeBrowse,
		helpOn:   true,
		ldapAddr: ldapAddr,
		dcHost:   dcHost,
	}

	m.form[fPrincipal] = mkInput("principal: ", "SERVICE/host or a user name", 256, false)
	m.form[fRealm] = mkInput("realm:     ", "REALM", 128, false)
	m.form[fRealm].SetValue(realm)
	m.form[fETypes] = mkInput("enctypes:  ", "blank = aes256-cts, aes128-cts", 256, false)
	m.form[fKVNO] = mkInput("kvno:      ", "1", 9, false)
	m.form[fPassword] = mkInput("password:  ", "", 256, true)

	m.prompt = mkInput("", "", 512, false)
	m.spnInput = mkInput("spn: ", "SERVICE/fqdn e.g. HTTP/host.example.com", 256, false)

	m.cfg, m.cfgErr = kt.LoadConfig(cfgPath)
	m.cursorToPrincipal(principal)

	return m
}

func mkInput(prompt, placeholder string, limit int, password bool) textinput.Model {
	t := textinput.New()
	t.Prompt = prompt
	t.Placeholder = placeholder
	t.CharLimit = limit

	if password {
		t.EchoMode = textinput.EchoPassword
	}

	return t
}

func (m *model) cursorToPrincipal(principal string) {
	if principal == "" {
		return
	}

	want := principal
	if at := strings.LastIndex(want, "@"); at >= 0 {
		want = want[:at]
	}

	for i, r := range m.rows {
		if strings.HasPrefix(r.Principal, want+"@") || r.Principal == want {
			m.cursor = i
			break
		}
	}
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tgtMsg:
		m.busy = false
		if msg.err != nil {
			m.isErr = true
			m.status = "login failed: " + msg.err.Error()

			return m, nil
		}

		if m.cl != nil {
			m.cl.Destroy()
		}

		m.cl = msg.cl
		m.tgt = msg.tgt
		m.haveTGT = true
		m.isErr = false
		m.status = fmt.Sprintf("TGT OK for %s@%s", msg.tgt.Principal, msg.tgt.Realm)

		return m, nil

	case svcMsg:
		m.busy = false
		if msg.err != nil {
			m.isErr = true
			m.status = "service ticket failed: " + msg.err.Error()

			return m, nil
		}

		m.haveSvc = true
		m.svc = msg.svc
		m.isErr = false
		m.status = fmt.Sprintf("ticket %s@%s [%s]", msg.svc.SName, msg.svc.Realm, msg.svc.ETypeName)

		return m, nil

	case kvnoMsg:
		m.busy = false
		if msg.err != nil {
			m.isErr = true
			m.status = "Get KVNO from AD failed: " + msg.err.Error()

			return m, nil
		}

		m.form[fKVNO].SetValue(strconv.FormatUint(uint64(msg.kvno), 10))
		m.isErr = false
		m.status = fmt.Sprintf("AD kvno = %d (edit it if you need another)", msg.kvno)

		return m, nil
	}

	return m, nil
}

func (m *model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		return m, tea.Quit
	}

	switch m.mode {
	case modeForm:
		return m.handleFormKey(msg)
	case modePrompt:
		return m.handlePromptKey(msg)
	case modeTest:
		return m.handleTestKey(msg)
	default:
		return m.handleBrowseKey(msg)
	}
}

func (m *model) handleBrowseKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+q", "q":
		return m, tea.Quit
	case "ctrl+h":
		m.helpOn = !m.helpOn
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.rows)-1 {
			m.cursor++
		}
	case "ctrl+n":
		m.newKeytab()
	case "ctrl+o":
		m.startPrompt(promptOpen, "Open keytab: ", m.ktPath)
	case "ctrl+s":
		m.save()
	case "ctrl+a":
		m.startForm(false)
	case "ctrl+e":
		m.startForm(true)
	case "ctrl+l":
		m.startClone()
	case "ctrl+d":
		m.deleteEntry()
	case "ctrl+t":
		return m, m.startTest()
	case "ctrl+k":
		m.isErr = true
		m.status = "Get KVNO from AD: open the add/edit form (ctrl+a or ctrl+e), then press ctrl+k"
	}

	return m, nil
}

// ---- new / open / save ----

func (m *model) newKeytab() {
	m.ktab = keytab.New()
	m.ktPath = ""
	m.rows = nil
	m.cursor = 0
	m.dirty = false
	m.isErr = false
	m.status = "new empty keytab (ctrl+a to add an entry, ctrl+s to save)"
}

func (m *model) save() {
	if len(m.ktab.Entries) == 0 {
		m.isErr = true
		m.status = "nothing to save (the keytab is empty)"

		return
	}

	if m.ktPath == "" {
		m.startPrompt(promptSaveAs, "Save as: ", "")
		return
	}

	if err := kt.Save(m.ktab, m.ktPath); err != nil {
		m.isErr = true
		m.status = "save failed: " + err.Error()

		return
	}

	m.dirty = false
	m.isErr = false
	m.status = "saved " + m.ktPath
}

func (m *model) startPrompt(kind promptKind, label, value string) {
	m.mode = modePrompt
	m.promptKind = kind
	m.promptLabel = label
	m.prompt.Prompt = label
	m.prompt.SetValue(value)
	m.prompt.CursorEnd()
	m.prompt.Focus()
}

func (m *model) handlePromptKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeBrowse
		m.prompt.Blur()

		return m, nil
	case "enter":
		m.applyPrompt(strings.TrimSpace(m.prompt.Value()))
		return m, nil
	}

	var cmd tea.Cmd
	m.prompt, cmd = m.prompt.Update(msg)

	return m, cmd
}

func (m *model) applyPrompt(value string) {
	switch m.promptKind {
	case promptOpen:
		if value == "" {
			m.isErr = true
			m.status = "type a keytab path"

			return
		}

		ktab, err := kt.Load(value)
		if err != nil {
			m.isErr = true
			m.status = "open failed: " + err.Error()

			return
		}

		m.ktab = ktab
		m.ktPath = value
		m.rows = kt.Rows(ktab)
		m.cursor = 0
		m.dirty = false
		m.mode = modeBrowse
		m.prompt.Blur()
		m.isErr = false
		m.status = "opened " + value

	case promptSaveAs:
		if value == "" {
			m.isErr = true
			m.status = "type a path to save to"

			return
		}

		m.ktPath = value
		m.mode = modeBrowse
		m.prompt.Blur()
		m.save()

	case promptCloneKVNO:
		kvno, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			m.isErr = true
			m.status = "kvno must be a number"

			return
		}

		m.doClone(uint32(kvno))
		m.mode = modeBrowse
		m.prompt.Blur()
	}
}

// ---- add / edit / clone / delete ----

func (m *model) startForm(edit bool) {
	m.mode = modeForm
	m.formEdit = edit
	m.formFocus = fPrincipal

	for i := range m.form {
		m.form[i].Blur()
	}

	if edit {
		if len(m.rows) == 0 {
			m.mode = modeBrowse
			m.isErr = true
			m.status = "no entry to edit"

			return
		}

		m.formIndex = m.cursor
		e := m.ktab.Entries[m.cursor]
		m.form[fPrincipal].SetValue(strings.Join(e.Principal.Components, "/"))
		m.form[fRealm].SetValue(e.Principal.Realm)
		m.etypeIdx = etypeIndex(e.Key.KeyType)
		m.form[fKVNO].SetValue(strconv.FormatUint(uint64(e.KVNO), 10))
		m.form[fPassword].SetValue("")
	} else {
		m.form[fPrincipal].SetValue("")
		m.etypeIdx = 0
		m.form[fKVNO].SetValue("1")
		m.form[fPassword].SetValue("")
		// realm is kept from the last entry/flag as a convenience.
	}

	m.form[m.formFocus].Focus()
}

func (m *model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeBrowse
		m.blurForm()

		return m, nil
	case "ctrl+k":
		return m, m.fetchKVNOFromAD()
	case "tab", "down":
		m.formFocus = (m.formFocus + 1) % fFieldCount
		m.focusForm()

		return m, nil
	case "shift+tab", "up":
		m.formFocus = (m.formFocus - 1 + fFieldCount) % fFieldCount
		m.focusForm()

		return m, nil
	case "ctrl+s":
		m.commitForm()

		return m, nil
	case "enter":
		if m.formFocus == fFieldCount-1 {
			m.commitForm()

			return m, nil
		}

		m.formFocus++
		m.focusForm()

		return m, nil
	}

	// The enctype field is a dropdown: left/right (or space) cycle it.
	if m.formFocus == fETypes {
		switch msg.String() {
		case "left", "h":
			m.etypeIdx = (m.etypeIdx - 1 + len(kt.SupportedETypes)) % len(kt.SupportedETypes)
		case "right", "l", " ":
			m.etypeIdx = (m.etypeIdx + 1) % len(kt.SupportedETypes)
		}

		return m, nil
	}

	var cmd tea.Cmd
	m.form[m.formFocus], cmd = m.form[m.formFocus].Update(msg)

	return m, cmd
}

func (m *model) commitForm() {
	name, realm := kt.NormalizePrincipal(
		strings.TrimSpace(m.form[fPrincipal].Value()),
		strings.TrimSpace(m.form[fRealm].Value()),
	)

	if name == "" || realm == "" {
		m.isErr = true
		m.status = "a principal and realm are required"

		return
	}

	password := m.form[fPassword].Value()
	if password == "" {
		m.isErr = true
		m.status = "a password is required"

		return
	}

	etype := kt.SupportedETypes[m.etypeIdx]

	kvno := uint32(1)
	if v := strings.TrimSpace(m.form[fKVNO].Value()); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			m.isErr = true
			m.status = "kvno must be a number"

			return
		}

		kvno = uint32(n)
	}

	// On edit, drop the entry being replaced first.
	if m.formEdit && m.formIndex < len(m.ktab.Entries) {
		m.ktab.Entries = append(m.ktab.Entries[:m.formIndex], m.ktab.Entries[m.formIndex+1:]...)
	}

	if err := m.ktab.AddEntryWithSalt(name, realm, password, "", time.Now(), kvno, etype); err != nil {
		m.isErr = true
		m.status = "add " + kt.EtypeName(etype) + ": " + err.Error()
		m.refresh()

		return
	}

	m.dirty = true
	m.mode = modeBrowse
	m.blurForm()
	m.refresh()
	m.isErr = false

	if m.formEdit {
		m.status = "entry replaced (" + kt.EtypeName(etype) + ") — ctrl+s to save"
	} else {
		m.status = fmt.Sprintf("added %s for %s@%s — ctrl+s to save", kt.EtypeName(etype), name, realm)
	}
}

// fetchKVNOFromAD queries AD over LDAP for the form principal's kvno and fills
// the kvno field. It needs the principal, realm and password filled in, and
// the -ldap/-dc addresses on the command line.
func (m *model) fetchKVNOFromAD() tea.Cmd {
	if m.busy {
		return nil
	}

	name, realm := kt.NormalizePrincipal(
		strings.TrimSpace(m.form[fPrincipal].Value()),
		strings.TrimSpace(m.form[fRealm].Value()),
	)

	password := m.form[fPassword].Value()
	if name == "" || realm == "" || password == "" {
		m.isErr = true
		m.status = "Get KVNO from AD needs principal, realm and password filled in"

		return nil
	}

	if m.ldapAddr == "" || m.dcHost == "" {
		m.isErr = true
		m.status = "Get KVNO from AD needs -ldap HOST:PORT and -dc DCHOST on the command line"

		return nil
	}

	m.busy = true
	m.isErr = false
	m.status = "querying AD for " + name + "'s kvno..."

	addr, dc, cfg := m.ldapAddr, m.dcHost, m.cfg

	return func() tea.Msg {
		return safeMsg(
			func() tea.Msg {
				kvno, err := kt.GetKVNOFromAD(name, realm, password, cfg, addr, dc)
				return kvnoMsg{kvno: kvno, err: err}
			},
			func(r any) tea.Msg {
				return kvnoMsg{err: fmt.Errorf("Get KVNO from AD crashed (recovered panic): %v", r)}
			},
		)
	}
}

func (m *model) startClone() {
	if len(m.rows) == 0 {
		m.isErr = true
		m.status = "no entry to clone"

		return
	}

	next := m.ktab.Entries[m.cursor].KVNO + 1
	m.startPrompt(promptCloneKVNO, "Clone with kvno: ", strconv.FormatUint(uint64(next), 10))
}

// doClone appends a copy of the selected entry with a new kvno and the current
// time, reusing its derived key (no password needed).
func (m *model) doClone(kvno uint32) {
	if m.cursor >= len(m.ktab.Entries) {
		return
	}

	clone := m.ktab.Entries[m.cursor]
	clone.SetKVNO(kvno)
	clone.SetTimestamp(time.Now())

	m.ktab.Entries = append(m.ktab.Entries, clone)
	m.dirty = true
	m.refresh()
	m.cursor = len(m.rows) - 1
	m.isErr = false
	m.status = fmt.Sprintf("cloned %s as kvno %d — ctrl+s to save", clone.Principal.String(), kvno)
}

func (m *model) deleteEntry() {
	if len(m.ktab.Entries) == 0 {
		m.isErr = true
		m.status = "no entry to delete"

		return
	}

	gone := m.ktab.Entries[m.cursor].Principal.String()
	m.ktab.Entries = append(m.ktab.Entries[:m.cursor], m.ktab.Entries[m.cursor+1:]...)
	m.dirty = true
	m.refresh()

	if m.cursor >= len(m.rows) && m.cursor > 0 {
		m.cursor--
	}

	m.isErr = false
	m.status = "deleted " + gone + " — ctrl+s to save"
}

func (m *model) refresh() {
	m.rows = kt.Rows(m.ktab)

	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}

	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m *model) focusForm() {
	for i := range m.form {
		if i == m.formFocus {
			m.form[i].Focus()
		} else {
			m.form[i].Blur()
		}
	}
}

func (m *model) blurForm() {
	for i := range m.form {
		m.form[i].Blur()
	}
}

// safeMsg runs a command body under a panic guard. Bubble Tea runs a tea.Cmd in
// its own goroutine and kills the whole program if that goroutine panics (the
// user then sees only "program was killed: context canceled", and any unsaved
// keytab edits are lost). A panic in a library network call must not do that,
// so a recovered panic becomes onPanic(r) — an ordinary result message the
// Update loop can show in the status line, naming the panic so it can be
// reported.
func safeMsg(body func() tea.Msg, onPanic func(r any) tea.Msg) (result tea.Msg) {
	defer func() {
		if r := recover(); r != nil {
			result = onPanic(r)
		}
	}()

	return body()
}

// ---- test (TGT + service ticket) ----

func (m *model) startTest() tea.Cmd {
	if len(m.rows) == 0 {
		m.isErr = true
		m.status = "no entry to test"

		return nil
	}

	m.mode = modeTest
	m.testEntry = m.cursor
	m.haveTGT = false
	m.haveSvc = false
	m.spnInput.SetValue("")
	m.spnInput.Focus()

	if m.cfgErr != nil {
		m.isErr = true
		m.status = "krb5.conf: " + m.cfgErr.Error()

		return nil
	}

	return m.loginSelected()
}

func (m *model) loginSelected() tea.Cmd {
	if m.busy {
		return nil
	}

	e := m.ktab.Entries[m.testEntry]
	principal := strings.Join(e.Principal.Components, "/")
	realm := e.Principal.Realm

	m.busy = true
	m.isErr = false
	m.status = "getting TGT for " + principal + "..."

	ktab := m.ktab
	cfg := m.cfg

	return func() tea.Msg {
		return safeMsg(
			func() tea.Msg {
				cl, tgt, err := kt.Login(ktab, principal, realm, cfg)
				return tgtMsg{cl: cl, tgt: tgt, err: err}
			},
			func(r any) tea.Msg {
				return tgtMsg{err: fmt.Errorf("login crashed (recovered panic): %v", r)}
			},
		)
	}
}

func (m *model) handleTestKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.mode = modeBrowse
		m.spnInput.Blur()

		return m, nil
	case "ctrl+t":
		return m, m.loginSelected()
	case "enter":
		return m, m.getServiceTicket()
	}

	var cmd tea.Cmd
	m.spnInput, cmd = m.spnInput.Update(msg)

	return m, cmd
}

func (m *model) getServiceTicket() tea.Cmd {
	if m.busy {
		return nil
	}

	if !m.haveTGT || m.cl == nil {
		m.isErr = true
		m.status = "get a TGT first (ctrl+t)"

		return nil
	}

	spn := strings.TrimSpace(m.spnInput.Value())
	if spn == "" {
		m.isErr = true
		m.status = "type an SPN (SERVICE/fqdn) first"

		return nil
	}

	m.busy = true
	m.isErr = false
	m.status = "getting service ticket for " + spn + "..."

	cl := m.cl

	return func() tea.Msg {
		return safeMsg(
			func() tea.Msg {
				svc, err := kt.ServiceTicket(cl, spn)
				return svcMsg{svc: svc, err: err}
			},
			func(r any) tea.Msg {
				return svcMsg{err: fmt.Errorf("service ticket crashed (recovered panic): %v", r)}
			},
		)
	}
}

// ---- rendering ----

func (m *model) View() string {
	width := m.width
	if width < 50 {
		width = 100
	}

	height := m.height
	if height < 12 {
		height = 28
	}

	title := titleStyle.Width(width).Render(" " + m.titleText())

	helpOn := m.helpOn && width >= 72

	var help string

	leftW := width

	if helpOn {
		help = paneStyle.Width(helpWidth - 4).Render(m.helpContent())
		leftW = width - lipgloss.Width(help) - 1
	}

	bodyH := height - 5
	if bodyH < 6 {
		bodyH = 6
	}

	left := paneStyle.Width(leftW - 4).Height(bodyH).Render(m.leftContent(leftW - 6))

	body := left
	if helpOn {
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, " ", help)
	}

	return lipgloss.JoinVertical(lipgloss.Left, title, body, m.footerView(width))
}

func (m *model) titleText() string {
	t := "ktman — Keytab Manager"
	if m.ktPath != "" {
		t += "  [" + m.ktPath + "]"
	}

	if m.dirty {
		t += "  *unsaved*"
	}

	return t
}

func (m *model) leftContent(w int) string {
	switch m.mode {
	case modeForm:
		return m.formView()
	case modePrompt:
		return m.promptView()
	case modeTest:
		return m.testView()
	default:
		return m.tableView(w)
	}
}

func (m *model) tableView(w int) string {
	var b strings.Builder

	b.WriteString(headerStyle.Render(fmt.Sprintf("%-5s %-16s %-22s %-26s %s", "KVNO", "TIMESTAMP", "PRINCIPAL", "ENCTYPE", "KEY")))
	b.WriteString("\n")

	if len(m.rows) == 0 {
		b.WriteString(dimStyle.Render("(empty — press ctrl+a to add an entry)"))
		return b.String()
	}

	keyMax := w - 73
	if keyMax < 8 {
		keyMax = 8
	}

	for i, r := range m.rows {
		line := fmt.Sprintf("%-5d %-16s %-22s %-26s %s",
			r.KVNO, fmtTime(r.Timestamp), truncate(r.Principal, 22), truncate(kt.ETypeLabel(r.ETypeID), 26), truncate(r.KeyHex, keyMax))

		if i == m.cursor {
			line = selRowStyle.Render(line)
		}

		b.WriteString(line)
		b.WriteString("\n")
	}

	return strings.TrimRight(b.String(), "\n")
}

func (m *model) formView() string {
	heading := "Add entry"
	if m.formEdit {
		heading = "Edit entry"
	}

	var b strings.Builder

	b.WriteString(headerStyle.Render(heading))
	b.WriteString("\n\n")

	for i := range m.form {
		marker := "  "
		if i == m.formFocus {
			marker = keyStyle.Render("> ")
		}

		if i == fETypes {
			b.WriteString(marker + "enctype:   " + kt.ETypeLabel(kt.SupportedETypes[m.etypeIdx]) + dimStyle.Render("   ‹ › to change"))
			b.WriteString("\n")

			continue
		}

		b.WriteString(marker + m.form[i].View() + "\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("tab/↑↓: fields · ‹ ›: enctype · ctrl+k: kvno from AD · enter: next (password: save) · esc: cancel"))

	return b.String()
}

func (m *model) promptView() string {
	var b strings.Builder

	b.WriteString(headerStyle.Render("Keytab"))
	b.WriteString("\n\n")
	b.WriteString(m.prompt.View())
	b.WriteString("\n\n")
	b.WriteString(dimStyle.Render("enter: confirm · esc: cancel"))

	return b.String()
}

func (m *model) testView() string {
	var b strings.Builder

	e := m.ktab.Entries[m.testEntry]

	b.WriteString(headerStyle.Render("Test entry"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s  (kvno %d, %s)\n\n", e.Principal.String(), e.KVNO, kt.EtypeName(e.Key.KeyType)))

	if m.haveTGT {
		b.WriteString(okStyle.Render("  TGT: "))
		b.WriteString(fmt.Sprintf("%s@%s → %s\n", m.tgt.Principal, m.tgt.Realm, m.tgt.SName))
		b.WriteString(dimStyle.Render(fmt.Sprintf("       valid %s .. %s\n", fmtTime(m.tgt.StartTime), fmtTime(m.tgt.EndTime))))
	} else {
		b.WriteString(dimStyle.Render("  TGT: press ctrl+t to get it\n"))
	}

	b.WriteString("\n  ")
	b.WriteString(m.spnInput.View())
	b.WriteString("\n")

	if m.haveSvc {
		b.WriteString(okStyle.Render("  Ticket: "))
		b.WriteString(fmt.Sprintf("%s@%s [%s]\n", m.svc.SName, m.svc.Realm, m.svc.ETypeName))
		b.WriteString(dimStyle.Render(fmt.Sprintf("          valid %s .. %s\n", fmtTime(m.svc.StartTime), fmtTime(m.svc.EndTime))))
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("ctrl+t: get TGT · type an SPN + enter: service ticket · esc: back"))

	return b.String()
}

func (m *model) helpContent() string {
	kv := func(k, d string) string { return "  " + keyStyle.Render(fmt.Sprintf("%-7s", k)) + descStyle.Render(d) }

	lines := []string{
		sectionStyle.Render("Navigation"),
		"  " + keyStyle.Render("↑ ↓") + descStyle.Render("   Select entry"),
		"",
		sectionStyle.Render("File"),
		kv("ctrl+n", "New keytab"),
		kv("ctrl+o", "Open keytab"),
		kv("ctrl+s", "Save keytab"),
		"",
		sectionStyle.Render("Entry"),
		kv("ctrl+a", "Add entry"),
		kv("ctrl+e", "Edit entry"),
		kv("ctrl+l", "Clone entry"),
		kv("ctrl+d", "Delete entry"),
		"",
		sectionStyle.Render("AD / Testing"),
		kv("ctrl+k", "Get KVNO (AD)"),
		kv("ctrl+t", "Test entry"),
		"",
		sectionStyle.Render("Other"),
		kv("ctrl+h", "Toggle help"),
		kv("ctrl+q", "Quit"),
		kv("ctrl+c", "Force quit"),
		"",
		sectionStyle.Render("Columns"),
		dimStyle.Render("  KVNO    Key version"),
		dimStyle.Render("  ENCTYPE id + name"),
		dimStyle.Render("  KEY     Derived (hex)"),
	}

	return strings.Join(lines, "\n")
}

func (m *model) footerView(width int) string {
	entries := fmt.Sprintf(" Entries: %d", len(m.rows))
	if m.dirty {
		entries += "   *unsaved*"
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		barStyle.Width(width).Render(entries),
		m.statusView(),
		m.chipsView())
}

func (m *model) statusView() string {
	if m.status == "" {
		return dimStyle.Render(" Ready.  ctrl+o Open · ctrl+n New · ctrl+a Add entry")
	}

	style := okStyle
	if m.isErr {
		style = errStyle
	}

	prefix := " "
	if m.busy {
		prefix = " … "
	}

	return style.Render(prefix + m.status)
}

func (m *model) chipsView() string {
	pairs := [][2]string{
		{"ctrl+h", "Help"}, {"ctrl+n", "New"}, {"ctrl+o", "Open"}, {"ctrl+s", "Save"},
		{"ctrl+a", "Add"}, {"ctrl+e", "Edit"}, {"ctrl+l", "Clone"}, {"ctrl+d", "Del"},
		{"ctrl+t", "Test"}, {"ctrl+q", "Quit"},
	}

	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, chipKey.Render(p[0])+chipLabel.Render(" "+p[1]+" "))
	}

	return " " + strings.Join(parts, "  ")
}

// etypeIndex is the position of an encryption-type ID in kt.SupportedETypes, or
// 0 when it is not one we offer (an old entry's type, say).
func etypeIndex(id int32) int {
	for i, e := range kt.SupportedETypes {
		if e == id {
			return i
		}
	}

	return 0
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}

	if len(s) <= n {
		return s
	}

	if n == 1 {
		return "…"
	}

	return s[:n-1] + "…"
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	return t.Local().Format("2006-01-02 15:04")
}
