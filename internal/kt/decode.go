package kt

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-krb5/x/rpc/mstypes"

	"github.com/SorinS/krb5/iana/adtype"
	"github.com/SorinS/krb5/keytab"
	"github.com/SorinS/krb5/messages"
	"github.com/SorinS/krb5/pac"
	"github.com/SorinS/krb5/types"
)

// DecodeTicket writes the ticket of a service-ticket result out, field by field
// under its ASN.1 (RFC 4120) names. The outer part is in the clear and always
// shown. The encrypted part, EncTicketPart, and the Microsoft PAC in it are
// shown when one of the keytabs holds the service's key (its principal, realm,
// kvno and enctype); otherwise what is missing is said. The session key's
// bytes are written only with showKeys (as klist -K does): with the ticket
// they let anyone act as the client toward the service until it expires.
// Otherwise only its type and length are.
func DecodeTicket(w io.Writer, svc SvcInfo, showKeys bool, keytabs ...*keytab.Keytab) {
	t := svc.Ticket

	fmt.Fprintln(w, "Ticket")
	fmt.Fprintf(w, "  tkt-vno:   %d\n", t.TktVNO)
	fmt.Fprintf(w, "  realm:     %s\n", t.Realm)
	fmt.Fprintf(w, "  sname:     %s\n", principalString(t.SName))
	fmt.Fprintln(w, "  enc-part:")
	fmt.Fprintf(w, "    etype:   %s\n", ETypeLabel(t.EncPart.EType))
	fmt.Fprintf(w, "    kvno:    %d\n", t.EncPart.KVNO)
	fmt.Fprintf(w, "    cipher:  %d bytes\n", len(t.EncPart.Cipher))

	skt := serviceKeytab(keytabs, t)
	if skt == nil {
		fmt.Fprintf(w, "\n  (sealed: no keytab given holds %s@%s kvno %d %s, the service's key)\n",
			t.SName.PrincipalNameString(), t.Realm, t.EncPart.KVNO, EtypeName(t.EncPart.EType))

		return
	}

	if err := t.DecryptEncPart(skt, nil); err != nil {
		fmt.Fprintf(w, "\n  (could not decrypt with the keytab's key, wrong password or salt?): %v\n", err)
		return
	}

	e := t.DecryptedEncPart

	fmt.Fprintln(w, "\nEncTicketPart (decrypted with the service's key)")
	fmt.Fprintf(w, "  flags:     %s\n", strings.Join(FlagNames(e.Flags), " "))
	fmt.Fprintf(w, "  key:       %s, %d bytes%s\n", ETypeLabel(e.Key.KeyType), len(e.Key.KeyValue), sessionKeyCheck(e.Key, svc.SessionKey))
	if showKeys {
		fmt.Fprintf(w, "    keyvalue: %s\n", hex.EncodeToString(e.Key.KeyValue))
	}

	fmt.Fprintf(w, "  crealm:    %s\n", e.CRealm)
	fmt.Fprintf(w, "  cname:     %s\n", principalString(e.CName))
	fmt.Fprintf(w, "  transited: type %d, %s\n", e.Transited.TRType, transitedString(e))
	fmt.Fprintf(w, "  authtime:  %s\n", decodeTime(e.AuthTime))
	fmt.Fprintf(w, "  starttime: %s\n", decodeTime(e.StartTime))
	fmt.Fprintf(w, "  endtime:   %s\n", decodeTime(e.EndTime))
	fmt.Fprintf(w, "  renew-till: %s\n", decodeTime(e.RenewTill))

	if len(e.CAddr) > 0 {
		fmt.Fprintf(w, "  caddr:     %d address(es)\n", len(e.CAddr))
	}

	if len(e.AuthorizationData) == 0 {
		fmt.Fprintln(w, "  authorization-data: none")
		return
	}

	fmt.Fprintln(w, "  authorization-data:")
	writeAD(w, e.AuthorizationData, "    ")

	isPAC, p, err := t.GetPACType(skt, nil, trace)
	if !isPAC {
		return
	}

	writePAC(w, p, err)
}

// serviceKeytab is the first of keytabs that holds the ticket's service key,
// nil if none does.
func serviceKeytab(keytabs []*keytab.Keytab, t messages.Ticket) *keytab.Keytab {
	for _, kt := range keytabs {
		if kt == nil {
			continue
		}

		if _, _, err := kt.GetEncryptionKey(t.SName, t.Realm, t.EncPart.KVNO, t.EncPart.EType); err == nil {
			return kt
		}
	}

	return nil
}

func principalString(p types.PrincipalName) string {
	return fmt.Sprintf("%s (name-type %d)", p.PrincipalNameString(), p.NameType)
}

func decodeTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// sessionKeyCheck says whether the ticket's session key is the one the KDC
// gave the client, which it must be.
func sessionKeyCheck(inTicket, fromKDC types.EncryptionKey) string {
	if len(fromKDC.KeyValue) == 0 {
		return ""
	}

	if inTicket.KeyType == fromKDC.KeyType && subtle.ConstantTimeCompare(inTicket.KeyValue, fromKDC.KeyValue) == 1 {
		return " (the session key the KDC gave the client)"
	}

	return " (NOT the session key the KDC gave the client)"
}

// transitedString is the transited realms (domain-X500-compress, RFC 4120
// 3.3.3.2). A direct trust leaves it empty: the hop shows as crealm vs realm.
func transitedString(e messages.EncTicketPart) string {
	if len(e.Transited.Contents) > 0 {
		return fmt.Sprintf("%q", string(e.Transited.Contents))
	}

	if e.CRealm != "" {
		return "empty (no realm between the client's and this one's)"
	}

	return "empty"
}

var adTypeNames = map[int32]string{
	adtype.ADIfRelevant:                  "AD-IF-RELEVANT",
	adtype.ADIntendedForServer:           "AD-INTENDED-FOR-SERVER",
	adtype.ADIntendedForApplicationClass: "AD-INTENDED-FOR-APPLICATION-CLASS",
	adtype.ADKDCIssued:                   "AD-KDC-ISSUED",
	adtype.ADAndOr:                       "AD-AND-OR",
	adtype.ADMandatoryTicketExtensions:   "AD-MANDATORY-TICKET-EXTENSIONS",
	adtype.ADInTicketExtensions:          "AD-IN-TICKET-EXTENSIONS",
	adtype.ADMandatoryForKDC:             "AD-MANDATORY-FOR-KDC",
	adtype.ADOSFDCEPKICertID:             "OSF-DCE-PKI-CERTID",
	adtype.ADAuthenticationStrength:      "AD-AUTHENTICATION-STRENGTH",
	adtype.ADFXFastArmor:                 "AD-FX-FAST-ARMOR",
	adtype.ADFXFastUsed:                  "AD-FX-FAST-USED",
	adtype.ADWin2KPAC:                    "AD-WIN2K-PAC",
	adtype.ADEtypeNegotiation:            "AD-ETYPE-NEGOTIATION",
	141:                                  "KERB-AD-RESTRICTION-ENTRY",
	142:                                  "KERB-LOCAL",
	143:                                  "AD-AUTH-DATA-AP-OPTIONS",
}

func adTypeName(t int32) string {
	if n, ok := adTypeNames[t]; ok {
		return fmt.Sprintf("%s (%d)", n, t)
	}

	return fmt.Sprintf("unknown (%d)", t)
}

// writeAD lists authorization data elements, opening AD-IF-RELEVANT ones.
func writeAD(w io.Writer, ad types.AuthorizationData, indent string) {
	for _, el := range ad {
		fmt.Fprintf(w, "%s%s, %d bytes\n", indent, adTypeName(el.ADType), len(el.ADData))

		if el.ADType != adtype.ADIfRelevant {
			continue
		}

		var inner types.AuthorizationData
		if err := inner.Unmarshal(el.ADData); err != nil {
			fmt.Fprintf(w, "%s  (does not decode: %v)\n", indent, err)
			continue
		}

		writeAD(w, inner, indent+"  ")
	}
}

// The PAC buffer types, MS-PAC 2.4.
var pacTypeNames = map[uint32]string{
	1:  "LOGON_INFO",
	2:  "CREDENTIALS_INFO",
	6:  "SERVER_CHECKSUM",
	7:  "PRIVSVR_CHECKSUM",
	10: "CLIENT_INFO",
	11: "CONSTRAINED_DELEGATION_INFO",
	12: "UPN_DNS_INFO",
	13: "CLIENT_CLAIMS_INFO",
	14: "DEVICE_INFO",
	15: "DEVICE_CLAIMS_INFO",
	16: "TICKET_CHECKSUM",
	17: "ATTRIBUTES_INFO",
	18: "REQUESTOR",
	19: "FULL_CHECKSUM",
}

// The PAC signature types, MS-PAC 2.8.
var sigTypeNames = map[uint32]string{
	0xFFFFFF76: "hmac-md5",
	15:         "hmac-sha1-96-aes128",
	16:         "hmac-sha1-96-aes256",
}

func writePAC(w io.Writer, p pac.PACType, err error) {
	fmt.Fprintln(w, "\nPAC (MS-PAC)")

	switch {
	case err == nil:
		fmt.Fprintln(w, "  server signature: verified with the service's key")
	case len(p.Buffers) == 0:
		fmt.Fprintf(w, "  (does not decode: %v)\n", err)
		return
	default:
		fmt.Fprintf(w, "  UNVERIFIED: %v\n", err)
	}

	fmt.Fprintln(w, "  KDC signature: not checked (that needs the krbtgt key)")
	fmt.Fprintf(w, "  version %d, %d buffers:\n", p.Version, len(p.Buffers))

	for _, b := range p.Buffers {
		name := pacTypeNames[b.ULType]
		if name == "" {
			name = "unknown"
		}

		fmt.Fprintf(w, "    %-28s %4d bytes\n", fmt.Sprintf("%s (%d)", name, b.ULType), b.CBBufferSize)
	}

	if k := p.KerbValidationInfo; k != nil {
		writeLogonInfo(w, k)
	}

	if c := p.ClientInfo; c != nil {
		fmt.Fprintln(w, "  CLIENT_INFO")
		fmt.Fprintf(w, "    name:              %s\n", c.Name)
		fmt.Fprintf(w, "    client id:         %s (the TGT's authtime)\n", decodeTime(c.ClientID.Time()))
	}

	if u := p.UPNDNSInfo; u != nil {
		fmt.Fprintln(w, "  UPN_DNS_INFO")
		fmt.Fprintf(w, "    upn:               %s\n", u.UPN)
		fmt.Fprintf(w, "    dns domain:        %s\n", u.DNSDomain)
		fmt.Fprintf(w, "    flags:             0x%x%s\n", u.Flags, upnFlags(u.Flags))
	}

	if d := p.S4UDelegationInfo; d != nil {
		fmt.Fprintln(w, "  CONSTRAINED_DELEGATION_INFO")
		fmt.Fprintf(w, "    s4u2proxy target:  %s\n", d.S4U2proxyTarget.Value)

		for _, s := range d.S4UTransitedServices {
			fmt.Fprintf(w, "    transited service: %s\n", s.Value)
		}
	}

	if p.CredentialsInfo != nil {
		fmt.Fprintf(w, "  CREDENTIALS_INFO: present (etype %d; contents not shown)\n", p.CredentialsInfo.EType)
	}

	for _, b := range p.Buffers {
		data := p.Data[b.Offset : b.Offset+uint64(b.CBBufferSize)]

		switch b.ULType {
		case 17:
			fmt.Fprintf(w, "  ATTRIBUTES_INFO: %s\n", attributesInfo(data))
		case 18:
			fmt.Fprintf(w, "  REQUESTOR: %s\n", sidString(data))
		}
	}

	for _, s := range []struct {
		name string
		sig  *pac.SignatureData
	}{
		{"SERVER_CHECKSUM", p.ServerChecksum},
		{"PRIVSVR_CHECKSUM", p.KDCChecksum},
		{"TICKET_CHECKSUM", p.TicketChecksum},
		{"FULL_CHECKSUM", p.FullChecksum},
	} {
		if s.sig == nil {
			continue
		}

		typ := sigTypeNames[s.sig.SignatureType]
		if typ == "" {
			typ = fmt.Sprintf("type %d", int32(s.sig.SignatureType))
		}

		fmt.Fprintf(w, "  %-17s  %s, %d bytes\n", s.name+":", typ, len(s.sig.Signature))
	}
}

func writeLogonInfo(w io.Writer, k *pac.KerbValidationInfo) {
	dom := k.LogonDomainID.String()

	fmt.Fprintln(w, "  LOGON_INFO (KERB_VALIDATION_INFO)")
	fmt.Fprintf(w, "    effective name:    %s\n", k.EffectiveName.Value)
	fmt.Fprintf(w, "    full name:         %s\n", k.FullName.Value)
	fmt.Fprintf(w, "    logon domain:      %s (%s)\n", k.LogonDomainName.Value, dom)
	fmt.Fprintf(w, "    logon server:      %s\n", k.LogonServer.Value)
	fmt.Fprintf(w, "    user sid:          %s-%d\n", dom, k.UserID)
	fmt.Fprintf(w, "    primary group:     %s-%d\n", dom, k.PrimaryGroupID)

	for _, g := range k.GroupIDs {
		fmt.Fprintf(w, "    group:             %s-%d (attrs 0x%x)\n", dom, g.RelativeID, g.Attributes)
	}

	for _, s := range k.ExtraSIDs {
		fmt.Fprintf(w, "    extra sid:         %s (attrs 0x%x)\n", s.SID.String(), s.Attributes)
	}

	if k.ResourceGroupCount > 0 {
		rd := k.ResourceGroupDomainSID.String()
		for _, g := range k.ResourceGroupIDs {
			fmt.Fprintf(w, "    resource group:    %s-%d (attrs 0x%x)\n", rd, g.RelativeID, g.Attributes)
		}
	}

	fmt.Fprintf(w, "    user flags:        0x%x\n", k.UserFlags)
	fmt.Fprintf(w, "    uac:               0x%x\n", k.UserAccountControl)
	fmt.Fprintf(w, "    logon count:       %d, bad password count %d\n", k.LogonCount, k.BadPasswordCount)
	fmt.Fprintf(w, "    password last set: %s\n", fileTime(k.PasswordLastSet))
}

// fileTime is a FILETIME; 0 and the maximum mean "never".
func fileTime(ft mstypes.FileTime) string {
	if ft.LowDateTime == 0 && ft.HighDateTime == 0 || ft.HighDateTime == 0x7FFFFFFF {
		return "never"
	}

	return decodeTime(ft.Time())
}

func upnFlags(f uint32) string {
	var s []string
	if f&1 != 0 {
		s = append(s, "UPN constructed from the name")
	}

	if f&2 != 0 {
		s = append(s, "extended")
	}

	if len(s) == 0 {
		return ""
	}

	return " (" + strings.Join(s, ", ") + ")"
}

// attributesInfo decodes PAC_ATTRIBUTES_INFO (MS-PAC 2.14): a flag count in
// bits, then the flags.
func attributesInfo(b []byte) string {
	if len(b) < 8 {
		return fmt.Sprintf("%d bytes, too short", len(b))
	}

	f := binary.LittleEndian.Uint32(b[4:8])

	var s []string
	if f&1 != 0 {
		s = append(s, "PAC_WAS_REQUESTED")
	}

	if f&2 != 0 {
		s = append(s, "PAC_WAS_GIVEN_IMPLICITLY")
	}

	return fmt.Sprintf("0x%x %s", f, strings.Join(s, " "))
}

// sidString decodes a binary SID (MS-DTYP 2.4.2.2), as PAC_REQUESTOR holds.
func sidString(b []byte) string {
	if len(b) < 8 || len(b) < 8+4*int(b[1]) {
		return fmt.Sprintf("%d bytes, not a SID", len(b))
	}

	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}

	var s bytes.Buffer

	fmt.Fprintf(&s, "S-%d-%d", b[0], auth)

	for i := 0; i < int(b[1]); i++ {
		fmt.Fprintf(&s, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}

	return s.String()
}
