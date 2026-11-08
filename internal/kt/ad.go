package kt

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/config"
	"github.com/SorinS/krb5/gsskrb5"
	"github.com/SorinS/krb5/ldap"
)

// GetKVNOFromAD looks up a principal's key version number in Active Directory
// over LDAP: it logs in as the principal with its password, binds to the DC's
// LDAP with SASL GSSAPI (signing), and reads msDS-KeyVersionNumber of the
// object whose servicePrincipalName — or, failing that, sAMAccountName — is the
// principal.
//
// ldapAddr is the LDAP server's HOST:PORT (a loopback tunnel's, say); dcHost is
// the DC's host name, used in the ldap/<dcHost> service the bind authenticates
// to. cfg is the krb5.conf whose realm names the KDC to log in against.
func GetKVNOFromAD(principal, realm, password string, cfg *config.Config, ldapAddr, dcHost string) (uint32, error) {
	name, realm := NormalizePrincipal(principal, realm)

	cl := client.NewWithPassword(name, realm, password, cfg, clientSettings()...)
	if err := cl.Login(); err != nil {
		return 0, fmt.Errorf("login as %s@%s: %w", name, realm, err)
	}

	defer cl.Destroy()

	c, err := ldap.Dial(ldapAddr)
	if err != nil {
		return 0, fmt.Errorf("connecting to LDAP %s: %w", ldapAddr, err)
	}

	defer c.Close()

	if err := c.BindGSSAPI(cl, "ldap@"+dcHost, gsskrb5.LayerIntegrity); err != nil {
		return 0, fmt.Errorf("LDAP SASL bind to ldap@%s: %w", dcHost, err)
	}

	base, err := c.DefaultNamingContext()
	if err != nil {
		return 0, fmt.Errorf("reading the naming context: %w", err)
	}

	const attr = "msDS-KeyVersionNumber"

	esc := ldap.EscapeFilterValue([]byte(name))

	entries, err := c.Search(base, ldap.ScopeSubtree, "(servicePrincipalName="+esc+")", attr)
	if err != nil {
		return 0, fmt.Errorf("LDAP search by SPN: %w", err)
	}

	if len(entries) == 0 {
		entries, err = c.Search(base, ldap.ScopeSubtree, "(sAMAccountName="+esc+")", attr)
		if err != nil {
			return 0, fmt.Errorf("LDAP search by sAMAccountName: %w", err)
		}
	}

	if len(entries) == 0 {
		return 0, fmt.Errorf("no AD object with servicePrincipalName or sAMAccountName %q", name)
	}

	v := strings.TrimSpace(entries[0].Get(attr))
	if v == "" {
		return 0, fmt.Errorf("the AD object has no %s", attr)
	}

	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("unexpected %s value %q: %w", attr, v, err)
	}

	return uint32(n), nil
}
