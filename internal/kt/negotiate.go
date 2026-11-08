package kt

import (
	"encoding/base64"
	"fmt"

	"github.com/SorinS/krb5/client"
	"github.com/SorinS/krb5/spnego"
)

// NegotiateToken is a SPNEGO token for spn, base64 as an HTTP
// "Authorization: Negotiate <token>" header carries it (without the
// "Negotiate " prefix). It wraps an AP-REQ for the service ticket (taken from
// the client's cache, or got), so the service accepts it once (it keeps a
// replay cache) and only within its clock skew of now, about five minutes.
func NegotiateToken(cl *client.Client, spn string) (string, error) {
	s := spnego.SPNEGOClient(cl, spn)
	if err := s.AcquireCred(); err != nil {
		return "", fmt.Errorf("could not acquire client credential: %w", err)
	}

	st, err := s.InitSecContext()
	if err != nil {
		return "", fmt.Errorf("could not make the SPNEGO token: %w", err)
	}

	b, err := st.Marshal()
	if err != nil {
		return "", fmt.Errorf("could not encode the SPNEGO token: %w", err)
	}

	return base64.StdEncoding.EncodeToString(b), nil
}
