// Package httpresponse is the http-response predicate type, v1 (spec/predicates/http-response/v1.md): an HTTP
// response fetched over HTTPS. The statement's subject "body" is SHA-256 of the response body exactly as received,
// before any content decoding (a capturing program may ask for "Accept-Encoding: identity", but a server may still
// encode it).
package httpresponse

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
)

const PredicateType = "https://github.com/nikitakarpei/hardware-attested-statements/blob/main/spec/predicates/http-response/v1.md"

// Predicate describes the exchange.
type Predicate struct {
	Request struct {
		Method  string      `json:"method"`
		URL     string      `json:"url"`
		Headers [][2]string `json:"headers"`
		Cookies string      `json:"cookies"`
	} `json:"request"`
	Connection struct {
		Route                   string `json:"route"`
		ConnectedTo             string `json:"connectedTo"`
		Protocol                string `json:"protocol"`
		TLSVersion              string `json:"tlsVersion"`
		CipherSuite             string `json:"cipherSuite"`
		ServerCertificateSha256 string `json:"serverCertificateSha256"`
	} `json:"connection"`
	Response struct {
		StatusLine string      `json:"statusLine"`
		Status     int         `json:"status"`
		Headers    [][2]string `json:"headers"`
	} `json:"response"`
}

// Parse reads the predicate of a statement of this type.
func Parse(st *verifier.Statement) (*Predicate, error) {
	if st.PredicateType != PredicateType {
		return nil, fmt.Errorf("predicate type is %s, not %s", st.PredicateType, PredicateType)
	}
	var p Predicate
	if err := json.Unmarshal(st.Predicate, &p); err != nil {
		return nil, fmt.Errorf("predicate: %w", err)
	}
	if p.Request.URL == "" || p.Response.Status == 0 {
		return nil, errors.New("predicate: missing request URL or response status")
	}
	return &p, nil
}

// Headers the proxy never forwards, so a saved response can't be compared on them.
var framing = map[string]bool{"connection": true, "content-length": true, "keep-alive": true,
	"proxy-connection": true, "transfer-encoding": true}

// CheckResponse checks that a saved response is the one the statement describes: same body, status and headers.
func CheckResponse(st *verifier.Statement, p *Predicate, r *verifier.HTTPResponse) error {
	want, ok := st.SubjectDigest("body")
	if !ok {
		return errors.New(`the statement has no "body" subject`)
	}
	got := sha256.Sum256(r.Body)
	if hex.EncodeToString(got[:]) != want {
		return errors.New("the body doesn't match the signed digest")
	}
	if r.Status != p.Response.Status {
		return fmt.Errorf("status %d differs from the signed %d", r.Status, p.Response.Status)
	}
	normalize := func(hs [][2]string) []string {
		var out []string
		for _, h := range hs {
			n := strings.ToLower(strings.TrimSpace(h[0]))
			if !framing[n] && !strings.HasPrefix(n, "attested-") {
				out = append(out, n+": "+strings.TrimSpace(h[1]))
			}
		}
		slices.Sort(out)
		return out
	}
	if g, w := normalize(r.Headers), normalize(p.Response.Headers); !slices.Equal(g, w) {
		return fmt.Errorf("the headers differ from the signed ones (%d received, %d signed)", len(g), len(w))
	}
	return nil
}
