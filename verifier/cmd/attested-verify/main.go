// Command attested-verify checks Hardware-Attested Statement bundles (spec/README.md).
//
//	attested-verify -policy policy.json http RESPONSE.http           a response carrying a bundle in its headers
//	attested-verify -policy policy.json bundle B.json [INPUT.json …] a bundle, and bundles of its inputs not nested in it
//	attested-verify extract RESPONSE.http > B.json                    the bundle from a response's headers
package main

import (
	"context"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nikitakarpei/hardware-attested-statements/verifier"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/predicates/httpresponse"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/profiles/android"
	"github.com/nikitakarpei/hardware-attested-statements/verifier/profiles/awsnitro"
)

type files []string

func (f *files) String() string     { return strings.Join(*f, ",") }
func (f *files) Set(v string) error { *f = append(*f, v); return nil }

func main() {
	policyFile := flag.String("policy", "", "policy file (required, except for extract)")
	revocationFile := flag.String("revocation-list", "", "Google's revocation list, saved from "+android.RevocationURL+" (default: fetch)")
	grapheneKeys := flag.String("grapheneos-keys", "", "GrapheneOS key list, saved from "+android.GrapheneOSKeysURL+
		" (with a saved revocation list; without it, GrapheneOS devices are rejected)")
	grapheneSig := flag.String("grapheneos-keys-sig", "", "its signature, saved from "+android.GrapheneOSKeysSigURL)
	obtainedAt := flag.String("lists-obtained-at", "", "when the saved lists were downloaded, as RFC 3339 (required with -revocation-list)")
	asJSON := flag.Bool("json", false, "print the results as JSON")
	var testRoots files
	flag.Var(&testRoots, "test-only-root", "also trust this attestation root (PEM); for tests only")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: attested-verify [flags] http RESPONSE | bundle BUNDLE [INPUT …] | extract RESPONSE")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 2 {
		flag.Usage()
		os.Exit(2)
	}
	if args[0] == "extract" {
		raw, err := os.ReadFile(args[1])
		fail(err)
		_, b, err := verifier.ParseHTTPResponse(raw)
		fail(err)
		out, err := json.Marshal(b, jsontext.WithIndent("  "))
		fail(err)
		fmt.Println(string(out))
		return
	}
	if *policyFile == "" {
		fail(errors.New("-policy is required"))
	}
	policyRaw, err := os.ReadFile(*policyFile)
	fail(err)
	policy, err := verifier.ParsePolicy(policyRaw)
	fail(err)
	trust, err := loadTrust(*revocationFile, *grapheneKeys, *grapheneSig, *obtainedAt)
	fail(err)
	for _, path := range testRoots {
		raw, err := os.ReadFile(path)
		fail(err)
		block, _ := pem.Decode(raw)
		if block == nil {
			fail(fmt.Errorf("%s: not PEM", path))
		}
		c, err := x509.ParseCertificate(block.Bytes)
		fail(err)
		trust.Roots = append(trust.Roots, c)
		fmt.Fprintf(os.Stderr, "warning: trusting test root %s\n", path)
	}
	nitroTrust, err := awsnitro.DefaultTrust()
	fail(err)
	v, err := verifier.New(policy, android.New(trust), awsnitro.New(nitroTrust))
	fail(err)

	switch args[0] {
	case "http":
		raw, err := os.ReadFile(args[1])
		fail(err)
		resp, b, err := verifier.ParseHTTPResponse(raw)
		fail(err)
		r, err := v.Verify(b)
		failWith(*asJSON, r, err)
		fail(verifier.CheckHTTPBody(r.Statement, resp))
		var p *httpresponse.Predicate
		if r.Statement.PredicateType == httpresponse.PredicateType {
			p, err = httpresponse.Parse(r.Statement)
			fail(err)
			fail(httpresponse.CheckResponse(r.Statement, p, resp))
		}
		report(*asJSON, r, p)
	case "bundle":
		var bundles []*verifier.Bundle
		for _, path := range args[1:] {
			raw, err := os.ReadFile(path)
			fail(err)
			b, err := verifier.ParseBundle(raw)
			fail(fmt.Errorf("%s: %w", path, err), err)
			bundles = append(bundles, b)
		}
		r, err := v.Verify(bundles[0], bundles[1:]...)
		failWith(*asJSON, r, err)
		report(*asJSON, r, nil)
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func loadTrust(revocation, keys, sig, obtainedAt string) (*android.Trust, error) {
	if revocation == "" && keys == "" && sig == "" && obtainedAt == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return android.LoadTrust(ctx, nil)
	}
	if revocation == "" || obtainedAt == "" || (keys == "") != (sig == "") {
		return nil, errors.New("saved lists need -revocation-list and -lists-obtained-at, and -grapheneos-keys with -grapheneos-keys-sig")
	}
	obtained, err := time.Parse(time.RFC3339, obtainedAt)
	if err != nil {
		return nil, fmt.Errorf("-lists-obtained-at: %w", err)
	}
	read := func(p string) ([]byte, error) {
		if p == "" {
			return nil, nil
		}
		return os.ReadFile(p)
	}
	var raw [3][]byte
	for i, p := range []string{revocation, keys, sig} {
		if raw[i], err = read(p); err != nil {
			return nil, err
		}
	}
	fmt.Fprintf(os.Stderr, "note: saved lists, obtained at %s as stated\n", obtained.UTC().Format(time.RFC3339))
	return android.NewTrust(raw[0], raw[1], raw[2], obtained)
}

// failWith exits if the bundle didn't verify, showing what was established.
func failWith(asJSON bool, r *verifier.Result, err error) {
	if err == nil {
		return
	}
	if r != nil {
		if asJSON {
			out, _ := json.Marshal(map[string]any{"verified": false, "error": err.Error(), "result": r}, jsontext.WithIndent("  "))
			fmt.Println(string(out))
		} else {
			printResult(r, "")
		}
	}
	fail(err)
}

func report(asJSON bool, r *verifier.Result, p *httpresponse.Predicate) {
	if asJSON {
		out, err := json.Marshal(map[string]any{"verified": true, "result": r, "httpResponse": p}, jsontext.WithIndent("  "))
		fail(err)
		fmt.Println(string(out))
		return
	}
	fmt.Println("✔ VERIFIED")
	printResult(r, "")
	if p != nil {
		fmt.Printf("\ncaptured: %s %s → %s\n", p.Request.Method, p.Request.URL, p.Response.StatusLine)
		fmt.Printf("  server %s, %s %s, certificate SHA-256 %s (look it up on https://crt.sh/?q=%s)\n",
			p.Connection.ConnectedTo, p.Connection.TLSVersion, p.Connection.CipherSuite,
			p.Connection.ServerCertificateSha256, p.Connection.ServerCertificateSha256)
		fmt.Println("  the saved response's body, status and headers match the signed ones")
	}
}

// printResult prints a statement and, indented, the inputs it lists.
func printResult(r *verifier.Result, indent string) {
	const layout = "2006-01-02 15:04:05 MST"
	predicateType := "(unreadable)"
	if r.Statement != nil {
		predicateType = r.Statement.PredicateType
	}
	fmt.Printf("%sstatement %s: %s\n", indent, r.StatementID, predicateType)
	if r.Key != nil {
		for _, line := range r.Key.Description {
			fmt.Printf("%s  %s key: %s\n", indent, r.Profile, line)
		}
	}
	switch {
	case !r.NotBefore.IsZero() && !r.NotAfter.IsZero():
		fmt.Printf("%s  signed:    between %s and %s\n", indent, r.NotBefore.UTC().Format(layout), r.NotAfter.UTC().Format(layout))
	case !r.NotAfter.IsZero():
		fmt.Printf("%s  signed:    before %s\n", indent, r.NotAfter.UTC().Format(layout))
	case !r.NotBefore.IsZero():
		fmt.Printf("%s  signed:    after %s (no time-stamp)\n", indent, r.NotBefore.UTC().Format(layout))
	default:
		fmt.Printf("%s  signed:    time unknown (no time-stamp)\n", indent)
	}
	if r.TSA != "" {
		fmt.Printf("%s  time-stamp: %s, %s\n", indent, r.Timestamp.UTC().Format(layout), r.TSA)
	}
	for _, n := range r.Notes {
		fmt.Printf("%s  note:      %s\n", indent, n)
	}
	if !r.Passed {
		fmt.Printf("%s  FAILED:    %s\n", indent, r.Error)
	}
	for _, in := range r.Inputs {
		switch {
		case in.Result == nil:
			fmt.Printf("%s  input %s: NOT VERIFIED (%s)\n", indent, in.StatementID, in.Reason)
			continue
		case in.Verified:
			fmt.Printf("%s  input, verified:\n", indent)
		default:
			fmt.Printf("%s  input, NOT VERIFIED (%s):\n", indent, in.Reason)
		}
		printResult(in.Result, indent+"    ")
	}
}

// fail exits on the first non-nil error; with two arguments, it reports the first when the second is non-nil.
func fail(errs ...error) {
	err := errs[0]
	if len(errs) == 2 && errs[1] == nil {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "✘ NOT VERIFIED:", err)
		os.Exit(1)
	}
}
