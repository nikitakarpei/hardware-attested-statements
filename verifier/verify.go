// Package verifier checks Hardware-Attested Statement bundles (spec/README.md): in-toto statements signed with a
// hardware-attested key, optionally time-stamped, and the bundles of the statements they were made from. Key
// evidence is checked by profiles (see profiles/android).
package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Verifier checks bundles against a policy.
type Verifier struct {
	Policy   *Policy
	Profiles map[string]Profile
	TSAs     []TSA                 // trusted, from the policy
	Drand    map[string]DrandChain // trusted, from the policy, by chain hash
	// Distrusted ones (spec section 5): their bounds aren't accepted.
	DistrustedTSAs  []TSA
	DistrustedDrand map[string]bool // by chain hash
	// Now is the verification time; nil means time.Now.
	Now func() time.Time

	// profilePolicies are the profiles' parsed parts of the policy, by predicate type and profile name.
	profilePolicies map[string]map[string]profilePolicy
}

type profilePolicy struct {
	signers int // how many trustedSigners entries are for the profile
	parsed  ProfilePolicy
}

// New makes a verifier for policy, with the profiles it may use, and checks the policy against them.
func New(policy *Policy, profiles ...Profile) (*Verifier, error) {
	v := &Verifier{Policy: policy, Profiles: map[string]Profile{}, Drand: map[string]DrandChain{},
		DistrustedDrand: map[string]bool{}, profilePolicies: map[string]map[string]profilePolicy{}}
	for _, p := range profiles {
		v.Profiles[p.Name()] = p
	}
	for _, e := range policy.TimestampAuthorities {
		tsa, err := e.tsa()
		if err != nil {
			return nil, err
		}
		v.TSAs = append(v.TSAs, tsa)
	}
	for _, name := range policy.DistrustedTimestampAuthorities {
		tsa, err := TSAEntry{Name: name}.tsa()
		if err != nil {
			return nil, err
		}
		v.DistrustedTSAs = append(v.DistrustedTSAs, tsa)
	}
	for _, name := range policy.DrandChains {
		c, err := drandChain(name)
		if err != nil {
			return nil, err
		}
		v.Drand[c.Hash] = c
	}
	for _, name := range policy.DistrustedDrandChains {
		c, err := drandChain(name)
		if err != nil {
			return nil, err
		}
		v.DistrustedDrand[c.Hash] = true
	}
	for t, pp := range policy.PredicateTypes {
		for _, raw := range pp.TrustedSigners {
			name, err := profileOf(raw)
			if err != nil {
				return nil, fmt.Errorf("policy: %s: every trustedSigners entry needs a profile", t)
			}
			if _, ok := v.Profiles[name]; !ok {
				return nil, fmt.Errorf("policy: %s: unknown profile %q", t, name)
			}
		}
		for name := range pp.Profiles {
			if _, ok := v.Profiles[name]; !ok {
				return nil, fmt.Errorf("policy: %s: unknown profile %q", t, name)
			}
		}
		v.profilePolicies[t] = map[string]profilePolicy{}
		for name, p := range v.Profiles {
			entries, err := pp.signersFor(name)
			if err != nil {
				return nil, err
			}
			parsed, err := p.CheckPolicy(entries, pp.Profiles[name])
			if err != nil {
				return nil, fmt.Errorf("policy: %s: %w", t, err)
			}
			v.profilePolicies[t][name] = profilePolicy{signers: len(entries), parsed: parsed}
		}
	}
	return v, nil
}

// Result is what verification established about one statement.
type Result struct {
	StatementID       string     `json:"statementId"`       // hex
	SignedStatementID string     `json:"signedStatementId"` // hex
	Statement         *Statement `json:"statement"`
	Profile           string     `json:"profile"`
	Key               *Key       `json:"key,omitzero"`
	// Timestamp is the earliest of the statement's own accepted time-stamps, if any, and TSA its authority.
	Timestamp *time.Time `json:"timestamp,omitzero"`
	TSA       string     `json:"tsa,omitzero"`
	// StartedAfter is the time of the statement's own drand round, if it includes one that was accepted.
	StartedAfter *time.Time `json:"startedAfter,omitzero"`
	// NotBefore and NotAfter bound when the statement was signed, after propagation (spec section 4); zero means
	// no bound.
	NotBefore time.Time `json:"notBefore,omitzero"`
	NotAfter  time.Time `json:"notAfter,omitzero"`
	// Notes are things a reader should know that didn't fail the statement (for example a distrusted TSA).
	Notes []string `json:"notes,omitzero"`
	// Passed: the statement passed its own checks; Accepted: and its inputs are accepted, or its policy allows
	// unverified inputs (spec section 5). Error says why it didn't pass.
	Passed   bool    `json:"passed"`
	Accepted bool    `json:"accepted"`
	Error    string  `json:"error,omitzero"`
	Inputs   []Input `json:"inputs,omitzero"`

	bundles   []*Bundle
	signedID  [32]byte
	err       error
	pp        PredicatePolicy
	ownUpper  time.Time
	ownLower  time.Time
	parents   []*Result
	accepting bool // guards the accepted() recursion
}

// Input is one of a statement's listed inputs: its result if a bundle of it was presented, and if it isn't
// verified (accepted), why.
type Input struct {
	StatementID       string  `json:"statementId"`
	SignedStatementID string  `json:"signedStatementId"`
	Result            *Result `json:"result,omitzero"`
	Verified          bool    `json:"verified"`
	Reason            string  `json:"reason,omitzero"`
}

// Verify checks a bundle, the input bundles nested in it, and any input bundles presented separately (spec
// section 5). It returns the bundle's result, and an error unless the bundle verifies; a structurally broken set
// of bundles gives no result.
func (v *Verifier) Verify(b *Bundle, presented ...*Bundle) (*Result, error) {
	now := timeOrNow(v.Now)
	nodes := map[[32]byte]*Result{}

	// Step 1: links, and each bundle's own evidence of time.
	var build func(b *Bundle, depth int) (*Result, error)
	build = func(b *Bundle, depth int) (*Result, error) {
		if depth > maxNesting {
			return nil, errors.New("bundles nested too deeply")
		}
		n, err := v.node(b, nodes, now)
		if err != nil {
			return nil, err
		}
		for i, ib := range b.VerificationMaterial.InputBundles {
			if ib == nil {
				return nil, errors.New("null input bundle")
			}
			child, err := build(ib, depth+1)
			if u, ok := err.(*unidentified); ok && linkFailed(n, u) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("statement %s: input bundle %d: %w", n.StatementID, i+1, err)
			}
			if !link(n, child) {
				return nil, fmt.Errorf("statement %s: input bundle %d (statement %s) is not one of its listed inputs",
					n.StatementID, i+1, child.StatementID)
			}
		}
		return n, nil
	}
	root, err := build(b, 0)
	if err != nil {
		return nil, err
	}
	var pool []*Result
	var failed []*unidentified
	for i, p := range presented {
		n, err := build(p, 0)
		if u, ok := err.(*unidentified); ok {
			failed = append(failed, u)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("presented bundle %d: %w", i+1, err)
		}
		if n != root && len(n.parents) == 0 {
			pool = append(pool, n)
		}
	}
	for progress := true; progress && len(pool) > 0; {
		progress = false
		for i := 0; i < len(pool); i++ {
			linked := false
			for _, n := range nodes {
				linked = link(n, pool[i]) || linked
			}
			if linked {
				pool = append(pool[:i], pool[i+1:]...)
				i--
				progress = true
			}
		}
	}
	if len(pool) > 0 {
		return nil, fmt.Errorf("presented bundle of statement %s is not a listed input of any statement", pool[0].StatementID)
	}
	for _, u := range failed {
		linked := false
		for _, n := range nodes {
			linked = linkFailed(n, u) || linked
		}
		if !linked {
			return nil, fmt.Errorf("presented bundle of statement %s: %w", u.statementID, u.err)
		}
	}

	// Step 2: bounds, over every link whose IDs match.
	for _, n := range nodes {
		n.NotAfter, n.NotBefore = n.ownUpper, n.ownLower
	}
	for changed, rounds := true, 0; changed && rounds <= len(nodes); rounds++ {
		changed = false
		for _, n := range nodes {
			for _, p := range n.parents {
				if !p.NotAfter.IsZero() && (n.NotAfter.IsZero() || p.NotAfter.Before(n.NotAfter)) {
					n.NotAfter, changed = p.NotAfter, true
				}
			}
			for _, in := range n.Inputs {
				if c := in.Result; c != nil && c.NotBefore.After(n.NotBefore) {
					n.NotBefore, changed = c.NotBefore, true
				}
			}
		}
	}

	for _, n := range nodes {
		if !n.NotBefore.IsZero() && !n.NotAfter.IsZero() && n.NotBefore.After(n.NotAfter) {
			return nil, fmt.Errorf("statement %s: inconsistent time bounds (after %v but before %v): a trusted time source is wrong",
				n.StatementID, n.NotBefore.UTC(), n.NotAfter.UTC())
		}
	}

	// Step 3: policy.
	for _, n := range nodes {
		if n.err == nil {
			n.err = v.policy(n, now)
		}
		n.Passed = n.err == nil
		if n.err != nil {
			n.Error = n.err.Error()
		}
	}
	for _, n := range nodes {
		accepted(n)
	}
	if !root.Accepted {
		if !root.Passed {
			return root, root.err
		}
		for _, in := range root.UnverifiedInputs() {
			return root, fmt.Errorf("input %s isn't verified: %s", in.StatementID, in.Reason)
		}
	}
	return root, nil
}

// UnverifiedInputs lists every input, anywhere below r, that isn't verified.
func (r *Result) UnverifiedInputs() []Input {
	var out []Input
	seen := map[*Result]bool{}
	var walk func(*Result)
	walk = func(n *Result) {
		if seen[n] {
			return
		}
		seen[n] = true
		for _, in := range n.Inputs {
			if !in.Verified {
				out = append(out, in)
			}
			if in.Result != nil {
				walk(in.Result)
			}
		}
	}
	walk(r)
	return out
}

func accepted(n *Result) bool {
	if n.accepting {
		return n.Accepted
	}
	n.accepting = true
	all := true
	for i := range n.Inputs {
		in := &n.Inputs[i]
		switch c := in.Result; {
		case c == nil:
			in.Reason = "its bundle wasn't presented"
		case !accepted(c):
			if c.err != nil {
				in.Reason = c.err.Error()
			} else {
				in.Reason = "one of its own inputs isn't verified"
			}
		default:
			in.Verified = true
		}
		all = all && in.Verified
	}
	n.Accepted = n.Passed && (all || n.pp.AllowUnverifiedInputs)
	return n.Accepted
}

// link makes child the result of every listed input of n that names it, and reports whether there was one.
func link(n, child *Result) bool {
	found := false
	for i, in := range n.Inputs {
		if in.SignedStatementID == child.SignedStatementID && in.StatementID == child.StatementID {
			n.Inputs[i].Result = child
			found = true
		}
	}
	if found {
		for _, p := range child.parents {
			if p == n {
				return true
			}
		}
		child.parents = append(child.parents, n)
	}
	return found
}

// unidentified is a bundle whose signed-statement ID can't be computed (unknown profile, unreadable evidence):
// if its statement ID is a listed input, that input has failed (spec section 2).
type unidentified struct {
	statementID string
	err         error
}

func (u *unidentified) Error() string { return u.err.Error() }

// linkFailed makes a failed result of u for every listed input of n with u's statement ID and no result yet.
func linkFailed(n *Result, u *unidentified) bool {
	found := false
	for i, in := range n.Inputs {
		if in.StatementID == u.statementID && in.Result == nil {
			n.Inputs[i].Result = &Result{StatementID: u.statementID, Error: u.err.Error(), err: u.err, parents: []*Result{n}}
			found = true
		}
	}
	return found
}

// node finds or creates b's node, and checks b's own envelope, time-stamp and startedAfter.
func (v *Verifier) node(b *Bundle, nodes map[[32]byte]*Result, now time.Time) (*Result, error) {
	if b.MediaType != BundleMediaType {
		return nil, fmt.Errorf("unknown bundle mediaType %q", b.MediaType)
	}
	env := b.DSSEEnvelope
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != nil {
		return nil, errors.New("expected exactly one signature, without keyid")
	}
	// The envelope is part of the bundle, outside its statement and key evidence: an error in it fails the whole
	// verification (spec section 0, Errors).
	if env.PayloadType != InTotoPayload {
		return nil, fmt.Errorf("unexpected payloadType %q", env.PayloadType)
	}
	evidence := b.VerificationMaterial.Key
	id := StatementID(env.Payload)
	profile, ok := v.Profiles[evidence.Profile]
	if !ok {
		return nil, &unidentified{hex.EncodeToString(id[:]), fmt.Errorf("key evidence of unknown profile %q", evidence.Profile)}
	}
	binding, err := profile.Binding(evidence.Raw)
	if err != nil {
		return nil, &unidentified{hex.EncodeToString(id[:]), err}
	}
	signature := env.Signatures[0].Sig
	sid := SignedStatementID(evidence.Profile, id, binding, signature)
	n, exists := nodes[sid]
	if !exists {
		n = &Result{StatementID: hex.EncodeToString(id[:]), SignedStatementID: hex.EncodeToString(sid[:]),
			Profile: evidence.Profile, signedID: sid}
		nodes[sid] = n
		n.err = v.statement(n, env, now)
	}
	n.bundles = append(n.bundles, b)
	// Every bundle's time-stamp is checked, even once the node has failed: one that passes gives its bound
	// whatever else fails, so bounds don't depend on the order bundles come in (spec section 4).
	if ts := b.VerificationMaterial.Timestamp; ts != nil {
		r, err := verifyTimestamp(ts, sid, v.TSAs, now)
		if err != nil {
			if d, derr := verifyTimestamp(ts, sid, v.DistrustedTSAs, now); derr == nil {
				n.Notes = append(n.Notes, fmt.Sprintf("time-stamp by distrusted authority %s: no bound", d.TSA))
				return n, nil
			}
			if n.err == nil {
				n.err = err
			}
		} else if n.ownUpper.IsZero() || r.Upper.Before(n.ownUpper) {
			n.ownUpper, n.Timestamp, n.TSA = r.Upper, &r.Time, r.TSA
		}
	}
	return n, nil
}

// statement parses a new node's statement, its listed inputs, and its startedAfter.
func (v *Verifier) statement(n *Result, env DSSEEnvelope, now time.Time) error {
	st, err := ParseStatement(env.Payload)
	if err != nil {
		return err
	}
	n.Statement = st
	inputs, inputsErr := st.Inputs()
	for _, in := range inputs {
		n.Inputs = append(n.Inputs, Input{StatementID: in.Digest["sha256"], SignedStatementID: in.Annotations.SignedStatementID})
	}
	// The startedAfter gives its bound even if the inputs fail (spec section 4).
	if err := v.startedAfter(n, st); inputsErr == nil {
		return err
	}
	return inputsErr
}

// startedAfter checks st's startedAfter, if any, and sets n's own lower bound from it.
func (v *Verifier) startedAfter(n *Result, st *Statement) error {
	after, err := st.StartedAfter()
	if err != nil || after == nil {
		return err
	}
	if v.DistrustedDrand[after.Drand.Chain] {
		n.Notes = append(n.Notes, "startedAfter from a distrusted drand chain: no bound")
		return nil
	}
	chain, ok := v.Drand[after.Drand.Chain]
	if !ok {
		return fmt.Errorf("startedAfter: drand chain %s is not trusted", after.Drand.Chain)
	}
	sig, _ := hex.DecodeString(after.Drand.Signature)
	if err := chain.Verify(after.Drand.Round, sig); err != nil {
		return fmt.Errorf("startedAfter: %w", err)
	}
	t := chain.RoundTime(after.Drand.Round)
	n.StartedAfter, n.ownLower = &t, t
	return nil
}

// policy applies the policy to a node whose own evidence of time passed (spec section 5, step 3).
func (v *Verifier) policy(n *Result, now time.Time) error {
	st := n.Statement
	pp, ok := v.Policy.PredicateTypes[st.PredicateType]
	if !ok {
		return fmt.Errorf("predicate type %s is not in the policy", st.PredicateType)
	}
	n.pp = pp
	profile := v.Profiles[n.Profile]
	parsed, ok := v.profilePolicies[st.PredicateType][n.Profile]
	if !ok {
		return fmt.Errorf("the policy for %s wasn't checked for the %s profile (make the verifier with New)", st.PredicateType, n.Profile)
	}
	if parsed.signers == 0 {
		return fmt.Errorf("the policy trusts no %s signers for %s", n.Profile, st.PredicateType)
	}

	// Time (spec section 4).
	if pp.RequireTimestamp && n.NotAfter.IsZero() {
		return errors.New("a time-stamp is required, on it or on a statement made from it")
	}
	if pp.RequireStartedAfter && n.NotBefore.IsZero() {
		return errors.New("startedAfter is required, in it or in one of its inputs")
	}
	upper := n.NotAfter
	if upper.IsZero() {
		upper = now
		if n.NotBefore.After(now) {
			return fmt.Errorf("its lower time bound %v is in the future", n.NotBefore.UTC())
		}
	}

	// Every copy must pass every check, at the same upper bound: copies share the statement, key binding and
	// signature, but not the rest of their key evidence (on Android, the certificates above the leaf).
	for _, b := range n.bundles {
		key, err := profile.VerifyKey(b.VerificationMaterial.Key.Raw, parsed.parsed, now)
		if err != nil {
			return err
		}
		if key.PublicKey == nil || key.PublicKey.Curve != elliptic.P256() {
			return errors.New("the signing key is not a P-256 key")
		}
		env := b.DSSEEnvelope
		if err := verifySignature(key.PublicKey, PAE(env.PayloadType, env.Payload), env.Signatures[0].Sig); err != nil {
			return err
		}
		if err := checkKeyAt(key, upper, !n.NotAfter.IsZero()); err != nil {
			return err
		}
		if n.Key == nil {
			n.Key = key
		}
	}
	return nil
}

// checkKeyAt checks that key's evidence, and the policy's limits on it, hold at the statement's upper bound;
// stamped says whether the bound is a time-stamp's (or else verification time).
func checkKeyAt(key *Key, upper time.Time, stamped bool) error {
	if upper.Before(key.ValidFrom) || upper.After(key.ValidUntil) {
		if !stamped {
			return errors.New("its key evidence isn't valid now, and no time-stamp shows it was signed while it was")
		}
		return fmt.Errorf("its key evidence wasn't valid at its upper time bound %v", upper.UTC())
	}
	if from := key.AcceptedFrom; !from.IsZero() && upper.Before(from) {
		return fmt.Errorf("its upper time bound %v is before %v, when the policy starts accepting its key", upper.UTC(), from.UTC())
	}
	if until := key.AcceptedUntil; !until.IsZero() && !upper.Before(until) {
		return fmt.Errorf("its upper time bound %v is not before %v, when the policy stops accepting its key", upper.UTC(), until.UTC())
	}
	if max := key.MaxAge; max > 0 {
		c := key.Created
		switch {
		case c == nil:
			return errors.New("the key's creation time is unknown, and the policy limits key age")
		case c.After(upper):
			return errors.New("the key's stated creation time is after its statement's upper bound")
		case upper.Sub(*c) > max:
			return fmt.Errorf("the key was created %v before the statement's upper bound, more than the policy allows", upper.Sub(*c).Round(time.Hour))
		}
	}
	return nil
}

var p256HalfOrder = new(big.Int).Rsh(elliptic.P256().Params().N, 1)

// verifySignature checks a DSSE signature: strict DER, low-S, valid (spec section 2).
func verifySignature(pub *ecdsa.PublicKey, message, sig []byte) error {
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(sig, &rs); err != nil || len(rest) > 0 {
		return errors.New("signature is not DER")
	}
	if again, err := asn1.Marshal(rs); err != nil || string(again) != string(sig) {
		return errors.New("signature is not strict DER")
	}
	if rs.R.Sign() <= 0 || rs.S.Sign() <= 0 || rs.S.Cmp(p256HalfOrder) > 0 {
		return errors.New("signature is not low-S")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(pub, digest[:], rs.R, rs.S) {
		return errors.New("signature is invalid")
	}
	return nil
}
