package android

import (
	"errors"
	"fmt"
	"math/big"
)

// A minimal DER reader for the attestation extension. Go's encoding/asn1 can't skip the unknown,
// high-numbered tags that new KeyMint versions add, so the extension is walked element by element.

const (
	classUniversal = 0
	classContext   = 2

	tagBoolean     = 1
	tagInteger     = 2
	tagOctetString = 4
	tagEnumerated  = 10
	tagSequence    = 16
	tagSet         = 17
)

type element struct {
	class       int
	constructed bool
	tag         int
	content     []byte
}

func readElement(b []byte) (element, []byte, error) {
	if len(b) < 2 {
		return element{}, nil, errors.New("truncated element")
	}
	e := element{class: int(b[0] >> 6), constructed: b[0]&0x20 != 0, tag: int(b[0] & 0x1f)}
	i := 1
	if e.tag == 0x1f { // high tag number: base-128, most significant group first
		e.tag = 0
		for {
			if i >= len(b) || i > 4 {
				return element{}, nil, errors.New("bad tag")
			}
			c := b[i]
			i++
			e.tag = e.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
	}
	if i >= len(b) {
		return element{}, nil, errors.New("truncated length")
	}
	length := int(b[i])
	i++
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 {
			return element{}, nil, errors.New("unsupported length encoding")
		}
		if i+n > len(b) {
			return element{}, nil, errors.New("truncated length")
		}
		length = 0
		for _, c := range b[i : i+n] {
			length = length<<8 | int(c)
		}
		i += n
	}
	if length < 0 || i+length > len(b) {
		return element{}, nil, errors.New("element longer than its container")
	}
	e.content = b[i : i+length]
	return e, b[i+length:], nil
}

// parseOne reads exactly one element filling b.
func parseOne(b []byte) (element, error) {
	e, rest, err := readElement(b)
	if err == nil && len(rest) > 0 {
		err = errors.New("trailing data")
	}
	return e, err
}

func (e element) children() ([]element, error) {
	if !e.constructed {
		return nil, errors.New("not a constructed element")
	}
	var out []element
	for b := e.content; len(b) > 0; {
		c, rest, err := readElement(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		b = rest
	}
	return out, nil
}

func (e element) is(class, tag int) bool { return e.class == class && e.tag == tag }

func (e element) expect(class, tag int) error {
	if !e.is(class, tag) {
		return fmt.Errorf("expected class %d tag %d, got class %d tag %d", class, tag, e.class, e.tag)
	}
	return nil
}

func (e element) int64() (int64, error) {
	if !e.is(classUniversal, tagInteger) && !e.is(classUniversal, tagEnumerated) {
		return 0, fmt.Errorf("expected an integer, got tag %d", e.tag)
	}
	if len(e.content) == 0 {
		return 0, errors.New("empty integer")
	}
	n := new(big.Int).SetBytes(e.content)
	if e.content[0]&0x80 != 0 { // negative: two's complement
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), uint(8*len(e.content))))
	}
	if !n.IsInt64() {
		return 0, errors.New("integer out of range")
	}
	return n.Int64(), nil
}

func (e element) bool() (bool, error) {
	if !e.is(classUniversal, tagBoolean) {
		return false, fmt.Errorf("expected a boolean, got tag %d", e.tag)
	}
	if len(e.content) != 1 || (e.content[0] != 0 && e.content[0] != 0xff) {
		return false, errors.New("boolean is not DER (must be 0x00 or 0xFF)")
	}
	return e.content[0] == 0xff, nil
}

func (e element) octets() ([]byte, error) {
	if !e.is(classUniversal, tagOctetString) || e.constructed {
		return nil, fmt.Errorf("expected an octet string, got tag %d", e.tag)
	}
	return e.content, nil
}
