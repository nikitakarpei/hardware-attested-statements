package awsnitro

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// A strict reader for the subset of CBOR (RFC 8949) that AWS's attestation documents use (spec:
// profiles/awsnitro.md, verification step 2): integers, byte and text strings, arrays, maps and null, every item
// of definite length except, where allowed, the top-level map; no tags, floats or other simple values; integers
// and lengths in shortest form; unique map keys. Anything else is an error, never interpreted.

type kind int

const (
	kindUnsigned kind = iota
	kindNegative
	kindBytes
	kindText
	kindArray
	kindMap
	kindNull
)

func (k kind) String() string {
	return [...]string{"an unsigned integer", "a negative integer", "a byte string", "a text string", "an array",
		"a map", "null"}[k]
}

// item is one decoded CBOR item.
type item struct {
	kind kind
	raw  []byte // the item's encoding, as given
	// value is an unsigned integer, or n for the negative integer -1 - n.
	value uint64
	// bytes is a byte string's or text string's content; never nil for a string, even an empty one.
	bytes []byte
	// items are an array's elements, or a map's keys and values: key, value, key, value, …
	items []item
}

// maxDepth bounds nesting: an attestation document nests three levels deep.
const maxDepth = 8

var errTruncated = errors.New("truncated")

// decodeCBOR reads exactly one item from b, with nothing after it. If indefiniteMap is set, the item may be a map
// of indefinite length; nothing inside it may be.
func decodeCBOR(b []byte, indefiniteMap bool) (item, error) {
	r := reader{b: b}
	it, err := r.item(0, indefiniteMap)
	if err != nil {
		return item{}, err
	}
	if r.i != len(b) {
		return item{}, errors.New("bytes after the item")
	}
	return it, nil
}

type reader struct {
	b []byte
	i int
}

// shortest are the smallest arguments that need 1, 2, 4 and 8 bytes: smaller ones fit in a shorter form.
var shortest = [4]uint64{24, 1 << 8, 1 << 16, 1 << 32}

// head reads an item's initial byte and argument.
func (r *reader) head() (major byte, arg uint64, indefinite bool, err error) {
	if r.i >= len(r.b) {
		return 0, 0, false, errTruncated
	}
	initial := r.b[r.i]
	r.i++
	major, info := initial>>5, initial&0x1f
	switch {
	case info < 24:
		return major, uint64(info), false, nil
	case info <= 27:
		n := 1 << (info - 24)
		if len(r.b)-r.i < n {
			return 0, 0, false, errTruncated
		}
		for _, c := range r.b[r.i : r.i+n] {
			arg = arg<<8 | uint64(c)
		}
		r.i += n
		if arg < shortest[info-24] {
			return 0, 0, false, errors.New("an integer or length isn't in shortest form")
		}
		return major, arg, false, nil
	case info == 31:
		return major, 0, true, nil
	}
	return 0, 0, false, fmt.Errorf("reserved additional information %d", info)
}

func (r *reader) item(depth int, indefiniteMap bool) (item, error) {
	if depth > maxDepth {
		return item{}, errors.New("nested too deeply")
	}
	start := r.i
	major, arg, indefinite, err := r.head()
	if err != nil {
		return item{}, err
	}
	if indefinite && (major != 5 || !indefiniteMap) {
		return item{}, errors.New("an item of indefinite length")
	}
	remaining := uint64(len(r.b) - r.i)
	var it item
	switch major {
	case 0:
		it = item{kind: kindUnsigned, value: arg}
	case 1:
		it = item{kind: kindNegative, value: arg}
	case 2, 3:
		if arg > remaining {
			return item{}, errTruncated
		}
		it = item{kind: kindBytes, bytes: r.b[r.i : r.i+int(arg) : r.i+int(arg)]}
		r.i += int(arg)
		if major == 3 {
			if !utf8.Valid(it.bytes) {
				return item{}, errors.New("a text string that isn't UTF-8")
			}
			it.kind = kindText
		}
	case 4:
		if arg > remaining { // every element takes at least a byte
			return item{}, errTruncated
		}
		it = item{kind: kindArray}
		for range arg {
			e, err := r.item(depth+1, false)
			if err != nil {
				return item{}, err
			}
			it.items = append(it.items, e)
		}
	case 5:
		if !indefinite && arg > remaining/2 { // every entry takes at least two bytes
			return item{}, errTruncated
		}
		it = item{kind: kindMap}
		seen := map[string]bool{}
		for n := uint64(0); ; n++ {
			if indefinite {
				if r.i >= len(r.b) {
					return item{}, errTruncated
				}
				if r.b[r.i] == 0xff {
					r.i++
					break
				}
			} else if n == arg {
				break
			}
			key, err := r.item(depth+1, false)
			if err != nil {
				return item{}, err
			}
			if seen[string(key.raw)] {
				return item{}, errors.New("a duplicate map key")
			}
			seen[string(key.raw)] = true
			value, err := r.item(depth+1, false)
			if err != nil {
				return item{}, err
			}
			it.items = append(it.items, key, value)
		}
	case 6:
		return item{}, errors.New("a tag")
	default: // 7
		if r.b[start] != 0xf6 {
			return item{}, errors.New("a float, boolean or simple value other than null")
		}
		it = item{kind: kindNull}
	}
	it.raw = r.b[start:r.i:r.i]
	return it, nil
}

// text returns a text string's content.
func (it item) text() string { return string(it.bytes) }
