package awsnitro

import (
	"bytes"
	"testing"
)

func TestDecodeCBORRejects(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, maxDepth+2) // arrays of one array of …
	for name, raw := range map[string][]byte{
		"empty":                        {},
		"truncated argument":           {0x19, 0x01},
		"truncated string":             {0x45, 1, 2},
		"a length beyond the input":    {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"an array beyond the input":    {0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"a map beyond the input":       {0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"an unterminated map":          {0xbf, 0x01, 0x02},
		"reserved additional info":     {0x1c},
		"a stray break":                {0xff},
		"undefined":                    {0xf7},
		"nested too deeply":            append(deep, 0xf6),
		"an indefinite map inside one": {0xbf, 0x01, 0xbf, 0xff, 0xff},
	} {
		if _, err := decodeCBOR(raw, true); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := decodeCBOR([]byte{0xbf, 0x01, 0x02, 0xff}, false); err == nil {
		t.Error("an indefinite map where none is allowed: accepted")
	}
	for _, raw := range [][]byte{{0x18, 24}, {0x19, 1, 0}, {0x1a, 0, 1, 0, 0}, {0x1b, 0, 0, 0, 1, 0, 0, 0, 0}, {0x38, 24}} {
		it, err := decodeCBOR(raw, false)
		if err != nil || !bytes.Equal(encodeItem(it), raw) {
			t.Errorf("%x: %v", raw, err)
		}
	}
}
