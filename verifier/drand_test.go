package verifier

import (
	"encoding/hex"
	"testing"
	"time"
)

// Real quicknet rounds, as served by api.drand.sh.
func TestDrandQuicknet(t *testing.T) {
	c, err := DrandQuicknet()
	if err != nil {
		t.Fatal(err)
	}
	rounds := map[uint64]string{
		1000:     "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39",
		33638467: "b30c2babcb6b1aa5f1fd2aa3fd7db6c8a21ecc2c7e5b2724417f23bf3b717ff036091e64f2f7dcaeb11572ab58a5d959",
	}
	for round, s := range rounds {
		sig, _ := hex.DecodeString(s)
		if err := c.Verify(round, sig); err != nil {
			t.Errorf("round %d: %v", round, err)
		}
		if err := c.Verify(round+1, sig); err == nil {
			t.Errorf("round %d's signature accepted for round %d", round, round+1)
		}
		bad := append([]byte{}, sig...)
		bad[10] ^= 1
		if err := c.Verify(round, bad); err == nil {
			t.Errorf("round %d: tampered signature accepted", round)
		}
	}
	if got := c.RoundTime(33638467); !got.Equal(time.Date(2026, 11, 3, 15, 12, 45, 0, time.UTC)) {
		t.Errorf("round time %v", got)
	}
}
