package dpiproxy

import "testing"

func TestQUICInitialDerivedKeys(t *testing.T) {
	dcid := mustHex("8394c8f03e515708")
	keys := deriveClientInitialKeys(dcid)

	check := func(name string, got []byte, want string) {
		t.Helper()
		if hexEncode(got) != want {
			t.Errorf("%s = %s, want %s", name, hexEncode(got), want)
		}
	}
	check("client_key", keys.key, "1f369613dd76d5467730efcbe3b1a22d")
	check("client_iv", keys.iv, "fa044b2f42a3fd3b46fb255c")
	check("client_hp", keys.hp, "9f50449e04a0e810283a1e9933adedd2")
}

func TestQUICInitialDecryptRealPacket(t *testing.T) {
	packet := mustHex("c900000001088394c8f03e515708000040581946b451999b7ca318c0a55e84d79966d2330101efba41060aa067ae7f8b3711a51d64f57f551a66486d0627fb13e5e574e9027cd731e3aa76aaddd0805411755eda3c3ed69a6ce3ca9c678cd86dad52dbcaeb21a7892af1")

	plaintext, sni, err := decryptQUICClientInitial(packet)
	if err != nil {
		t.Fatalf("decryptQUICClientInitial: %v", err)
	}
	if len(plaintext) == 0 {
		t.Fatal("decryptQUICClientInitial returned empty plaintext")
	}
	if sni != "example.com" {
		t.Fatalf("SNI = %q, want %q", sni, "example.com")
	}
}

func TestQUICInitialDecryptRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x00, 0x01, 0x02},
		make([]byte, 200),
	}
	for i, c := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d: panicked: %v", i, r)
				}
			}()
			_, sni, err := decryptQUICClientInitial(c)
			if err == nil {
				t.Errorf("case %d: expected error, got sni=%q", i, sni)
			}
		}()
	}
}

func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
