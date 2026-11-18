package dpiproxy

import "testing"

func FuzzParseClientHello(f *testing.F) {
	f.Add(buildProbeClientHello("example.com"))
	f.Add(buildProbeClientHello(""))
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00, 0x00})
	f.Add([]byte{0x01, 0xff, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseClientHello panicked on input %x: %v", data, r)
			}
		}()
		ch, err := parseClientHello(data)
		if err != nil {
			return
		}

		serializeClientHello(ch)
		extractSNI(data)
		applyTLSProfile(ch, "chrome")
		shuffleClientHello(ch)
	})
}

func FuzzExtractSNI(f *testing.F) {
	f.Add(buildProbeClientHello("example.com"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("extractSNI panicked on input %x: %v", data, r)
			}
		}()
		extractSNI(data)
	})
}
