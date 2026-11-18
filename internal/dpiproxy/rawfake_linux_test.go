//go:build linux

package dpiproxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestInjectedDecoyNeverReachesServerApplication(t *testing.T) {
	if err := rawFakeAvailable(); err != nil {
		t.Skipf("raw fake packets unavailable: %v", err)
	}

	for _, m := range []string{"ttl", "md5", "badseq", "badsum"} {
		t.Run(m, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			got := make(chan []byte, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()

				c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
				data, _ := io.ReadAll(c)
				got <- data
			}()

			c, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			cfg := defaultConfig()
			cfg.FakeMethod = m
			if !sendFakeClientHellos(c, [2]byte{3, 1}, cfg) {
				t.Fatal("decoy was not sent")
			}
			time.Sleep(100 * time.Millisecond)
			if _, err := c.Write([]byte("REAL-DATA")); err != nil {
				t.Fatal(err)
			}
			c.Close()

			select {
			case data := <-got:
				if m == "ttl" {
					if string(data) == "REAL-DATA" {
						t.Fatal("control failed: a valid decoy was not delivered, the test proves nothing")
					}
				} else if string(data) != "REAL-DATA" {
					t.Fatalf("server application received %q", data)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout")
			}
		})
	}
}
