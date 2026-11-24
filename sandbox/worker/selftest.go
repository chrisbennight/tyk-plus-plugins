package worker

import (
	"net"
	"os"
	"time"
)

// SelfTest is what a worker reports when started in self-test mode inside a
// fresh sandbox. It stands in for a program that has already escaped the
// JavaScript engine, and records whether each way out was blocked.
func SelfTest(hostFile string) map[string]string {
	outcome := func(err error) string {
		if err != nil {
			return "blocked"
		}
		return "allowed"
	}
	return map[string]string{
		"network": outcome(func() error {
			c, err := net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second)
			if err == nil {
				c.Close()
			}
			return err
		}()),
		"host file": outcome(func() error { _, err := os.ReadFile(hostFile); return err }()),
		"write":     outcome(os.WriteFile("/self-test", []byte("x"), 0o600)),
	}
}
