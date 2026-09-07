package coordinator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigStrictInputsAndExactReadback(t *testing.T) {
	root := t.TempDir()
	config := Config{HTTPSOrigin: "https://localhost:8443", WSSURL: "wss://localhost:8443/v1/signals", HTTPSListen: "127.0.0.1:8443", STUNListen: "127.0.0.1:3478", STUNAddress: "localhost:3478", TLSCertPath: filepath.Join(root, "tls.crt"), TLSKeyPath: filepath.Join(root, "tls.key"), DatabasePath: filepath.Join(root, "state.db"), IdentityKeyPath: filepath.Join(root, "identity.key")}
	path := filepath.Join(root, "config.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	readback, err := ReadConfig(path)
	if err != nil || readback != config {
		t.Fatal("config readback substituted explicit values", err)
	}
	for name, mutate := range map[string]func(*Config){
		"clear TLS path":     func(c *Config) { c.TLSCertPath = "" },
		"HTTP":               func(c *Config) { c.HTTPSOrigin = "http://localhost:8443" },
		"foreign WSS":        func(c *Config) { c.WSSURL = "wss://other:8443/v1/signals" },
		"implicit STUN port": func(c *Config) { c.STUNAddress = "localhost" },
		"zero port":          func(c *Config) { c.STUNListen = "127.0.0.1:0" },
		"large port":         func(c *Config) { c.HTTPSListen = "127.0.0.1:65536" },
		"same state paths":   func(c *Config) { c.IdentityKeyPath = c.DatabasePath },
	} {
		t.Run(name, func(t *testing.T) {
			changed := config
			mutate(&changed)
			if changed.Validate() == nil {
				t.Fatal("invalid explicit configuration accepted")
			}
		})
	}
	for _, body := range []string{`{}`, `{"httpsOrigin":"x","httpsOrigin":"y"}`, `null`} {
		if err = os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadConfig(path); err == nil {
			t.Fatal("ambiguous config accepted")
		}
	}
	if _, err = ReadConfig(filepath.Join(root, "absent.json")); err == nil {
		t.Fatal("missing configuration replaced")
	}
}
