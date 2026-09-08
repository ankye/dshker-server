package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/coordinator"
)

func TestCLIInitCreateDisableAndNoSecretOutput(t *testing.T) {
	root := t.TempDir()
	config := coordinator.Config{HTTPSOrigin: "https://localhost:8443", WSSURL: "wss://localhost:8443/v1/signals", HTTPSListen: "127.0.0.1:8443", STUNListen: "127.0.0.1:3478", STUNAddress: "localhost:3478", TLSCertPath: filepath.Join(root, "tls.crt"), TLSKeyPath: filepath.Join(root, "tls.key"), DatabasePath: filepath.Join(root, "state.db"), IdentityKeyPath: filepath.Join(root, "identity.key")}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var output bytes.Buffer
	if err = run(ctx, []string{"init", "--config", path}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if err = run(ctx, []string{"init", "--config", path}, strings.NewReader(""), &output); err == nil {
		t.Fatal("init overwrote state")
	}
	output.Reset()
	password := "cli-secret-password-123"
	if err = run(ctx, []string{"user-add", "--config", path, "--username", "cli@test.com"}, strings.NewReader(password+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	var user coordinator.User
	if json.Unmarshal(output.Bytes(), &user) != nil || user.ID == "" || strings.Contains(output.String(), password) {
		t.Fatal("user result leaked secret or missing id")
	}
	store, err := coordinator.OpenStore(config.DatabasePath, config.IdentityKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	session, err := store.Login("cli@test.com", password, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = run(ctx, []string{"user-disable", "--config", path, "--user-id", user.ID}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AuthenticateUser(session.Token, time.Now()); err == nil {
		t.Fatal("CLI disable did not persist")
	}
}

func TestCLIRequiresExplicitInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"serve"}, {"unknown"}, {"init", "--password", "secret"}, {"init", "--config", "missing", "--username", "unused"}} {
		if err := run(context.Background(), args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal("incomplete command admitted", args)
		}
	}
}
