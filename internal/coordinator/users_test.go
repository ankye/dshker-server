package coordinator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

func TestUserSessionsIsolationRestartLogoutAndDisable(t *testing.T) {
	store, db, key, now := newStore(t)
	if _, err := store.CreateUser("short", "short"); err == nil {
		t.Fatal("weak password accepted")
	}
	if _, err := store.CreateUser("fixture-user", "fixture-password-123"); err == nil {
		t.Fatal("duplicate user accepted")
	}
	for _, username := range []string{"fixture-user", "unknown-user"} {
		if _, err := store.Login(username, "wrong", now); err == nil || err.Error() != "p2p.login_failed" {
			t.Fatal("credential error differs", err)
		}
	}
	session, err := store.Login("fixture-user", "fixture-password-123", now)
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	if err = store.db.QueryRow("SELECT hash FROM user_sessions WHERE user_id=?", session.User.ID).Scan(&hash); err != nil || hash == session.Token || hash != digest(session.Token) {
		t.Fatal("token stored in clear", err)
	}
	reopened, err := OpenStore(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if user, err := reopened.AuthenticateUser(session.Token, now); err != nil || user != session.User {
		t.Fatal("restart lost session", err)
	}
	if _, err = reopened.AuthenticateUser(session.Token, now.Add(24*time.Hour)); err == nil {
		t.Fatal("expired session accepted")
	}
	if err = reopened.Logout(session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AuthenticateUser(session.Token, now); err == nil {
		t.Fatal("logout did not persist")
	}
	session, err = store.Login("fixture-user", "fixture-password-123", now)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.DisableUser(session.User.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AuthenticateUser(session.Token, now); err == nil {
		t.Fatal("disabled session accepted")
	}
	if _, err = store.Login("fixture-user", "fixture-password-123", now); err == nil {
		t.Fatal("disabled login accepted")
	}
}

func TestPrivateNetworksMembershipAndRevocation(t *testing.T) {
	store, db, key, now := newStore(t)
	n := fixtureNetwork(t, store)
	other, err := store.CreateUser("other-user", "other-password-123")
	if err != nil {
		t.Fatal(err)
	}
	otherNetwork, err := store.CreateNetwork(other.ID, "other network")
	if err != nil {
		t.Fatal(err)
	}
	a, _, _, _ := enroll(t, store, now)
	b, _, _, _ := enroll(t, store, now)
	pair := pairDevices(t, store, a, b, now)
	for name, operation := range map[string]func() error{
		"rename":              func() error { _, e := store.RenameNetwork(other.ID, n.ID, "hijacked"); return e },
		"delete":              func() error { return store.DeleteNetwork(other.ID, n.ID, now) },
		"enrollment":          func() error { _, e := store.IssueEnrollmentToken(other.ID, n.ID, now); return e },
		"bind foreign device": func() error { return store.BindDevice(other.ID, otherNetwork.ID, a.ID) },
		"unbind":              func() error { return store.UnbindDevice(other.ID, n.ID, a.ID, now) },
		"delete pair":         func() error { return store.DeletePair(other.ID, n.ID, pair.ID, now) },
		"list devices":        func() error { _, e := store.NetworkDevices(other.ID, n.ID); return e },
		"list pairs":          func() error { _, e := store.NetworkPairs(other.ID, n.ID); return e },
	} {
		t.Run(name, func(t *testing.T) {
			if operation() == nil {
				t.Fatal("cross-user resource admitted")
			}
		})
	}
	listed, err := store.Networks(other.ID)
	if err != nil || len(listed) != 1 || listed[0].ID != otherNetwork.ID {
		t.Fatal("network list leaked", listed, err)
	}
	if current, err := networkOwned(store.db, n.UserID, n.ID); err != nil || current.Name != n.Name {
		t.Fatal("foreign operation mutated network", err)
	}
	if renamed, err := store.RenameNetwork(n.UserID, n.ID, "renamed"); err != nil || renamed.ID != n.ID {
		t.Fatal("rename replaced identity", err)
	}
	secondNetwork, err := store.CreateNetwork(n.UserID, "second")
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range []Device{a, b} {
		if err = store.BindDevice(n.UserID, secondNetwork.ID, device.ID); err != nil {
			t.Fatal(err)
		}
	}
	sessions := NewSessions(store)
	sessions.Heartbeat(a.ID, now)
	sessions.Heartbeat(b.ID, now)
	lease, err := sessions.Begin(a.ID, pair.ID, 1, now)
	if err != nil || lease.UserID != n.UserID || lease.NetworkID != n.ID {
		t.Fatal("lease scope missing", err)
	}
	if err = store.UnbindDevice(n.UserID, n.ID, a.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.Renew(a.ID, pair.ID, lease.AttemptID, now); err == nil {
		t.Fatal("renewed unbound lease")
	}
	if err = store.BindDevice(n.UserID, n.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if pair, err = store.Pair(a.ID, pair.ID); err != nil || pair.State != "revoked" {
		t.Fatal("rebind restored pairing", err)
	}
	if devices, err := store.NetworkDevices(n.UserID, secondNetwork.ID); err != nil || len(devices) != 2 {
		t.Fatal("unbind crossed network", err)
	}
	token, err := store.IssueEnrollmentToken(n.UserID, n.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteNetwork(n.UserID, n.ID, now); err != nil {
		t.Fatal(err)
	}
	_, csr := makeCSR(t)
	if _, err = store.Enroll(Enrollment{protocol.NewID(), token, csr, "deleted"}, now); err == nil {
		t.Fatal("deleted network enrollment accepted")
	}
	if err = store.DeleteNetwork(n.UserID, n.ID, now); err == nil {
		t.Fatal("repeated deletion silently succeeded")
	}
	reopened, err := OpenStore(db, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = networkOwned(reopened.db, n.UserID, n.ID); err == nil {
		t.Fatal("restart restored deleted network")
	}
	if pairs, err := reopened.NetworkPairs(n.UserID, secondNetwork.ID); err != nil || len(pairs) != 0 {
		t.Fatal("network isolation failed", err)
	}
}

func TestGinUserAPIRealTLSAndStrictAdmission(t *testing.T) {
	_, surface, client, _ := networkServer(t)
	var session UserSession
	if status := post(t, client, surface.URL+"/v1/login", loginRequest{"fixture-user", "fixture-password-123"}, &session); status != 200 {
		t.Fatal(status)
	}
	call := func(method, path, body, token string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(method, surface.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var buffer bytes.Buffer
		if _, err = buffer.ReadFrom(response.Body); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, buffer.Bytes()
	}
	status, data := call("POST", "/v1/networks", `{"name":"API network"}`, session.Token)
	var network Network
	if status != 200 || json.Unmarshal(data, &network) != nil || network.UserID != session.User.ID {
		t.Fatal("create failed", status, string(data))
	}
	for _, body := range []string{`{"name":"x","userId":"foreign"}`, `{"name":"one","name":"two"}`, `{}`, `{"name":null}`} {
		if status, _ := call("POST", "/v1/networks", body, session.Token); status == 200 {
			t.Fatal("malformed body accepted", body)
		}
	}
	if status, _ = call("GET", "/v1/networks", "", ""); status == 200 {
		t.Fatal("anonymous management admitted")
	}
	if status, _ = call("GET", "/v1/me", "", session.Token); status == 200 {
		t.Fatal("user token replaced device proof")
	}
	if status, _ = call("PATCH", "/v1/networks/"+network.ID, `{"name":"API renamed"}`, session.Token); status != 200 {
		t.Fatal("rename failed", status)
	}
	if status, _ = call("DELETE", "/v1/networks/"+network.ID, `{}`, session.Token); status != 200 {
		t.Fatal("delete failed", status)
	}
	if status, _ = call("POST", "/v1/logout", `{}`, session.Token); status != 200 {
		t.Fatal("logout failed", status)
	}
	if status, _ = call("GET", "/v1/networks", "", session.Token); status == 200 {
		t.Fatal("logged out token accepted")
	}
}
