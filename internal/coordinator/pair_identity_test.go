package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPairIdentityRealTLSReadbackAndAdmission(t *testing.T) {
	server, surface, client, now := networkServer(t)
	a, aKey, _, _ := enroll(t, server.store, now)
	b, bKey, _, _ := enroll(t, server.store, now)
	other, otherKey, _, _ := enroll(t, server.store, now)
	share, err := server.store.Share(b.ID, fixtureNetwork(t, server.store).ID, now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := server.store.Invite(a.ID, share, now)
	if err != nil {
		t.Fatal(err)
	}
	request := func(device Device, key ed25519.PrivateKey) (int, []byte) {
		t.Helper()
		transport := client.Transport.(*http.Transport).Clone()
		if key != nil {
			transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{device.Certificate}, PrivateKey: key}}
		}
		defer transport.CloseIdleConnections()
		authenticated := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := authenticated.Get(surface.URL + "/v1/pairs/" + pair.ID + "/identity")
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	assertIdentity := func(device Device, key ed25519.PrivateKey, expectedState string) {
		t.Helper()
		status, body := request(device, key)
		var actual PairIdentity
		if status != http.StatusOK || json.Unmarshal(body, &actual) != nil {
			t.Fatalf("identity read failed: %d %s", status, body)
		}
		if actual.Pair.ID != pair.ID || actual.Pair.NetworkID != pair.NetworkID || actual.Pair.State != expectedState || actual.Initiator.DeviceID != a.ID || actual.Target.DeviceID != b.ID || actual.Initiator.UserID != a.UserID || actual.Target.UserID != b.UserID || !bytes.Equal(actual.Initiator.PublicKey, a.PublicKey) || !bytes.Equal(actual.Target.PublicKey, b.PublicKey) || actual.Initiator.Name != a.Name || actual.Target.Name != b.Name {
			t.Fatal("pair identity readback differs from persisted participants")
		}
		if actual.Initiator.Presence != "online" || actual.Target.Presence != "offline" {
			t.Fatal("presence was not read from current device heartbeat")
		}
		if strings.Contains(string(body), "certificate") || strings.Contains(string(body), "privateKey") {
			t.Fatal("identity response exposed unnecessary credentials")
		}
	}
	if err = server.sessions.Heartbeat(a.ID, DeviceTelemetry{}, now); err != nil {
		t.Fatal(err)
	}
	assertIdentity(a, aKey, "invited")
	assertIdentity(b, bKey, "invited")
	if _, err = server.sessions.Begin(a.ID, pair.ID, 1, now); err == nil {
		t.Fatal("identity read granted connection before confirmation")
	}
	for _, unauthorized := range []struct {
		device Device
		key    ed25519.PrivateKey
	}{{other, otherKey}, {Device{}, nil}} {
		status, body := request(unauthorized.device, unauthorized.key)
		if status == http.StatusOK || bytes.Contains(body, a.PublicKey) || strings.Contains(string(body), a.ID) || strings.Contains(string(body), b.ID) {
			t.Fatal("unrelated caller obtained pair participants")
		}
	}
	if _, err = server.store.ActOnPair(b.ID, pair.ID, "approve", "", now); err != nil {
		t.Fatal(err)
	}
	assertIdentity(a, aKey, "approved")
	if _, err = server.store.ActOnPair(a.ID, pair.ID, "confirm", share.Fingerprint, now); err != nil {
		t.Fatal(err)
	}
	assertIdentity(a, aKey, "active")
	if _, err = server.store.ActOnPair(a.ID, pair.ID, "revoke", "", now); err != nil {
		t.Fatal(err)
	}
	status, body := request(b, bKey)
	if status != http.StatusForbidden || !strings.Contains(string(body), "p2p.pair_unauthorized") {
		t.Fatal("revoked identity remained readable", status, string(body))
	}
}

func TestPairIdentityRejectsExpiredUnboundAndRestartedPresence(t *testing.T) {
	for _, state := range []string{"expired", "rejected", "unbound", "restart"} {
		t.Run(state, func(t *testing.T) {
			server, _, _, now := networkServer(t)
			a, _, _, _ := enroll(t, server.store, now)
			b, _, _, _ := enroll(t, server.store, now)
			share, err := server.store.Share(b.ID, fixtureNetwork(t, server.store).ID, now)
			if err != nil {
				t.Fatal(err)
			}
			pair, err := server.store.Invite(a.ID, share, now)
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "expired":
				now = now.Add(5 * time.Minute)
			case "rejected":
				_, err = server.store.ActOnPair(b.ID, pair.ID, "reject", "", now)
			case "unbound":
				_, err = server.store.db.Exec("UPDATE bindings SET active=0 WHERE network_id=? AND device_id=?", pair.NetworkID, b.ID)
			case "restart":
				if err = server.sessions.Heartbeat(a.ID, DeviceTelemetry{}, now); err != nil {
					t.Fatal(err)
				}
				server.sessions = NewSessions(server.store)
			}
			if err != nil {
				t.Fatal(err)
			}
			actual, err := server.pairIdentity(a.ID, pair.ID, now)
			if state == "restart" {
				if err != nil || actual.Pair.ID != pair.ID || actual.Initiator.Presence != "offline" || actual.Target.Presence != "offline" {
					t.Fatal("restart revived presence or changed pair identity", err)
				}
			} else if err == nil {
				t.Fatal("invalid relationship disclosed identities")
			}
		})
	}
}
