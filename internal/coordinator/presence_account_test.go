package coordinator

import (
	"testing"
	"time"
)

// Presence belongs to an account. A machine that is signed in nowhere reports
// nothing and reads as offline, and one account's report never makes the machine
// look online to another account that is linked to the same device.
func TestPresenceIsScopedToTheSignedInAccount(t *testing.T) {
	store, _, _, now := newStore(t)
	sessions := NewSessions(store)
	first, second := enrollTwoAccounts(t, store, now)

	if err := sessions.Heartbeat(first.ID, "", DeviceTelemetry{}, now); err != nil {
		t.Fatal(err)
	}
	if got := sessions.Presence(first.ID, first.UserID, now); got != "offline" {
		t.Fatalf("a heartbeat with no account reported %q, want offline", got)
	}

	if err := sessions.Heartbeat(first.ID, first.UserID, DeviceTelemetry{}, now); err != nil {
		t.Fatal(err)
	}
	if got := sessions.Presence(first.ID, first.UserID, now); got != "online" {
		t.Fatalf("presence for the signed-in account = %q, want online", got)
	}
	if got := sessions.Presence(first.ID, second.UserID, now); got != "offline" {
		t.Fatalf("the other account sees %q, want offline", got)
	}

	// A report for an account the device is not linked to is refused, not believed.
	stranger, strangerNetwork := secondAccount(t, store, "presence-stranger@test.com", "stranger-network")
	if strangerNetwork.UserID != stranger.ID {
		t.Fatal("fixture network owner mismatch")
	}
	if err := sessions.Heartbeat(first.ID, stranger.ID, DeviceTelemetry{}, now); err == nil {
		t.Fatal("a heartbeat for an unlinked account was accepted")
	}

	// Losing the socket clears every account this machine reported for.
	sessions.Offline(first.ID, "")
	if got := sessions.Presence(first.ID, first.UserID, now); got != "offline" {
		t.Fatalf("after the socket closed presence = %q, want offline", got)
	}
}

// enrollTwoAccounts returns one machine enrolled under two accounts: the point is
// that presence has to be answered per account for the same device id.
func enrollTwoAccounts(t *testing.T, store *Store, now time.Time) (Device, Device) {
	t.Helper()
	network := fixtureNetwork(t, store)
	_, csr := makeCSR(t)
	same := enrollInto(t, store, network.UserID, network.ID, csr, "电脑", now)

	second, secondNetwork := secondAccount(t, store, "presence-second@test.com", "presence-network")
	if secondNetwork.UserID != second.ID {
		t.Fatalf("fixture network owner = %s, want %s", secondNetwork.UserID, second.ID)
	}
	enrolled := enrollInto(t, store, second.ID, secondNetwork.ID, csr, "电脑", now)
	if enrolled.ID != same.ID {
		t.Fatalf("the same machine enrolled as two devices: %s and %s", same.ID, enrolled.ID)
	}
	// The device knows both accounts; only the account it reports for is online.
	return Device{ID: same.ID, UserID: network.UserID}, Device{ID: same.ID, UserID: second.ID}
}
