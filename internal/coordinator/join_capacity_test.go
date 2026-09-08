package coordinator

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

// joinEnroll performs a login-free join into the given network.
func joinEnroll(t *testing.T, store *Store, networkID string, now time.Time) (Device, ed25519.PrivateKey, string) {
	t.Helper()
	private, csr := makeCSR(t)
	request := NetworkJoin{RequestID: protocol.NewID(), NetworkID: networkID, CSR: csr, Name: "加入电脑"}
	device, err := store.JoinNetwork(request, now)
	if err != nil {
		t.Fatal(err)
	}
	return device, private, csr
}

func TestLoginFreeJoinEnrollsIntoNetwork(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	device, _, _ := joinEnroll(t, store, network.ID, now)
	if device.UserID != network.UserID {
		t.Fatalf("join device owner = %s, want network owner %s", device.UserID, network.UserID)
	}
	if device.ID == "" || len(device.Certificate) == 0 {
		t.Fatal("join produced no device identity or certificate")
	}
}

func TestLoginFreeJoinRejectsUnknownNetwork(t *testing.T) {
	store, _, _, now := newStore(t)
	_, csr := makeCSR(t)
	missing := "00000000000000000000000000000000"
	request := NetworkJoin{RequestID: protocol.NewID(), NetworkID: missing, CSR: csr, Name: "电脑"}
	if _, err := store.JoinNetwork(request, now); err == nil || err.Error() != "p2p.network_unauthorized" {
		t.Fatalf("unknown network join not rejected: %v", err)
	}
}

func TestJoinHonorsNetworkCapacity(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	if network.MaxDevices != DefaultNetworkLimit {
		t.Fatalf("default limit = %d, want %d", network.MaxDevices, DefaultNetworkLimit)
	}
	for i := 0; i < DefaultNetworkLimit; i++ {
		joinEnroll(t, store, network.ID, now)
	}
	_, csr := makeCSR(t)
	request := NetworkJoin{RequestID: protocol.NewID(), NetworkID: network.ID, CSR: csr, Name: "超额"}
	if _, err := store.JoinNetwork(request, now); err == nil || err.Error() != "p2p.network_full" {
		t.Fatalf("join over capacity not rejected: %v", err)
	}
}

func TestRaiseNetworkLimitAllowsMoreJoins(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	updated, err := store.UpdateNetworkLimit(network.UserID, network.ID, 20)
	if err != nil || updated.MaxDevices != 20 {
		t.Fatalf("limit not raised: %v %+v", err, updated)
	}
	if _, err = store.UpdateNetworkLimit(network.UserID, network.ID, 15); err == nil || err.Error() != "p2p.invalid_network_limit" {
		t.Fatalf("invalid limit accepted: %v", err)
	}
	// After raising to 20, more than the original default of 10 devices join.
	for i := 0; i < 12; i++ {
		joinEnroll(t, store, network.ID, now)
	}
}

func TestLowerNetworkLimitDoesNotEvict(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	// 12 devices join under a raised limit of 20.
	if _, err := store.UpdateNetworkLimit(network.UserID, network.ID, 20); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		joinEnroll(t, store, network.ID, now)
	}
	// Lowering to 10 keeps the 12 bound devices; only new joins are rejected.
	lowered, err := store.UpdateNetworkLimit(network.UserID, network.ID, 10)
	if err != nil || lowered.MaxDevices != 10 {
		t.Fatalf("lower limit failed: %v %+v", err, lowered)
	}
	_, csr := makeCSR(t)
	request := NetworkJoin{RequestID: protocol.NewID(), NetworkID: network.ID, CSR: csr, Name: "再来"}
	if _, err := store.JoinNetwork(request, now); err == nil || err.Error() != "p2p.network_full" {
		t.Fatalf("join after lowering limit not rejected: %v", err)
	}
}

func TestJoinRejectsInvalidInput(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	_, csr := makeCSR(t)
	cases := []NetworkJoin{
		{RequestID: "", NetworkID: network.ID, CSR: csr, Name: "x"},
		{RequestID: protocol.NewID(), NetworkID: "BADID", CSR: csr, Name: "x"},
		{RequestID: protocol.NewID(), NetworkID: network.ID, CSR: "not a csr", Name: "x"},
		{RequestID: protocol.NewID(), NetworkID: network.ID, CSR: csr, Name: " x"},
	}
	for index, request := range cases {
		if _, err := store.JoinNetwork(request, now); err == nil {
			t.Fatalf("case %d accepted invalid join", index)
		}
	}
}
