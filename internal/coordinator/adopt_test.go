package coordinator

import (
	"testing"

	"github.com/ankye/dshker-server/internal/protocol"
)

// Joining a network is the authorization. Requiring an invite code between two
// devices the same user bound to the same network made membership grant nothing,
// so these tests fix the adoption behaviour and its trust boundary.

func TestAdoptNetworkPairsDevicesSharingANetwork(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	first, _, _, _ := enroll(t, store, now)
	second, _, _, _ := enroll(t, store, now)
	for _, device := range []Device{first, second} {
		if err := store.BindDevice(network.UserID, network.ID, device.ID); err != nil {
			t.Fatal(err)
		}
	}
	pairs, err := store.AdoptNetwork(first.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected one adopted pair, got %d", len(pairs))
	}
	// Usable immediately: there is no second party left to confirm anything.
	if pairs[0].State != "active" {
		t.Fatalf("expected an active pair, got %q", pairs[0].State)
	}
	if pairs[0].NetworkID != network.ID {
		t.Fatal("pair was not created in the shared network")
	}
}

func TestAdoptNetworkIsIdempotent(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	first, _, _, _ := enroll(t, store, now)
	second, _, _, _ := enroll(t, store, now)
	for _, device := range []Device{first, second} {
		if err := store.BindDevice(network.UserID, network.ID, device.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.AdoptNetwork(first.ID, now); err != nil {
		t.Fatal(err)
	}
	// A second pass must not duplicate the pair: startup runs this every time.
	again, err := store.AdoptNetwork(first.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("expected no new pairs, got %d", len(again))
	}
	pairs, err := store.Pairs(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 1 {
		t.Fatalf("expected exactly one pair to exist, got %d", len(pairs))
	}
}

func TestAdoptNetworkNeverReachesAnotherAccount(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	mine, _, _, _ := enroll(t, store, now)
	if err := store.BindDevice(network.UserID, network.ID, mine.ID); err != nil {
		t.Fatal(err)
	}
	// A second account with its own network and its own bound device.
	other, err := store.CreateUser("other@test.com", "other-password-123")
	if err != nil {
		t.Fatal(err)
	}
	otherNetwork, err := store.CreateNetwork(other.ID, "other-network")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := store.IssueEnrollmentToken(other.ID, otherNetwork.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	_, csr := makeCSR(t)
	theirs, err := store.Enroll(Enrollment{protocol.NewID(), secret, csr, "theirs"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindDevice(other.ID, otherNetwork.ID, theirs.ID); err != nil {
		t.Fatal(err)
	}
	pairs, err := store.AdoptNetwork(mine.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("adopted a device from another account: %+v", pairs)
	}
}

func TestAdoptNetworkSkipsARevokedDevice(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	first, _, _, _ := enroll(t, store, now)
	second, _, _, _ := enroll(t, store, now)
	for _, device := range []Device{first, second} {
		if err := store.BindDevice(network.UserID, network.ID, device.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec("UPDATE devices SET revoked=1 WHERE id=?", second.ID); err != nil {
		t.Fatal(err)
	}
	pairs, err := store.AdoptNetwork(first.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("adopted a revoked device: %+v", pairs)
	}
}

func TestAdoptNetworkWithNoPeersSucceeds(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	only, _, _, _ := enroll(t, store, now)
	if err := store.BindDevice(network.UserID, network.ID, only.ID); err != nil {
		t.Fatal(err)
	}
	// The first machine to start has nobody to pair with; that is not a failure.
	pairs, err := store.AdoptNetwork(only.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 0 {
		t.Fatalf("expected no pairs, got %d", len(pairs))
	}
}
