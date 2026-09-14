package coordinator

import (
	"bytes"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

// enrollInto issues a token for one account's network and enrolls the given
// machine key into it.
func enrollInto(t *testing.T, store *Store, userID, networkID string, csr string, name string, now time.Time) Device {
	t.Helper()
	token, err := store.IssueEnrollmentToken(userID, networkID, now)
	if err != nil {
		t.Fatal(err)
	}
	device, err := store.Enroll(Enrollment{protocol.NewID(), token, csr, name}, now)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func secondAccount(t *testing.T, store *Store, email, network string) (User, Network) {
	t.Helper()
	user, err := store.CreateUser(email, "second-password-123")
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateNetwork(user.ID, network)
	if err != nil {
		t.Fatal(err)
	}
	return user, created
}

// A device id belongs to the machine, like a hardware address: enrolling the same
// key again — under another account — must be the same device, not a new one. A
// minted-per-enrollment id is what left every pair, pin and catalog row pointing
// at an identity that no longer existed.
func TestMachineKeepsItsDeviceIDAcrossAccounts(t *testing.T) {
	store, _, _, now := newStore(t)
	first := fixtureNetwork(t, store)
	_, csr := makeCSR(t)
	account := enrollInto(t, store, first.UserID, first.ID, csr, "电脑", now)

	second, secondNetwork := secondAccount(t, store, "second@test.com", "second-network")
	again := enrollInto(t, store, second.ID, secondNetwork.ID, csr, "电脑", now)

	if again.ID != account.ID {
		t.Fatalf("the same machine enrolled as a different device: %s then %s", account.ID, again.ID)
	}
	public, err := csrKey(csr)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.KeyID(public) != account.ID {
		t.Fatalf("device id %s is not derived from the machine key", account.ID)
	}
	if again.UserID != second.ID {
		t.Fatalf("the enrollment reported account %s, want the enrolling account %s", again.UserID, second.ID)
	}
	// Both accounts see the machine, and neither sees the other's networks through it.
	for _, userID := range []string{first.UserID, second.ID} {
		devices, err := store.UserDevices(userID)
		if err != nil {
			t.Fatal(err)
		}
		if len(devices) != 1 || devices[0].DeviceID != account.ID {
			t.Fatalf("account %s sees %+v, want the one machine", userID, devices)
		}
	}
}

// Re-enrolling a known machine keeps its certificate: the device already
// identified itself with it, and replacing it would invalidate every session that
// authenticated with the old one for no reason.
func TestReenrollingAMachineReusesItsIdentity(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	_, csr := makeCSR(t)
	first := enrollInto(t, store, network.UserID, network.ID, csr, "电脑", now)
	second := enrollInto(t, store, network.UserID, network.ID, csr, "电脑改名", now)

	if second.ID != first.ID || !bytes.Equal(second.Certificate, first.Certificate) {
		t.Fatal("re-enrolling the same machine issued a new identity or certificate")
	}
	if second.Name != "电脑改名" {
		t.Fatalf("re-enrollment did not refresh the machine name: %q", second.Name)
	}
}

// Revocation is deliberate, so a machine that enrolls again must not come back.
func TestARevokedMachineStaysRevokedWhenItEnrollsAgain(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	_, csr := makeCSR(t)
	device := enrollInto(t, store, network.UserID, network.ID, csr, "电脑", now)
	if _, err := store.db.Exec("UPDATE devices SET revoked=1 WHERE id=?", device.ID); err != nil {
		t.Fatal(err)
	}
	enrollInto(t, store, network.UserID, network.ID, csr, "电脑", now)

	var revoked int
	if err := store.db.QueryRow("SELECT revoked FROM devices WHERE id=?", device.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked == 0 {
		t.Fatal("re-enrollment revived a revoked device")
	}
	if _, err := store.UserDevices(network.UserID); err != nil {
		t.Fatal(err)
	}
	devices, err := store.UserDevices(network.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("a revoked machine is still listed: %+v", devices)
	}
}
