package coordinator

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

func TestCrossNetworkInvitationDoesNotConsumeShare(t *testing.T) {
	store, _, _, now := newStore(t)
	n := fixtureNetwork(t, store)
	a, _, _, _ := enroll(t, store, now)
	b, _, _, _ := enroll(t, store, now)
	second, err := store.CreateNetwork(n.UserID, "second-network")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindDevice(n.UserID, second.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	share, err := store.Share(b.ID, second.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Invite(a.ID, share, now); err == nil {
		t.Fatal("unbound network invitation accepted")
	}
	if err = store.BindDevice(n.UserID, second.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	pair, err := store.Invite(a.ID, share, now)
	if err != nil || pair.NetworkID != second.ID {
		t.Fatal("rejection consumed share or changed network", err)
	}
	if _, err = store.ActOnPair(b.ID, pair.ID, "approve", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActOnPair(a.ID, pair.ID, "confirm", share.Fingerprint, now); err != nil {
		t.Fatal(err)
	}
	if err = store.DeletePair(n.UserID, second.ID, pair.ID, now); err != nil {
		t.Fatal(err)
	}
	sessions := NewSessions(store)
	sessions.Heartbeat(a.ID, now)
	sessions.Heartbeat(b.ID, now)
	if _, err = sessions.Begin(a.ID, pair.ID, 1, now); err == nil {
		t.Fatal("deleted pair authorized attempt")
	}
	if firstPairs, err := store.NetworkPairs(n.UserID, n.ID); err != nil || len(firstPairs) != 0 {
		t.Fatal("pair crossed network", err)
	}
}

func TestNetworkNoOpPreservesIdentityAndRejectedInput(t *testing.T) {
	store, _, _, _ := newStore(t)
	n := fixtureNetwork(t, store)
	unchanged, err := store.RenameNetwork(n.UserID, n.ID, n.Name)
	if err != nil || unchanged != n {
		t.Fatal("no-op replaced network identity", err)
	}
	for _, name := range []string{"", " x", "x ", "x\n", "\x00"} {
		if _, err = store.RenameNetwork(n.UserID, n.ID, name); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
	current, err := networkOwned(store.db, n.UserID, n.ID)
	if err != nil || current != n {
		t.Fatal("rejected input changed persisted network", err)
	}
}

func TestPartialInitializationFailsWithoutOverwritingIdentity(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "identity.key")
	db := filepath.Join(root, "missing-parent", "state.db")
	if err := Initialize(db, key, time.Now()); err == nil {
		t.Fatal("missing database parent silently created")
	}
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = Initialize(db, key, time.Now()); err == nil || err.Error() != "p2p.state_already_exists" {
		t.Fatal("partial initialization was overwritten", err)
	}
	after, err := os.ReadFile(key)
	if err != nil || string(before) != string(after) {
		t.Fatal("partial identity changed", err)
	}
}

func TestDeleteNetworkAndEnrollmentAreAtomic(t *testing.T) {
	store, _, _, now := newStore(t)
	owner := fixtureNetwork(t, store).UserID
	for index := 0; index < 8; index++ {
		n, err := store.CreateNetwork(owner, "concurrent-network")
		if err != nil {
			t.Fatal(err)
		}
		token, err := store.IssueEnrollmentToken(owner, n.ID, now)
		if err != nil {
			t.Fatal(err)
		}
		_, csr := makeCSR(t)
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(2)
		var device Device
		var enrollmentErr, deletionErr error
		go func() {
			defer group.Done()
			<-start
			device, enrollmentErr = store.Enroll(Enrollment{protocol.NewID(), token, csr, "race-device"}, now)
		}()
		go func() { defer group.Done(); <-start; deletionErr = store.DeleteNetwork(owner, n.ID, now) }()
		close(start)
		group.Wait()
		if deletionErr != nil {
			t.Fatal(deletionErr)
		}
		if _, err = networkOwned(store.db, owner, n.ID); err == nil {
			t.Fatal("concurrent deletion lost")
		}
		var count int
		if err = store.db.QueryRow("SELECT count(*) FROM bindings WHERE network_id=? AND active=1", n.ID).Scan(&count); err != nil || count != 0 {
			t.Fatal("partial active binding survived delete", err)
		}
		if enrollmentErr == nil {
			if _, err = bindingOwner(store.db, n.ID, device.ID); err == nil {
				t.Fatal("concurrent enrollment authorized deleted network")
			}
		}
	}
}
