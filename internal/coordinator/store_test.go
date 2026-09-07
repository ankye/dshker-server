package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

func newStore(t *testing.T) (*Store, string, string, time.Time) {
	t.Helper()
	root := t.TempDir()
	database, key := filepath.Join(root, "state.db"), filepath.Join(root, "identity.pem")
	now := time.Now().UTC().Truncate(time.Second)
	if err := Initialize(database, key, now); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(database, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	user, err := store.CreateUser("fixture-user", "fixture-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreateNetwork(user.ID, "fixture-network"); err != nil {
		t.Fatal(err)
	}
	return store, database, key, now
}

func fixtureNetwork(t *testing.T, store *Store) Network {
	t.Helper()
	var n Network
	if err := store.db.QueryRow("SELECT n.id,n.user_id,n.name FROM networks n JOIN users u ON u.id=n.user_id WHERE u.username='fixture-user' AND n.name='fixture-network'").Scan(&n.ID, &n.UserID, &n.Name); err != nil {
		t.Fatal(err)
	}
	return n
}

func fixtureToken(t *testing.T, store *Store, now time.Time) (string, error) {
	t.Helper()
	n := fixtureNetwork(t, store)
	return store.IssueEnrollmentToken(n.UserID, n.ID, now)
}

func makeCSR(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	return private, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func enroll(t *testing.T, store *Store, now time.Time) (Device, ed25519.PrivateKey, string, Enrollment) {
	t.Helper()
	private, csr := makeCSR(t)
	token, err := fixtureToken(t, store, now)
	if err != nil {
		t.Fatal(err)
	}
	request := Enrollment{protocol.NewID(), token, csr, "电脑"}
	device, err := store.Enroll(request, now)
	if err != nil {
		t.Fatal(err)
	}
	return device, private, csr, request
}

func pairDevices(t *testing.T, store *Store, first, second Device, now time.Time) Pair {
	t.Helper()
	share, err := store.Share(second.ID, fixtureNetwork(t, store).ID, now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := store.Invite(first.ID, share, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActOnPair(second.ID, pair.ID, "approve", "", now); err != nil {
		t.Fatal(err)
	}
	pair, err = store.ActOnPair(first.ID, pair.ID, "confirm", share.Fingerprint, now)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestInitializeAndRestartIdentity(t *testing.T) {
	store, database, key, _ := newStore(t)
	before, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if Initialize(database, key, time.Now()) == nil {
		t.Fatal("overwrote existing state")
	}
	second, err := OpenStore(database, key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.ServiceID != store.ServiceID {
		t.Fatal("identity changed at restart")
	}
	after, _ := os.ReadFile(key)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key modified")
	}
	other, _, otherKey, _ := newStore(t)
	if other.ServiceID == store.ServiceID {
		t.Fatal("duplicate entropy")
	}
	if invalid, err := OpenStore(database, otherKey); err == nil {
		invalid.Close()
		t.Fatal("accepted wrong signing identity")
	}
	if _, err := OpenStore(database+"-missing", key); err == nil {
		t.Fatal("created missing database")
	}
}

func TestEnrollmentConcurrentConsumptionAndReadback(t *testing.T) {
	store, _, _, now := newStore(t)
	token, err := fixtureToken(t, store, now)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan Device, 8)
	for i := 0; i < 8; i++ {
		_, csr := makeCSR(t)
		group.Add(1)
		go func() {
			defer group.Done()
			device, err := store.Enroll(Enrollment{protocol.NewID(), token, csr, "same token"}, now)
			if err == nil {
				results <- device
			}
		}()
	}
	group.Wait()
	close(results)
	if len(results) != 1 {
		t.Fatalf("token consumed %d times", len(results))
	}
	winner := <-results
	stored, err := store.Device(winner.ID)
	if err != nil || !bytes.Equal(stored.PublicKey, winner.PublicKey) || !bytes.Equal(stored.Certificate, winner.Certificate) {
		t.Fatal("persisted identity differs", err)
	}
	var hash string
	var used int
	if err = store.db.QueryRow("SELECT hash,used FROM tokens").Scan(&hash, &used); err != nil || hash == token || hash != digest(token) || used != 1 {
		t.Fatal("token storage not hashed/consumed", err)
	}
	_, csr := makeCSR(t)
	if _, err = store.Enroll(Enrollment{protocol.NewID(), token, csr, "reuse"}, now); err == nil {
		t.Fatal("reused token")
	}
}

func TestEnrollmentFailuresDoNotConsumeToken(t *testing.T) {
	store, _, _, now := newStore(t)
	token, _ := fixtureToken(t, store, now)
	_, csr := makeCSR(t)
	request := Enrollment{protocol.NewID(), token, "invalid CSR", "computer"}
	if _, err := store.Enroll(request, now); err == nil {
		t.Fatal("accepted invalid CSR")
	}
	request.CSR = csr
	if _, err := store.Enroll(request, now.Add(5*time.Minute)); err == nil {
		t.Fatal("accepted expired token")
	}
	var used int
	if err := store.db.QueryRow("SELECT used FROM tokens WHERE hash=?", digest(token)).Scan(&used); err != nil || used != 0 {
		t.Fatal("invalid request consumed token", err)
	}
	if _, err := store.Enroll(request, now); err != nil {
		t.Fatal("valid retry failed", err)
	}
}

func TestLostEnrollmentResponseRequiresOwnership(t *testing.T) {
	store, _, _, now := newStore(t)
	device, private, _, request := enroll(t, store, now)
	query := EnrollmentQuery{request.RequestID, device.PublicKey, now.Unix(), ""}
	query.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, query.SigningBytes()))
	result, err := store.ReadEnrollment(query, now)
	if err != nil || result.ID != device.ID || !bytes.Equal(result.Certificate, device.Certificate) {
		t.Fatal("lost reply readback failed", err)
	}
	query.RequestID = protocol.NewID()
	if _, err = store.ReadEnrollment(query, now); err == nil {
		t.Fatal("accepted tampered query")
	}
}

func TestPairApprovalVisibilityRevocationAndRestart(t *testing.T) {
	store, database, key, now := newStore(t)
	a, _, _, _ := enroll(t, store, now)
	b, _, _, _ := enroll(t, store, now)
	outsider, _, _, _ := enroll(t, store, now)
	share, err := store.Share(b.ID, fixtureNetwork(t, store).ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Invite(b.ID, share, now); err == nil {
		t.Fatal("accepted self invite")
	}
	pair, err := store.Invite(a.ID, share, now)
	if err != nil || pair.State != "invited" {
		t.Fatal(err)
	}
	if _, err = store.Invite(outsider.ID, share, now); err == nil {
		t.Fatal("reused share")
	}
	if _, err = store.Pair(outsider.ID, pair.ID); err == nil {
		t.Fatal("leaked unrelated pair")
	}
	if _, err = store.ActOnPair(a.ID, pair.ID, "approve", "", now); err == nil {
		t.Fatal("initiator approved itself")
	}
	if _, err = store.ActOnPair(b.ID, pair.ID, "approve", "", now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActOnPair(a.ID, pair.ID, "confirm", "wrong", now); err == nil {
		t.Fatal("accepted wrong fingerprint")
	}
	active, err := store.ActOnPair(a.ID, pair.ID, "confirm", share.Fingerprint, now)
	if err != nil || active.State != "active" || active.Revision != 3 {
		t.Fatal("approval state differs", active, err)
	}
	if _, err = store.ActOnPair(b.ID, pair.ID, "revoke", "", now); err != nil {
		t.Fatal(err)
	}
	second, err := OpenStore(database, key)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	revoked, err := second.Pair(a.ID, pair.ID)
	if err != nil || revoked.State != "revoked" || revoked.Revision != 4 {
		t.Fatal("revocation resurrected", revoked, err)
	}
}

func TestCertificateRenewalPreservesPairAndRecoveryRejectsRevocation(t *testing.T) {
	store, _, _, now := newStore(t)
	a, _, csr, _ := enroll(t, store, now)
	b, _, _, _ := enroll(t, store, now)
	pair := pairDevices(t, store, a, b, now)
	certificate, err := x509.ParseCertificate(a.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	request := Renewal{protocol.NewID(), csr}
	if _, err = store.Renew(certificate, request, now); err == nil {
		t.Fatal("renewed before window")
	}
	due := now.Add(24 * 24 * time.Hour)
	renewed, err := store.Renew(certificate, request, due)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := store.Renew(certificate, request, due)
	if err != nil || !bytes.Equal(renewed, replayed) {
		t.Fatal("renewal reply not idempotent", err)
	}
	newCertificate, err := x509.ParseCertificate(renewed)
	if err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*x509.Certificate{certificate, newCertificate} {
		identity, err := store.Authenticate(cert, due)
		if err != nil || identity.ID != a.ID {
			t.Fatal("same-key renewal changed identity", err)
		}
	}
	current, err := store.Pair(a.ID, pair.ID)
	if err != nil || current != pair {
		t.Fatal("renewal changed pair", err)
	}
	expired := due.Add(31 * 24 * time.Hour)
	token, err := fixtureToken(t, store, expired)
	if err != nil {
		t.Fatal(err)
	}
	recovery := CertificateRecovery{a.ID, protocol.NewID(), csr, token}
	if _, err = store.RecoverCertificate(recovery, expired); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RecoverCertificate(recovery, expired); err == nil {
		t.Fatal("reused recovery")
	}
	if err = store.RevokeDevice(a.ID, expired); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RecoverCertificate(recovery, expired.Add(31*24*time.Hour)); err == nil {
		t.Fatal("restored revoked device")
	}
}

func TestExplicitBackupRecoveryInvalidatesAllOldAuthorizations(t *testing.T) {
	store, _, _, now := newStore(t)
	a, _, _, _ := enroll(t, store, now)
	b, _, _, _ := enroll(t, store, now)
	pair := pairDevices(t, store, a, b, now)
	root := t.TempDir()
	backupPath := filepath.Join(root, "before-revocation.db")
	if _, err := store.db.Exec("VACUUM INTO ?", backupPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(backupPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActOnPair(a.ID, pair.ID, "revoke", "", now); err != nil {
		t.Fatal(err)
	}
	backupDB, err := openDB(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	backup := &Store{db: backupDB, key: store.key}
	defer backup.Close()
	if err = backup.validate(); err != nil {
		t.Fatal(err)
	}
	old, err := backup.Pair(a.ID, pair.ID)
	if err != nil || old.State != "active" {
		t.Fatal("backup must genuinely predate revocation", err)
	}
	newDB, newKey := filepath.Join(root, "recovered.db"), filepath.Join(root, "recovered.pem")
	if err = backup.Recover(newDB, newKey, now); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenStore(newDB, newKey)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.ServiceID == store.ServiceID {
		t.Fatal("recovery reused old signing identity")
	}
	certificate, err := x509.ParseCertificate(a.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recovered.Authenticate(certificate, now); err == nil {
		t.Fatal("old credential regained authority")
	}
	if _, err = recovered.Pair(a.ID, pair.ID); err == nil {
		t.Fatal("old pair restored")
	}
}
