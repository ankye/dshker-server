package coordinator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

type Enrollment struct {
	RequestID string `json:"requestId"`
	Token     string `json:"token"`
	CSR       string `json:"csr"`
	Name      string `json:"name"`
}

// NetworkJoin is a login-free enrollment keyed by the target network id. The
// joining computer already owns a local device identity; presenting a valid
// networkId plus proof of private-key ownership over the CSR is enough to be
// admitted to that network's device directory. Login is only required later,
// when meshing (pairing/connecting) devices.
type NetworkJoin struct {
	RequestID string `json:"requestId"`
	NetworkID string `json:"networkId"`
	CSR       string `json:"csr"`
	Name      string `json:"name"`
}

type Device struct {
	ID          string `json:"deviceId"`
	UserID      string `json:"userId"`
	PublicKey   []byte `json:"publicKey"`
	Name        string `json:"name"`
	Certificate []byte `json:"certificate"`
}

// DeviceTelemetry is what a device reports about itself on each heartbeat.
//
// Every field is self-declared and descriptive: it is shown in the device list
// so an operator can tell builds apart, and is never used for authorization.
// Empty fields mean "unchanged", so a device that reports nothing keeps what it
// last reported instead of appearing to lose its identity.
type DeviceTelemetry struct {
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

// Bounds are generous but finite: these strings are displayed, so they must not
// be able to carry a payload or wreck a table layout.
func (telemetry DeviceTelemetry) valid() bool {
	for _, value := range []string{telemetry.Version, telemetry.Platform, telemetry.Architecture} {
		if len(value) > 64 || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
	}
	return true
}

// DeviceStatus adds the reported build and last-seen time to a device row.
type DeviceStatus struct {
	LastSeen     int64  `json:"lastSeen"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

// RecordDeviceSeen stores liveness and any newly reported telemetry.
//
// Invalid telemetry is dropped rather than rejected: the heartbeat's real job is
// liveness, and refusing it over a cosmetic field would take a device offline.
func (store *Store) RecordDeviceSeen(id string, telemetry DeviceTelemetry, now time.Time) error {
	if !protocol.ValidID(id) {
		return errors.New("p2p.invalid_request")
	}
	if !telemetry.valid() {
		telemetry = DeviceTelemetry{}
	}
	_, err := store.db.Exec(
		"UPDATE devices SET last_seen=?, version=CASE WHEN ?='' THEN version ELSE ? END, platform=CASE WHEN ?='' THEN platform ELSE ? END, architecture=CASE WHEN ?='' THEN architecture ELSE ? END WHERE id=? AND revoked=0",
		now.Unix(),
		telemetry.Version, telemetry.Version,
		telemetry.Platform, telemetry.Platform,
		telemetry.Architecture, telemetry.Architecture,
		id,
	)
	return err
}

func digest(value string) string {
	encoded := sha256.Sum256([]byte(value))
	return hex.EncodeToString(encoded[:])
}

func (store *Store) IssueEnrollmentToken(userID, networkID string, now time.Time) (string, error) {
	// A bearer secret, not an identifier: its length is its own (32 bytes hex),
	// so shortening the protocol's ids cannot shrink it. Building it out of ids
	// made the token 24 characters the moment ids became twelve, and every
	// enrollment then failed as malformed.
	token, err := protocol.NewSecret()
	if err != nil {
		return "", err
	}
	tx, err := store.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err = networkOwned(tx, userID, networkID); err != nil {
		return "", err
	}
	if _, err = tx.Exec("INSERT INTO tokens(hash,user_id,network_id,expires) VALUES (?,?,?,?)", digest(token), userID, networkID, now.Add(5*time.Minute).Unix()); err != nil {
		return "", err
	}
	return token, tx.Commit()
}

func (store *Store) Enroll(request Enrollment, now time.Time) (Device, error) {
	var device Device
	if !protocol.ValidID(request.RequestID) || len(request.Token) != 64 || request.Name != strings.TrimSpace(request.Name) || len(request.Name) < 1 || len(request.Name) > 256 || strings.ContainsAny(request.Name, "\r\n\x00") {
		return device, errors.New("p2p.invalid_enrollment")
	}
	public, err := csrKey(request.CSR)
	if err != nil {
		return device, err
	}
	// The device id is derived from the machine's key, like a hardware address, so
	// this machine is the same device every time it enrolls — under this account or
	// any other. Minting a fresh id here made every later enrollment a different
	// device and left every pair, pin and catalog row pointing at an identity that
	// no longer existed.
	device = Device{ID: protocol.KeyID(public), PublicKey: public, Name: request.Name}
	device.Certificate, err = store.issueCertificate(device.ID, public, now)
	if err != nil {
		return Device{}, err
	}
	tx, err := store.db.Begin()
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()
	userID, networkID, err := tokenScope(tx, request.Token, now)
	if err != nil {
		return Device{}, err
	}
	device.UserID = userID
	if fits, err := bindingFitsCapacity(tx, networkID); err != nil {
		return Device{}, err
	} else if !fits {
		return Device{}, errors.New("p2p.network_full")
	}
	if err = consumeToken(tx, request.Token, now); err != nil {
		return Device{}, err
	}
	// A machine that is already enrolled keeps its row and its certificate; this
	// enrollment only adds the account it is now reporting to, plus the network
	// binding that comes with that account's token.
	var known string
	switch err = tx.QueryRow("SELECT id FROM devices WHERE public_key=?", []byte(public)).Scan(&known); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.Exec("INSERT INTO devices(id,user_id,public_key,name,certificate,request_id) VALUES (?,?,?,?,?,?)", device.ID, userID, []byte(public), device.Name, device.Certificate, request.RequestID); err != nil {
			return Device{}, errors.New("p2p.device_already_enrolled")
		}
	case err != nil:
		return Device{}, err
	default:
		device.ID = known
		if _, err = tx.Exec("UPDATE devices SET name=?, request_id=? WHERE id=?", device.Name, request.RequestID, device.ID); err != nil {
			return Device{}, err
		}
		if err = tx.QueryRow("SELECT certificate FROM devices WHERE id=?", device.ID).Scan(&device.Certificate); err != nil {
			return Device{}, err
		}
	}
	if _, err = tx.Exec("INSERT INTO device_users(device_id,user_id) VALUES(?,?) ON CONFLICT(device_id,user_id) DO NOTHING", device.ID, userID); err != nil {
		return Device{}, err
	}
	if _, err = tx.Exec("INSERT INTO bindings(network_id,device_id,active) VALUES(?,?,1) ON CONFLICT(network_id,device_id) DO UPDATE SET active=1", networkID, device.ID); err != nil {
		return Device{}, err
	}
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES ('enrolled',?,?)", device.ID, now.Unix()); err != nil {
		return Device{}, err
	}
	if err = tx.Commit(); err != nil {
		return Device{}, err
	}
	return device, nil
}

// JoinNetwork admits a device into a network by its network id, without a
// user login or an owner-issued token. The device is owned by the network's
// owner user and actively bound to that network, so network co-membership is
// what later authorizes meshing. A network at its device capacity rejects the
// join with p2p.network_full.
func (store *Store) JoinNetwork(request NetworkJoin, now time.Time) (Device, error) {
	var device Device
	if !protocol.ValidID(request.RequestID) || !protocol.ValidID(request.NetworkID) || request.Name != strings.TrimSpace(request.Name) || len(request.Name) < 1 || len(request.Name) > 256 || strings.ContainsAny(request.Name, "\r\n\x00") {
		return device, errors.New("p2p.invalid_enrollment")
	}
	public, err := csrKey(request.CSR)
	if err != nil {
		return device, err
	}
	device = Device{ID: protocol.KeyID(public), PublicKey: public, Name: request.Name}
	device.Certificate, err = store.issueCertificate(device.ID, public, now)
	if err != nil {
		return Device{}, err
	}
	tx, err := store.db.Begin()
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()
	// The network must exist and be live; its owner is the account the joining
	// device reports to.
	var ownerUserID string
	if err = tx.QueryRow("SELECT user_id FROM networks WHERE id=? AND deleted=0", request.NetworkID).Scan(&ownerUserID); err != nil {
		return Device{}, errors.New("p2p.network_unauthorized")
	}
	var ownerDisabled int
	if err = tx.QueryRow("SELECT disabled FROM users WHERE id=?", ownerUserID).Scan(&ownerDisabled); err != nil || ownerDisabled != 0 {
		return Device{}, errors.New("p2p.network_unauthorized")
	}
	if fits, err := bindingFitsCapacity(tx, request.NetworkID); err != nil {
		return Device{}, err
	} else if !fits {
		return Device{}, errors.New("p2p.network_full")
	}
	device.UserID = ownerUserID
	// Same rule as Enroll: the id comes from the key, so a machine that is already
	// known keeps its device and its certificate and only gains this account.
	var known string
	switch err = tx.QueryRow("SELECT id FROM devices WHERE public_key=?", []byte(public)).Scan(&known); {
	case errors.Is(err, sql.ErrNoRows):
		if _, err = tx.Exec("INSERT INTO devices(id,user_id,public_key,name,certificate,request_id) VALUES (?,?,?,?,?,?)", device.ID, ownerUserID, []byte(public), device.Name, device.Certificate, request.RequestID); err != nil {
			return Device{}, errors.New("p2p.device_already_enrolled")
		}
	case err != nil:
		return Device{}, err
	default:
		device.ID = known
		if _, err = tx.Exec("UPDATE devices SET name=?, request_id=? WHERE id=?", device.Name, request.RequestID, device.ID); err != nil {
			return Device{}, err
		}
		if err = tx.QueryRow("SELECT certificate FROM devices WHERE id=?", device.ID).Scan(&device.Certificate); err != nil {
			return Device{}, err
		}
	}
	if _, err = tx.Exec("INSERT INTO device_users(device_id,user_id) VALUES(?,?) ON CONFLICT(device_id,user_id) DO NOTHING", device.ID, ownerUserID); err != nil {
		return Device{}, err
	}
	if _, err = tx.Exec("INSERT INTO bindings(network_id,device_id,active) VALUES(?,?,1) ON CONFLICT(network_id,device_id) DO UPDATE SET active=1", request.NetworkID, device.ID); err != nil {
		return Device{}, err
	}
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES ('network-join',?,?)", device.ID, now.Unix()); err != nil {
		return Device{}, err
	}
	if err = tx.Commit(); err != nil {
		return Device{}, err
	}
	return device, nil
}

func consumeToken(tx *sql.Tx, token string, now time.Time) error {
	if _, _, err := tokenScope(tx, token, now); err != nil {
		return err
	}
	result, err := tx.Exec("UPDATE tokens SET used=1 WHERE hash=? AND used=0 AND expires>?", digest(token), now.Unix())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("p2p.invalid_enrollment_token")
	}
	return nil
}

func tokenScope(tx *sql.Tx, token string, now time.Time) (string, string, error) {
	var userID, networkID string
	err := tx.QueryRow("SELECT t.user_id,t.network_id FROM tokens t JOIN users u ON u.id=t.user_id JOIN networks n ON n.id=t.network_id WHERE t.hash=? AND t.used=0 AND t.expires>? AND u.disabled=0 AND n.deleted=0 AND n.user_id=t.user_id", digest(token), now.Unix()).Scan(&userID, &networkID)
	if err != nil {
		return "", "", errors.New("p2p.invalid_enrollment_token")
	}
	return userID, networkID, nil
}

func csrKey(encoded string) (ed25519.PublicKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return nil, errors.New("p2p.invalid_csr")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, errors.New("p2p.invalid_csr")
	}
	public, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("p2p.invalid_device_key")
	}
	return public, nil
}

func (store *Store) issueCertificate(id string, public ed25519.PublicKey, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: id}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	return x509.CreateCertificate(rand.Reader, certificate, store.CA, public, store.key)
}

func (store *Store) Device(id string) (Device, error) {
	var device Device
	err := store.db.QueryRow("SELECT d.id,d.user_id,d.public_key,d.name,d.certificate FROM devices d JOIN users u ON u.id=d.user_id WHERE d.id=? AND d.revoked=0 AND u.disabled=0", id).Scan(&device.ID, &device.UserID, &device.PublicKey, &device.Name, &device.Certificate)
	if err != nil {
		return Device{}, errors.New("p2p.device_unauthorized")
	}
	return device, nil
}

func (store *Store) Authenticate(certificate *x509.Certificate, now time.Time) (Device, error) {
	if certificate == nil {
		return Device{}, errors.New("p2p.device_unauthorized")
	}
	roots := x509.NewCertPool()
	roots.AddCert(store.CA)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return Device{}, errors.New("p2p.device_unauthorized")
	}
	device, err := store.Device(certificate.Subject.CommonName)
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if err != nil || !ok || !public.Equal(ed25519.PublicKey(device.PublicKey)) {
		return Device{}, errors.New("p2p.identity_mismatch")
	}
	return device, nil
}
