package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"strconv"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

type EnrollmentQuery struct {
	RequestID string `json:"requestId"`
	PublicKey []byte `json:"publicKey"`
	IssuedAt  int64  `json:"issuedAt"`
	Signature string `json:"signature"`
}

func (query EnrollmentQuery) SigningBytes() []byte {
	return []byte("dshker.enrollment-query.v1\n" + query.RequestID + "\n" + base64.RawURLEncoding.EncodeToString(query.PublicKey) + "\n" + strconv.FormatInt(query.IssuedAt, 10))
}

func (store *Store) ReadEnrollment(query EnrollmentQuery, now time.Time) (Device, error) {
	signature, err := base64.RawURLEncoding.DecodeString(query.Signature)
	if err != nil || !protocol.ValidID(query.RequestID) || len(query.PublicKey) != ed25519.PublicKeySize || query.IssuedAt > now.Unix() || query.IssuedAt <= now.Add(-time.Minute).Unix() || !ed25519.Verify(query.PublicKey, query.SigningBytes(), signature) {
		return Device{}, errors.New("p2p.device_unauthorized")
	}
	var id string
	if err := store.db.QueryRow("SELECT id FROM devices WHERE public_key=? AND request_id=? AND revoked=0", query.PublicKey, query.RequestID).Scan(&id); err != nil {
		return Device{}, errors.New("p2p.enrollment_not_found")
	}
	return store.Device(id)
}

type Renewal struct {
	RequestID string `json:"requestId"`
	CSR       string `json:"csr"`
}

type CertificateRecovery struct {
	DeviceID  string `json:"deviceId"`
	RequestID string `json:"requestId"`
	CSR       string `json:"csr"`
	Token     string `json:"token"`
}

func (store *Store) Renew(certificate *x509.Certificate, request Renewal, now time.Time) ([]byte, error) {
	device, err := store.Authenticate(certificate, now)
	if err != nil {
		return nil, err
	}
	public, err := csrKey(request.CSR)
	if err != nil || !bytes.Equal(public, device.PublicKey) || !protocol.ValidID(request.RequestID) {
		return nil, errors.New("p2p.identity_mismatch")
	}
	var saved []byte
	err = store.db.QueryRow("SELECT certificate FROM renewals WHERE device_id=? AND request_id=?", device.ID, request.RequestID).Scan(&saved)
	if err == nil {
		return saved, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if certificate.NotAfter.After(now.Add(7 * 24 * time.Hour)) {
		return nil, errors.New("p2p.renewal_not_due")
	}
	return store.replaceCertificate(device, request.RequestID, "", now)
}

func (store *Store) RecoverCertificate(request CertificateRecovery, now time.Time) ([]byte, error) {
	device, err := store.Device(request.DeviceID)
	if err != nil {
		return nil, err
	}
	public, err := csrKey(request.CSR)
	if err != nil || !bytes.Equal(public, device.PublicKey) || !protocol.ValidID(request.RequestID) || len(request.Token) != 64 {
		return nil, errors.New("p2p.identity_mismatch")
	}
	certificate, err := x509.ParseCertificate(device.Certificate)
	if err != nil || now.Before(certificate.NotAfter) {
		return nil, errors.New("p2p.certificate_not_expired")
	}
	return store.replaceCertificate(device, request.RequestID, request.Token, now)
}

func (store *Store) replaceCertificate(device Device, requestID, token string, now time.Time) ([]byte, error) {
	certificate, err := store.issueCertificate(device.ID, device.PublicKey, now)
	if err != nil {
		return nil, err
	}
	tx, err := store.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var revoked int
	if err = tx.QueryRow("SELECT revoked FROM devices WHERE id=?", device.ID).Scan(&revoked); err != nil || revoked != 0 {
		return nil, errors.New("p2p.device_unauthorized")
	}
	var saved []byte
	err = tx.QueryRow("SELECT certificate FROM renewals WHERE device_id=? AND request_id=?", device.ID, requestID).Scan(&saved)
	if err == nil && token == "" {
		return saved, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if token != "" {
		userID, networkID, err := tokenScope(tx, token, now)
		if err != nil {
			return nil, err
		}
		if userID != device.UserID {
			return nil, errors.New("p2p.identity_mismatch")
		}
		if _, err = bindingOwner(tx, networkID, device.ID); err != nil {
			return nil, err
		}
		if err = consumeToken(tx, token, now); err != nil {
			return nil, err
		}
	}
	if _, err = tx.Exec("INSERT INTO renewals VALUES(?,?,?)", device.ID, requestID, certificate); err != nil {
		return nil, errors.New("p2p.request_conflict")
	}
	if _, err = tx.Exec("UPDATE devices SET certificate=? WHERE id=?", certificate, device.ID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return certificate, nil
}

// Recover creates a new network with no usable old authorizations. Never run it over live paths.
func (store *Store) Recover(databasePath, keyPath string, now time.Time) error {
	if err := Initialize(databasePath, keyPath, now); err != nil {
		return err
	}
	recovered, err := OpenStore(databasePath, keyPath)
	if err != nil {
		return err
	}
	defer recovered.Close()
	_, err = recovered.db.Exec("INSERT INTO audit(event,subject,at) VALUES ('recovered-without-authorizations',?,?)", store.ServiceID, now.Unix())
	return err
}

func (store *Store) RevokeDevice(id string, now time.Time) error {
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE devices SET revoked=1 WHERE id=? AND revoked=0", id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("p2p.device_unauthorized")
	}
	if _, err = tx.Exec("UPDATE pairs SET state='revoked', revision=revision+1 WHERE initiator=? OR target=?", id, id); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES ('device-revoked',?,?)", id, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
