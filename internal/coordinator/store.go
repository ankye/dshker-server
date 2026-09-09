package coordinator

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// SchemaVersion is the only layout this build accepts. It is a single constant
// because the store refuses any other value outright: there is no migration
// path, so a database written by a different version must be rebuilt.
const SchemaVersion = 5

const schema = `
CREATE TABLE metadata (version INTEGER NOT NULL, service_id TEXT NOT NULL, ca BLOB NOT NULL);
CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL, disabled INTEGER NOT NULL DEFAULT 0);
CREATE TABLE user_sessions (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
CREATE TABLE networks (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, max_devices INTEGER NOT NULL DEFAULT 10);
CREATE TABLE tokens (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), network_id TEXT NOT NULL REFERENCES networks(id), expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), public_key BLOB NOT NULL UNIQUE, name TEXT NOT NULL, certificate BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, request_id TEXT NOT NULL UNIQUE, last_seen INTEGER NOT NULL DEFAULT 0, version TEXT NOT NULL DEFAULT '', platform TEXT NOT NULL DEFAULT '', architecture TEXT NOT NULL DEFAULT '');
CREATE TABLE bindings (network_id TEXT NOT NULL REFERENCES networks(id), device_id TEXT NOT NULL REFERENCES devices(id), active INTEGER NOT NULL, PRIMARY KEY(network_id,device_id));
CREATE TABLE shares (nonce TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id), network_id TEXT NOT NULL REFERENCES networks(id), expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE pairs (id TEXT PRIMARY KEY, network_id TEXT NOT NULL REFERENCES networks(id), initiator TEXT NOT NULL REFERENCES devices(id), target TEXT NOT NULL REFERENCES devices(id), state TEXT NOT NULL, expires INTEGER NOT NULL, revision INTEGER NOT NULL);
CREATE TABLE renewals (device_id TEXT NOT NULL REFERENCES devices(id), request_id TEXT NOT NULL, certificate BLOB NOT NULL, PRIMARY KEY(device_id, request_id));
CREATE TABLE audit (id INTEGER PRIMARY KEY, event TEXT NOT NULL, subject TEXT NOT NULL, at INTEGER NOT NULL);
`

type Store struct {
	db              *sql.DB
	key             ed25519.PrivateKey
	CA              *x509.Certificate
	ServiceID       string
	logins          chan struct{}
	unknownPassword []byte
}

// Initialize never overwrites state. Both paths and their parent directories must be supplied.
func Initialize(databasePath, keyPath string, now time.Time) error {
	for _, path := range []string{databasePath, keyPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("p2p.state_already_exists")
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	if err = exclusiveFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	if err = exclusiveFile(databasePath, nil); err != nil {
		return err
	}
	db, err := openDB(databasePath)
	if err != nil {
		return err
	}
	defer db.Close()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: protocol.KeyID(public)}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(schema); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO metadata VALUES (?, ?, ?)", SchemaVersion, protocol.KeyID(public), der); err != nil {
		return err
	}
	return tx.Commit()
}

func OpenStore(databasePath, keyPath string) (*Store, error) {
	for _, path := range []string{databasePath, keyPath} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("p2p.state_unavailable_or_insecure")
		}
	}
	encoded, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return nil, errors.New("p2p.invalid_identity")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("p2p.invalid_identity")
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("p2p.invalid_identity")
	}
	db, err := openDB(databasePath)
	if err != nil {
		return nil, err
	}
	store := &Store{db: db, key: key, logins: make(chan struct{}, 4)}
	if err = store.validate(); err != nil {
		db.Close()
		return nil, err
	}
	store.unknownPassword, err = bcrypt.GenerateFromPassword([]byte(protocol.NewID()), 12)
	if err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) validate() error {
	var integrity string
	if err := store.db.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("p2p.invalid_database")
	}
	var version, count int
	var ca []byte
	if err := store.db.QueryRow("SELECT count(*) FROM metadata").Scan(&count); err != nil || count != 1 {
		return errors.New("p2p.invalid_database")
	}
	if err := store.db.QueryRow("SELECT version, service_id, ca FROM metadata").Scan(&version, &store.ServiceID, &ca); err != nil || version != SchemaVersion {
		return errors.New("p2p.unsupported_schema")
	}
	certificate, err := x509.ParseCertificate(ca)
	if err != nil {
		return errors.New("p2p.invalid_identity")
	}
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, store.key.Public().(ed25519.PublicKey)) || store.ServiceID != protocol.KeyID(public) || certificate.CheckSignatureFrom(certificate) != nil {
		return errors.New("p2p.identity_mismatch")
	}
	store.CA = certificate
	return nil
}

func (store *Store) Close() error { return store.db.Close() }

func openDB(path string) (*sql.DB, error) {
	address := url.URL{Scheme: "file", Path: path}
	query := url.Values{"mode": {"rw"}, "_pragma": {"foreign_keys(1)", "busy_timeout(5000)"}}
	address.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func exclusiveFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}
