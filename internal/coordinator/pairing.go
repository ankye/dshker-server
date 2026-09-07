package coordinator

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

type Share struct {
	Version     int    `json:"version"`
	ServiceID   string `json:"serviceId"`
	NetworkID   string `json:"networkId"`
	DeviceID    string `json:"deviceId"`
	Fingerprint string `json:"fingerprint"`
	Nonce       string `json:"nonce"`
	ExpiresAt   int64  `json:"expiresAt"`
	Signature   string `json:"signature"`
}

func (share Share) SigningBytes() []byte {
	data, _ := json.Marshal([]any{"dshker.pair-share.v1", share.Version, share.ServiceID, share.NetworkID, share.DeviceID, share.Fingerprint, share.Nonce, share.ExpiresAt})
	return data
}

func (store *Store) Share(id, networkID string, now time.Time) (Share, error) {
	device, err := store.Device(id)
	if err != nil {
		return Share{}, err
	}
	share := Share{protocol.Version, store.ServiceID, networkID, id, protocol.KeyID(device.PublicKey), protocol.NewID(), now.Add(5 * time.Minute).Unix(), ""}
	share.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(store.key, share.SigningBytes()))
	tx, err := store.db.Begin()
	if err != nil {
		return Share{}, err
	}
	defer tx.Rollback()
	if _, err = bindingOwner(tx, networkID, id); err != nil {
		return Share{}, err
	}
	if _, err = tx.Exec("INSERT INTO shares(nonce,device_id,network_id,expires) VALUES(?,?,?,?)", share.Nonce, id, networkID, share.ExpiresAt); err != nil {
		return Share{}, err
	}
	return share, tx.Commit()
}

type Pair struct {
	ID        string `json:"pairId"`
	NetworkID string `json:"networkId"`
	Initiator string `json:"initiator"`
	Target    string `json:"target"`
	State     string `json:"state"`
	ExpiresAt int64  `json:"expiresAt"`
	Revision  uint64 `json:"revision"`
}

func (store *Store) Invite(sender string, share Share, now time.Time) (Pair, error) {
	if _, err := store.Device(sender); err != nil {
		return Pair{}, err
	}
	target, err := store.Device(share.DeviceID)
	if err != nil {
		return Pair{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(share.Signature)
	if err != nil || share.Version != protocol.Version || share.ServiceID != store.ServiceID || share.DeviceID == sender || share.Fingerprint != protocol.KeyID(target.PublicKey) || share.ExpiresAt <= now.Unix() || share.ExpiresAt > now.Add(5*time.Minute).Unix() || !ed25519.Verify(store.key.Public().(ed25519.PublicKey), share.SigningBytes(), signature) {
		return Pair{}, errors.New("p2p.invalid_pairing_code")
	}
	tx, err := store.db.Begin()
	if err != nil {
		return Pair{}, err
	}
	defer tx.Rollback()
	owner, err := bindingOwner(tx, share.NetworkID, sender)
	if err != nil {
		return Pair{}, err
	}
	other, err := bindingOwner(tx, share.NetworkID, target.ID)
	if err != nil || owner != other {
		return Pair{}, errors.New("p2p.binding_unauthorized")
	}
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM pairs WHERE network_id=? AND ((initiator=? AND target=?) OR (initiator=? AND target=?)) AND (state='active' OR (state IN ('invited','approved') AND expires>?))", share.NetworkID, sender, target.ID, target.ID, sender, now.Unix()).Scan(&count); err != nil {
		return Pair{}, err
	}
	if count != 0 {
		return Pair{}, errors.New("p2p.pairing_busy")
	}
	result, err := tx.Exec("UPDATE shares SET used=1 WHERE nonce=? AND device_id=? AND network_id=? AND expires=? AND expires>? AND used=0", share.Nonce, target.ID, share.NetworkID, share.ExpiresAt, now.Unix())
	if err != nil {
		return Pair{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return Pair{}, errors.New("p2p.invalid_pairing_code")
	}
	pair := Pair{protocol.NewID(), share.NetworkID, sender, target.ID, "invited", now.Add(5 * time.Minute).Unix(), 1}
	if _, err = tx.Exec("INSERT INTO pairs VALUES(?,?,?,?,?,?,?)", pair.ID, pair.NetworkID, pair.Initiator, pair.Target, pair.State, pair.ExpiresAt, pair.Revision); err != nil {
		return Pair{}, err
	}
	if err = tx.Commit(); err != nil {
		return Pair{}, err
	}
	return pair, nil
}

func (store *Store) Pairs(deviceID string) ([]Pair, error) {
	if _, err := store.Device(deviceID); err != nil {
		return nil, err
	}
	rows, err := store.db.Query("SELECT id,network_id,initiator,target,state,expires,revision FROM pairs WHERE initiator=? OR target=? ORDER BY rowid", deviceID, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pairs := []Pair{}
	for rows.Next() {
		var pair Pair
		if err := rows.Scan(&pair.ID, &pair.NetworkID, &pair.Initiator, &pair.Target, &pair.State, &pair.ExpiresAt, &pair.Revision); err != nil {
			return nil, err
		}
		pairs = append(pairs, pair)
	}
	return pairs, rows.Err()
}

func (store *Store) Pair(deviceID, pairID string) (Pair, error) {
	pairs, err := store.Pairs(deviceID)
	if err != nil {
		return Pair{}, err
	}
	for _, pair := range pairs {
		if pair.ID == pairID {
			return pair, nil
		}
	}
	return Pair{}, errors.New("p2p.pair_unauthorized")
}

func (store *Store) ActOnPair(deviceID, pairID, action, fingerprint string, now time.Time) (Pair, error) {
	pair, err := store.Pair(deviceID, pairID)
	if err != nil {
		return Pair{}, err
	}
	if err = store.authorizePair(pair); err != nil {
		return Pair{}, err
	}
	next := ""
	switch action {
	case "approve", "reject":
		if pair.Target != deviceID || pair.State != "invited" {
			return Pair{}, errors.New("p2p.pair_state_conflict")
		}
		next = "approved"
		if action == "reject" {
			next = "rejected"
		}
	case "confirm":
		target, err := store.Device(pair.Target)
		if err != nil || pair.Initiator != deviceID || pair.State != "approved" || fingerprint != protocol.KeyID(target.PublicKey) {
			return Pair{}, errors.New("p2p.identity_mismatch")
		}
		next = "active"
	case "revoke":
		if pair.State != "active" {
			return Pair{}, errors.New("p2p.pair_state_conflict")
		}
		next = "revoked"
	default:
		return Pair{}, errors.New("p2p.invalid_pair_action")
	}
	if action != "revoke" && pair.ExpiresAt <= now.Unix() {
		return Pair{}, errors.New("p2p.pairing_expired")
	}
	result, err := store.db.Exec("UPDATE pairs SET state=?,revision=revision+1 WHERE id=? AND state=? AND revision=? AND NOT EXISTS(SELECT 1 FROM devices WHERE id IN (?,?) AND revoked=1)", next, pair.ID, pair.State, pair.Revision, pair.Initiator, pair.Target)
	if err != nil {
		return Pair{}, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return Pair{}, errors.New("p2p.pair_state_conflict")
	}
	return store.Pair(deviceID, pairID)
}

func (store *Store) authorizePair(pair Pair) error {
	owner, err := bindingOwner(store.db, pair.NetworkID, pair.Initiator)
	if err != nil {
		return err
	}
	other, err := bindingOwner(store.db, pair.NetworkID, pair.Target)
	if err != nil || owner != other {
		return errors.New("p2p.binding_unauthorized")
	}
	return nil
}
