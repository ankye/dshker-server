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

// AdoptNetwork pairs a device with every other device already bound to one of
// its networks, without an invite code or an approval step.
//
// The invite flow exists to answer "is this stranger's device really the one I
// mean?", which a human confirms by comparing a fingerprint. That question does
// not arise between two devices the same user bound to the same network: joining
// is itself the authorization, and the identity is carried by a certificate this
// coordinator issued. Requiring an invite between them made joining a network
// pointless, since membership granted nothing on its own.
//
// The trust boundary is unchanged. Every pair still requires an active binding
// in a shared network owned by the same user, with neither device revoked and
// the user enabled, which is exactly what the invite path verifies before it
// accepts a code. Only the human ceremony is dropped, not a check.
func (store *Store) AdoptNetwork(deviceID string, now time.Time) ([]Pair, error) {
	device, err := store.Device(deviceID)
	if err != nil {
		return nil, err
	}
	// Peers are restricted to networks this device is actually bound to, and to
	// devices owned by that network's owner, so adoption can never reach across
	// accounts.
	rows, err := store.db.Query(
		"SELECT DISTINCT b.network_id, other.device_id FROM bindings b JOIN networks n ON n.id=b.network_id JOIN users u ON u.id=n.user_id JOIN bindings other ON other.network_id=b.network_id AND other.device_id<>b.device_id AND other.active=1 JOIN devices d ON d.id=other.device_id WHERE b.device_id=? AND b.active=1 AND n.deleted=0 AND u.disabled=0 AND n.user_id=? AND d.user_id=n.user_id AND d.revoked=0 ORDER BY b.network_id, other.device_id",
		deviceID, device.UserID,
	)
	if err != nil {
		return nil, err
	}
	type peer struct{ networkID, deviceID string }
	peers := []peer{}
	for rows.Next() {
		var found peer
		if err = rows.Scan(&found.networkID, &found.deviceID); err != nil {
			rows.Close()
			return nil, err
		}
		peers = append(peers, found)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return nil, err
	}
	adopted := []Pair{}
	for _, found := range peers {
		pair, err := store.adopt(deviceID, found.deviceID, found.networkID, now)
		if err != nil {
			// An existing or in-flight pair is the desired end state, not a
			// failure, and one unusable peer must not hide the others.
			continue
		}
		adopted = append(adopted, pair)
	}
	return adopted, nil
}

// adopt creates one already-active pair, or reports why it cannot.
func (store *Store) adopt(initiator, target, networkID string, now time.Time) (Pair, error) {
	tx, err := store.db.Begin()
	if err != nil {
		return Pair{}, err
	}
	defer tx.Rollback()
	owner, err := bindingOwner(tx, networkID, initiator)
	if err != nil {
		return Pair{}, err
	}
	other, err := bindingOwner(tx, networkID, target)
	if err != nil || owner != other {
		return Pair{}, errors.New("p2p.binding_unauthorized")
	}
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM pairs WHERE network_id=? AND ((initiator=? AND target=?) OR (initiator=? AND target=?)) AND (state='active' OR (state IN ('invited','approved') AND expires>?))", networkID, initiator, target, target, initiator, now.Unix()).Scan(&count); err != nil {
		return Pair{}, err
	}
	if count != 0 {
		return Pair{}, errors.New("p2p.pairing_busy")
	}
	// Active immediately: there is no second party left to confirm anything, and
	// an expiry would strand a pair that membership already justifies. The
	// timestamp is kept for schema compatibility with invited pairs.
	pair := Pair{protocol.NewID(), networkID, initiator, target, "active", now.Add(5 * time.Minute).Unix(), 1}
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

// sameNetwork reports whether both devices are actively bound to one common
// network, which is the entire authorization for direct connections.
func (store *Store) sameNetwork(a, b string) bool {
	var count int
	row := store.db.QueryRow("SELECT count(*) FROM bindings x JOIN bindings y ON x.network_id=y.network_id WHERE x.device_id=? AND y.device_id=? AND x.active=1 AND y.active=1", a, b)
	return row.Scan(&count) == nil && count > 0
}

// sharedNetworkID returns one network both devices are actively bound to.
func (store *Store) sharedNetworkID(a, b string) (string, error) {
	var networkID string
	row := store.db.QueryRow("SELECT x.network_id FROM bindings x JOIN bindings y ON x.network_id=y.network_id WHERE x.device_id=? AND y.device_id=? AND x.active=1 AND y.active=1 LIMIT 1", a, b)
	if err := row.Scan(&networkID); err != nil {
		return "", errors.New("p2p.pair_unauthorized")
	}
	return networkID, nil
}
