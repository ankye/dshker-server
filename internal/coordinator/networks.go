package coordinator

import (
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ankye/dshker-server/internal/protocol"
)

type Network struct {
	ID         string `json:"networkId"`
	UserID     string `json:"userId"`
	Name       string `json:"name"`
	MaxDevices int    `json:"maxDevices"`
}

// DefaultNetworkLimit is the device capacity every network starts with; an
// owning user may raise it to any of the allowed limits below.
const DefaultNetworkLimit = 10

// AllowedNetworkLimits are the selectable per-network device capacities.
var AllowedNetworkLimits = map[int]bool{10: true, 20: true, 30: true}

func validNetworkLimit(limit int) bool { return AllowedNetworkLimits[limit] }

type queryer interface{ QueryRow(string, ...any) *sql.Row }

func networkOwned(db queryer, userID, id string) (Network, error) {
	var network Network
	err := db.QueryRow("SELECT n.id,n.user_id,n.name,n.max_devices FROM networks n JOIN users u ON u.id=n.user_id WHERE n.id=? AND n.user_id=? AND n.deleted=0 AND u.disabled=0", id, userID).Scan(&network.ID, &network.UserID, &network.Name, &network.MaxDevices)
	if err != nil {
		return Network{}, errors.New("p2p.network_unauthorized")
	}
	return network, nil
}

func validName(name string) bool {
	return utf8.ValidString(name) && len(name) > 0 && len(name) <= 256 && strings.TrimSpace(name) == name && !strings.ContainsAny(name, "\r\n\x00")
}

func (store *Store) CreateNetwork(userID, name string) (Network, error) {
	if !validName(name) {
		return Network{}, errors.New("p2p.invalid_name")
	}
	var count int
	if err := store.db.QueryRow("SELECT count(*) FROM networks WHERE user_id=? AND deleted=0", userID).Scan(&count); err != nil {
		return Network{}, err
	}
	if count >= 2 {
		return Network{}, errors.New("p2p.network_limit_reached")
	}
	network := Network{ID: protocol.NewID(), UserID: userID, Name: name, MaxDevices: DefaultNetworkLimit}
	result, err := store.db.Exec("INSERT INTO networks(id,user_id,name,max_devices) SELECT ?,id,?,? FROM users WHERE id=? AND disabled=0", network.ID, name, network.MaxDevices, userID)
	if err != nil {
		return Network{}, err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return Network{}, errors.New("p2p.user_unauthorized")
	}
	return network, nil
}

func (store *Store) Networks(userID string) ([]Network, error) {
	rows, err := store.db.Query("SELECT n.id,n.user_id,n.name,n.max_devices FROM networks n JOIN users u ON u.id=n.user_id WHERE n.user_id=? AND n.deleted=0 AND u.disabled=0 ORDER BY n.rowid", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Network{}
	for rows.Next() {
		var n Network
		if err = rows.Scan(&n.ID, &n.UserID, &n.Name, &n.MaxDevices); err != nil {
			return nil, err
		}
		items = append(items, n)
	}
	return items, rows.Err()
}

func (store *Store) RenameNetwork(userID, id, name string) (Network, error) {
	if !validName(name) {
		return Network{}, errors.New("p2p.invalid_name")
	}
	tx, err := store.db.Begin()
	if err != nil {
		return Network{}, err
	}
	defer tx.Rollback()
	network, err := networkOwned(tx, userID, id)
	if err != nil {
		return Network{}, err
	}
	if network.Name == name {
		return network, nil
	}
	if _, err = tx.Exec("UPDATE networks SET name=? WHERE id=?", name, id); err != nil {
		return Network{}, err
	}
	network.Name = name
	return network, tx.Commit()
}

// UpdateNetworkLimit raises or sets the device capacity of a network the user
// owns. Only the allowed limits (10/20/30) are accepted; lowering the limit
// never silently evicts already-bound devices.
func (store *Store) UpdateNetworkLimit(userID, id string, maxDevices int) (Network, error) {
	if !validNetworkLimit(maxDevices) {
		return Network{}, errors.New("p2p.invalid_network_limit")
	}
	tx, err := store.db.Begin()
	if err != nil {
		return Network{}, err
	}
	defer tx.Rollback()
	network, err := networkOwned(tx, userID, id)
	if err != nil {
		return Network{}, err
	}
	if network.MaxDevices == maxDevices {
		return network, nil
	}
	if _, err = tx.Exec("UPDATE networks SET max_devices=? WHERE id=?", maxDevices, id); err != nil {
		return Network{}, err
	}
	network.MaxDevices = maxDevices
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES('network-limit',?,?)", id+":"+strconv.Itoa(maxDevices), time.Now().Unix()); err != nil {
		return Network{}, err
	}
	return network, tx.Commit()
}

// activeBindingCount returns how many devices are actively bound to a network.
func activeBindingCount(tx *sql.Tx, networkID string) (int, error) {
	var count int
	err := tx.QueryRow("SELECT count(*) FROM bindings WHERE network_id=? AND active=1", networkID).Scan(&count)
	return count, err
}

// bindingFitsCapacity reports whether the network still accepts one more
// active device given its persisted max_devices limit.
func bindingFitsCapacity(tx *sql.Tx, networkID string) (bool, error) {
	var limit int
	if err := tx.QueryRow("SELECT max_devices FROM networks WHERE id=? AND deleted=0", networkID).Scan(&limit); err != nil {
		return false, err
	}
	count, err := activeBindingCount(tx, networkID)
	if err != nil {
		return false, err
	}
	return count < limit, nil
}

func (store *Store) DeleteNetwork(userID, id string, now time.Time) error {
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = networkOwned(tx, userID, id); err != nil {
		return err
	}
	for _, query := range []string{
		"UPDATE networks SET deleted=1 WHERE id=?",
		"UPDATE bindings SET active=0 WHERE network_id=?",
		"UPDATE tokens SET used=1 WHERE network_id=?",
		"UPDATE shares SET used=1 WHERE network_id=?",
		"UPDATE pairs SET state='revoked',revision=revision+1 WHERE network_id=? AND state IN ('invited','approved','active')",
	} {
		if _, err = tx.Exec(query, id); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES('network-deleted',?,?)", id, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func bindingOwner(db queryer, networkID, deviceID string) (string, error) {
	var userID string
	err := db.QueryRow("SELECT n.user_id FROM bindings b JOIN networks n ON n.id=b.network_id JOIN devices d ON d.id=b.device_id JOIN users u ON u.id=n.user_id WHERE b.network_id=? AND b.device_id=? AND b.active=1 AND n.deleted=0 AND d.revoked=0 AND u.disabled=0 AND d.user_id=n.user_id", networkID, deviceID).Scan(&userID)
	if err != nil {
		return "", errors.New("p2p.binding_unauthorized")
	}
	return userID, nil
}

func (store *Store) BindDevice(userID, networkID, deviceID string) error {
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = networkOwned(tx, userID, networkID); err != nil {
		return err
	}
	var owner string
	if err = tx.QueryRow("SELECT user_id FROM devices WHERE id=? AND revoked=0", deviceID).Scan(&owner); err != nil || owner != userID {
		return errors.New("p2p.device_unauthorized")
	}
	// Re-binding an already-active device is a no-op that must not consume
	// capacity; only a fresh active binding is counted.
	var already bool
	if err = tx.QueryRow("SELECT EXISTS(SELECT 1 FROM bindings WHERE network_id=? AND device_id=? AND active=1)", networkID, deviceID).Scan(&already); err != nil {
		return err
	}
	if !already {
		if fits, err := bindingFitsCapacity(tx, networkID); err != nil {
			return err
		} else if !fits {
			return errors.New("p2p.network_full")
		}
	}
	_, err = tx.Exec("INSERT INTO bindings(network_id,device_id,active) VALUES(?,?,1) ON CONFLICT(network_id,device_id) DO UPDATE SET active=1", networkID, deviceID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) UnbindDevice(userID, networkID, deviceID string, now time.Time) error {
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = networkOwned(tx, userID, networkID); err != nil {
		return err
	}
	if _, err = bindingOwner(tx, networkID, deviceID); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE bindings SET active=0 WHERE network_id=? AND device_id=?", networkID, deviceID); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE pairs SET state='revoked',revision=revision+1 WHERE network_id=? AND (initiator=? OR target=?) AND state IN ('invited','approved','active')", networkID, deviceID, deviceID); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE shares SET used=1 WHERE network_id=? AND device_id=?", networkID, deviceID); err != nil {
		return err
	}
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES('device-unbound',?,?)", networkID+":"+deviceID, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) NetworkDevices(userID, networkID string) ([]Device, error) {
	if _, err := networkOwned(store.db, userID, networkID); err != nil {
		return nil, err
	}
	return store.listDevices("SELECT d.id,d.user_id,d.public_key,d.name,d.certificate FROM devices d JOIN bindings b ON b.device_id=d.id JOIN networks n ON n.id=b.network_id JOIN users u ON u.id=d.user_id WHERE b.network_id=? AND d.user_id=? AND b.active=1 AND d.revoked=0 AND n.deleted=0 AND u.disabled=0 ORDER BY d.rowid", networkID, userID)
}

func (store *Store) UserDevices(userID string) ([]Device, error) {
	return store.listDevices("SELECT d.id,d.user_id,d.public_key,d.name,d.certificate FROM devices d JOIN users u ON u.id=d.user_id WHERE d.user_id=? AND d.revoked=0 AND u.disabled=0 ORDER BY d.rowid", userID)
}

func (store *Store) listDevices(query string, args ...any) ([]Device, error) {
	rows, err := store.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Device{}
	for rows.Next() {
		var d Device
		if err = rows.Scan(&d.ID, &d.UserID, &d.PublicKey, &d.Name, &d.Certificate); err != nil {
			return nil, err
		}
		items = append(items, d)
	}
	return items, rows.Err()
}

func (store *Store) DeletePair(userID, networkID, pairID string, now time.Time) error {
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = networkOwned(tx, userID, networkID); err != nil {
		return err
	}
	result, err := tx.Exec("UPDATE pairs SET state='revoked',revision=revision+1 WHERE id=? AND network_id=? AND state IN ('invited','approved','active')", pairID, networkID)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return errors.New("p2p.pair_unauthorized")
	}
	if _, err = tx.Exec("INSERT INTO audit(event,subject,at) VALUES('pair-deleted',?,?)", pairID, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}
