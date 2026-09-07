package coordinator

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

type Lease = protocol.Lease

type attempt struct {
	lease        Lease
	sequence     map[string]uint64
	sdpHash      map[string]string
	messageIDs   map[string]bool
	messageCount int
}

// Sessions is ephemeral: no presence, SDP, ICE credential or attempt survives restart.
type Sessions struct {
	mu       sync.Mutex
	store    *Store
	attempts map[string]*attempt
	presence map[string]time.Time
}

func NewSessions(store *Store) *Sessions {
	return &Sessions{store: store, attempts: make(map[string]*attempt), presence: make(map[string]time.Time)}
}

func (sessions *Sessions) Heartbeat(id string, now time.Time) error {
	if _, err := sessions.store.Device(id); err != nil {
		return err
	}
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	sessions.presence[id] = now
	return nil
}

func (sessions *Sessions) Offline(id string) {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	delete(sessions.presence, id)
}

func (sessions *Sessions) Presence(id string, now time.Time) string {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	at, ok := sessions.presence[id]
	if !ok {
		return "offline"
	}
	if !at.Add(30 * time.Second).After(now) {
		return "stale"
	}
	return "online"
}

func (sessions *Sessions) Begin(sender, pairID string, generation uint64, now time.Time) (Lease, error) {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	pair, err := sessions.store.Pair(sender, pairID)
	if err != nil || pair.State != "active" {
		return Lease{}, errors.New("p2p.pair_unauthorized")
	}
	if err = sessions.store.authorizePair(pair); err != nil {
		return Lease{}, err
	}
	target := pair.Target
	if target == sender {
		target = pair.Initiator
	}
	if generation == 0 || generation > 1<<53-1 {
		return Lease{}, errors.New("p2p.invalid_generation")
	}
	for _, id := range []string{sender, target} {
		if _, err := sessions.store.Device(id); err != nil {
			return Lease{}, err
		}
		if !sessions.presence[id].Add(30 * time.Second).After(now) {
			return Lease{}, errors.New("p2p.peer_offline")
		}
	}
	for id, current := range sessions.attempts {
		if current.lease.ExpiresAt <= now.Unix() {
			delete(sessions.attempts, id)
		}
	}
	if _, ok := sessions.attempts[pairID]; ok {
		return Lease{}, errors.New("p2p.connection_busy")
	}
	device, err := sessions.store.Device(sender)
	if err != nil {
		return Lease{}, err
	}
	lease := Lease{Version: protocol.Version, ServiceID: sessions.store.ServiceID, UserID: device.UserID, NetworkID: pair.NetworkID, PairID: pair.ID, AttemptID: protocol.NewID(), FromDeviceID: sender, ToDeviceID: target, Generation: generation, Revision: pair.Revision, ExpiresAt: now.Add(time.Minute).Unix(), Permission: "dsh-session"}
	sessions.signLease(&lease)
	sessions.attempts[pairID] = &attempt{lease: lease, sequence: map[string]uint64{}, sdpHash: map[string]string{}, messageIDs: map[string]bool{}}
	return lease, nil
}

func (sessions *Sessions) Renew(sender, pairID, attemptID string, now time.Time) (Lease, error) {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	current, err := sessions.authorize(sender, pairID, attemptID, now)
	if err != nil {
		return Lease{}, err
	}
	current.lease.ExpiresAt = now.Add(time.Minute).Unix()
	sessions.signLease(&current.lease)
	return current.lease, nil
}

func (sessions *Sessions) End(sender, pairID, attemptID string) error {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	current, exists := sessions.attempts[pairID]
	if !exists || current.lease.AttemptID != attemptID || (current.lease.FromDeviceID != sender && current.lease.ToDeviceID != sender) {
		return errors.New("p2p.attempt_not_found")
	}
	delete(sessions.attempts, pairID)
	return nil
}

func (sessions *Sessions) Admit(sender string, signal protocol.Signal, now time.Time) error {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	current, err := sessions.authorize(sender, signal.PairID, signal.AttemptID, now)
	if err != nil {
		return err
	}
	target := current.lease.ToDeviceID
	if target == sender {
		target = current.lease.FromDeviceID
	}
	device, err := sessions.store.Device(sender)
	if err != nil {
		return err
	}
	scope := protocol.SignalScope{AttemptID: current.lease.AttemptID, FromDeviceID: sender, ToDeviceID: target, PairID: signal.PairID, Generation: current.lease.Generation, NextSequence: current.sequence[sender] + 1}
	if err = signal.Verify(device.PublicKey, scope, now); err != nil {
		return err
	}
	if current.messageIDs[signal.MessageID] || current.messageCount >= 512 {
		return errors.New("p2p.signal_limit")
	}
	if err = admitSDP(current, sender, signal); err != nil {
		return err
	}
	current.sequence[sender] = signal.Sequence
	current.messageIDs[signal.MessageID] = true
	current.messageCount++
	return nil
}

func admitSDP(current *attempt, sender string, signal protocol.Signal) error {
	body, err := base64.RawURLEncoding.DecodeString(signal.Payload)
	if err != nil {
		return errors.New("p2p.invalid_payload")
	}
	if signal.Type == "offer" || signal.Type == "answer" {
		if current.sdpHash[sender] != "" || (signal.Type == "offer") != (sender == current.lease.FromDeviceID) {
			return errors.New("p2p.signal_state_conflict")
		}
		if signal.Type == "answer" && current.sdpHash[current.lease.FromDeviceID] == "" {
			return errors.New("p2p.signal_state_conflict")
		}
		var payload protocol.SDP
		if err = protocol.Decode(body, &payload); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte(payload.SDP))
		current.sdpHash[sender] = hex.EncodeToString(digest[:])
		return nil
	}
	var payload protocol.Candidate
	if err = protocol.Decode(body, &payload); err != nil {
		return err
	}
	if current.sdpHash[sender] == "" || current.sdpHash[sender] != payload.SDPHash {
		return errors.New("p2p.sdp_binding_mismatch")
	}
	return nil
}

func (sessions *Sessions) authorize(sender, pairID, attemptID string, now time.Time) (*attempt, error) {
	current, ok := sessions.attempts[pairID]
	if !ok || current.lease.AttemptID != attemptID || current.lease.ExpiresAt <= now.Unix() {
		return nil, errors.New("p2p.lease_expired")
	}
	pair, err := sessions.store.Pair(sender, pairID)
	if err != nil || pair.State != "active" || pair.Revision != current.lease.Revision {
		return nil, errors.New("p2p.pair_revoked")
	}
	if err = sessions.store.authorizePair(pair); err != nil {
		return nil, err
	}
	for _, id := range []string{current.lease.FromDeviceID, current.lease.ToDeviceID} {
		if _, err := sessions.store.Device(id); err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (sessions *Sessions) signLease(lease *Lease) {
	lease.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(sessions.store.key, lease.SigningBytes()))
}
