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

// persistedSeenInterval throttles the last-seen write.
//
// Presence itself stays in memory and stays exact; this only controls how often
// the value is durable. Heartbeats arrive far more often than once a minute, so
// writing every one would turn presence into a continuous disk load for
// information that is only read when a human opens the device list. One minute
// of imprecision after a restart is not worth that.
const persistedSeenInterval = time.Minute

// Sessions keeps presence in memory: no SDP, ICE credential or attempt survives
// restart. Last-seen is the single exception, persisted so the device list can
// still say when a device was last reachable after the server restarts.
type Sessions struct {
	mu        sync.Mutex
	store     *Store
	attempts  map[string]*attempt
	presence  map[string]time.Time
	seenSaved map[string]time.Time
}

func NewSessions(store *Store) *Sessions {
	return &Sessions{store: store, attempts: make(map[string]*attempt), presence: make(map[string]time.Time), seenSaved: make(map[string]time.Time)}
}

// Heartbeat records presence and the reported build.
//
// Telemetry is whatever the device claims about itself; it is descriptive only
// and never used for authorization, so a device that reports nothing keeps its
// previously stored values rather than having them blanked.
func (sessions *Sessions) Heartbeat(id string, telemetry DeviceTelemetry, now time.Time) error {
	if _, err := sessions.store.Device(id); err != nil {
		return err
	}
	sessions.mu.Lock()
	sessions.presence[id] = now
	saved, seen := sessions.seenSaved[id]
	due := !seen || !saved.Add(persistedSeenInterval).After(now)
	if due {
		sessions.seenSaved[id] = now
	}
	sessions.mu.Unlock()
	if !due {
		return nil
	}
	// A failed telemetry write must not fail the heartbeat: presence is already
	// recorded, and losing a descriptive field is not worth dropping liveness.
	_ = sessions.store.RecordDeviceSeen(id, telemetry, now)
	return nil
}

func (sessions *Sessions) Offline(id string) {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	delete(sessions.presence, id)
	// Forget the throttle too, so the next heartbeat persists immediately
	// instead of being suppressed by a write from the previous session.
	delete(sessions.seenSaved, id)
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

// Begin authorizes a connection attempt by network co-membership.
//
// The identifier is the TARGET DEVICE ID: trust comes from both devices being
// bound to a common network (the server vouches for every bound device by
// signing its certificate), so no per-pair record or invite is required. The
// lease keeps carrying the identifier as PairID because the transport state
// machine uses it as the connection id.
func (sessions *Sessions) Begin(sender, targetDeviceID string, generation uint64, now time.Time) (Lease, error) {
	sessions.mu.Lock()
	defer sessions.mu.Unlock()
	if !protocol.ValidID(targetDeviceID) || targetDeviceID == sender {
		return Lease{}, errors.New("p2p.invalid_request")
	}
	if !sessions.store.sameNetwork(sender, targetDeviceID) {
		return Lease{}, errors.New("p2p.pair_unauthorized")
	}
	target := targetDeviceID
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
	// One live attempt per device pair, in either direction: an attempt keyed
	// by the target also blocks the reverse dial over the same link.
	if _, ok := sessions.attempts[target]; ok {
		return Lease{}, errors.New("p2p.connection_busy")
	}
	for _, current := range sessions.attempts {
		link := current.lease
		if (link.FromDeviceID == sender && link.ToDeviceID == target) || (link.FromDeviceID == target && link.ToDeviceID == sender) {
			return Lease{}, errors.New("p2p.connection_busy")
		}
	}
	device, err := sessions.store.Device(sender)
	if err != nil {
		return Lease{}, err
	}
	// The shared network scopes the lease; any common network authorizes.
	networkID, err := sessions.store.sharedNetworkID(sender, target)
	if err != nil {
		return Lease{}, err
	}
	lease := Lease{Version: protocol.Version, ServiceID: sessions.store.ServiceID, UserID: device.UserID, NetworkID: networkID, PairID: target, AttemptID: protocol.NewID(), FromDeviceID: sender, ToDeviceID: target, Generation: generation, Revision: 1, ExpiresAt: now.Add(time.Minute).Unix(), Permission: "dsh-session"}
	sessions.signLease(&lease)
	sessions.attempts[target] = &attempt{lease: lease, sequence: map[string]uint64{}, sdpHash: map[string]string{}, messageIDs: map[string]bool{}}
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
	// Authorization is network co-membership: an unbound device loses the
	// lease immediately, in either direction of the link.
	if !sessions.store.sameNetwork(sender, pairID) {
		return nil, errors.New("p2p.pair_revoked")
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
