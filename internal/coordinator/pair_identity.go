package coordinator

import (
	"errors"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

// PairDeviceIdentity 仅投影核对和固定信任所需的公开字段，不包含设备证书。
type PairDeviceIdentity struct {
	DeviceID  string `json:"deviceId"`
	UserID    string `json:"userId"`
	PublicKey []byte `json:"publicKey"`
	Name      string `json:"name"`
	Presence  string `json:"presence"`
}

type PairIdentity struct {
	Pair      Pair               `json:"pair"`
	Initiator PairDeviceIdentity `json:"initiator"`
	Target    PairDeviceIdentity `json:"target"`
}

func (server *Server) pairIdentity(deviceID, pairID string, now time.Time) (PairIdentity, error) {
	if !protocol.ValidID(pairID) {
		return PairIdentity{}, errors.New("p2p.invalid_request")
	}
	pair, err := server.store.Pair(deviceID, pairID)
	if err != nil {
		return PairIdentity{}, err
	}
	if pair.State != "active" && pair.State != "invited" && pair.State != "approved" {
		return PairIdentity{}, errors.New("p2p.pair_unauthorized")
	}
	if pair.State != "active" && pair.ExpiresAt <= now.Unix() {
		return PairIdentity{}, errors.New("p2p.pairing_expired")
	}
	if err = server.store.authorizePair(pair); err != nil {
		return PairIdentity{}, err
	}
	first, err := server.store.Device(pair.Initiator)
	if err != nil {
		return PairIdentity{}, err
	}
	second, err := server.store.Device(pair.Target)
	if err != nil {
		return PairIdentity{}, err
	}
	// Presence belongs to an account, so the pair is projected for the account the
	// request is made from — the requesting device's own.
	viewer, err := server.store.Device(deviceID)
	if err != nil {
		return PairIdentity{}, err
	}
	account := viewer.UserID
	project := func(device Device) PairDeviceIdentity {
		return PairDeviceIdentity{device.ID, account, device.PublicKey, device.Name, server.sessions.Presence(device.ID, account, now)}
	}
	return PairIdentity{pair, project(first), project(second)}, nil
}
