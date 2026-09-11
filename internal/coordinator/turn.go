package coordinator

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pion/turn/v5"
)

// relayRealm names the authentication realm of the self-hosted relay.
const relayRealm = "dshker"

// TurnRelay is the resolved relay wiring: where the relay listens and which
// public address its allocations advertise. Allocation ports come from the
// OS ephemeral range on the relay socket.
type TurnRelay struct {
	SharedSecret   string
	ControlAddress string
	PublicIP       net.IP
}

// Enabled reports whether the configuration turns the TURN relay on. Without a
// shared secret there are no credentials to issue and the socket stays the
// plain STUN-only service.
func (turnRelay TurnRelay) Enabled() bool {
	return turnRelay.SharedSecret != ""
}

// TurnCredentials derives RFC 8656 time-windowed credentials (the TURN REST API
// shape: username "<unix-expiry>:<deviceID>", password base64(HMAC-SHA1(secret,
// username))), valid for 24 hours. A peer presents them to the relay on this
// server; the coordinator never persists them.
func TurnCredentials(sharedSecret, deviceID string) (username, password string, err error) {
	if len(sharedSecret) < 32 {
		return "", "", fmt.Errorf("p2p.relay_unconfigured")
	}
	return turn.GenerateLongTermTURNRESTCredentials(sharedSecret, deviceID, 24*time.Hour)
}

// ServeTURN runs the RFC 8656 relay on the UDP socket that previously answered
// bare STUN Bindings. It answers both Binding requests and authenticated
// Allocate/Refresh/CreatePermission/ChannelBind/Send/Data exchanges. The relay
// forwards only the packet stream between allocations; it never inspects
// payloads, so the peer-to-peer traffic stays end-to-end encrypted.
//
// The limiter from the STUN-only path is deliberately not applied here:
// authentication already gates every control exchange, and the relay cost is
// bounded by the allocation lifetime.
func ServeTURN(ctx context.Context, connection *net.UDPConn, relay TurnRelay) error {
	if !relay.Enabled() {
		return fmt.Errorf("p2p.relay_unconfigured")
	}
	generator := &turn.RelayAddressGeneratorStatic{
		RelayAddress: relay.PublicIP,
		Address:      relay.PublicIP.String(),
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm:       relayRealm,
		AuthHandler: turn.LongTermTURNRESTAuthHandler(relay.SharedSecret, nil),
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn:            connection,
			RelayAddressGenerator: generator,
		}},
	})
	if err != nil {
		return err
	}
	<-ctx.Done()
	return server.Close()
}
