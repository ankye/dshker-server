package coordinator

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

// relayRealm names the authentication realm of the self-hosted relay.
const relayRealm = "dshker"

// TurnRelay is the resolved relay wiring: where the relay listens and which
// public address its allocations advertise. Allocation ports come from the
// OS ephemeral range unless MinPort/MaxPort pin them to a fixed range.
type TurnRelay struct {
	SharedSecret   string
	ControlAddress string
	PublicIP       net.IP
	MinPort        int
	MaxPort        int
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
	// The public IP is only the advertised relay address. The generator must
	// actually bind on an interface this host owns: behind NAT the public IP
	// (relayPublicIP) exists only on the cloud gateway, never on a local NIC,
	// so binding to it fails with an allocation error 508. Binding 0.0.0.0
	// covers every local interface and the relayed candidate still advertises
	// RelayAddress (the public IP) in the allocation response.
	var generator turn.RelayAddressGenerator
	if relay.MinPort > 0 && relay.MaxPort >= relay.MinPort {
		generator = newPortRangeAllocator(relay.PublicIP, relay.MinPort, relay.MaxPort)
	} else {
		generator = &turn.RelayAddressGeneratorStatic{
			RelayAddress: relay.PublicIP,
			Address:      "0.0.0.0",
		}
	}
	var factory logging.LoggerFactory
	if os.Getenv("DSHKER_TURN_DEBUG") != "" {
		factory = &logging.DefaultLoggerFactory{Writer: os.Stderr, DefaultLogLevel: logging.LogLevelDebug}
	}
	server, err := turn.NewServer(turn.ServerConfig{
		Realm:         relayRealm,
		AuthHandler:   turn.LongTermTURNRESTAuthHandler(relay.SharedSecret, nil),
		LoggerFactory: factory,
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

// portRangeAllocator binds each relayed allocation to a random free UDP port
// inside a fixed range. pion/turn v5 dropped the old RelayPortMin/Max knobs and
// allocates OS ephemeral ports, which forces a cloud firewall to admit the
// whole ephemeral range; a bounded range keeps the admission rule narrow. The
// advertised address is always the public relay IP, never the bind address.
type portRangeAllocator struct {
	RelayAddress net.IP
	MinPort      int
	MaxPort      int
}

func newPortRangeAllocator(publicIP net.IP, minPort, maxPort int) *portRangeAllocator {
	return &portRangeAllocator{RelayAddress: publicIP, MinPort: minPort, MaxPort: maxPort}
}

func (g *portRangeAllocator) Validate() error {
	if g.RelayAddress == nil {
		return fmt.Errorf("p2p.invalid_relay_public_ip")
	}
	if g.MinPort < 1 || g.MaxPort > 65535 || g.MinPort > g.MaxPort {
		return fmt.Errorf("p2p.invalid_relay_port_range")
	}
	return nil
}

// bindOne binds a UDP relay socket on 0.0.0.0:port and, on success, swaps the
// local IP for the public relay address in the response addr.
func (g *portRangeAllocator) bindOne(network string, port int) (net.PacketConn, net.Addr, error) {
	conn, err := net.ListenPacket(network, net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		conn.Close()
		return nil, nil, fmt.Errorf("p2p.invalid_relay_address")
	}
	addr.IP = g.RelayAddress
	return conn, addr, nil
}

func (g *portRangeAllocator) AllocatePacketConn(conf turn.AllocateListenerConfig) (net.PacketConn, net.Addr, error) {
	if requestedPort := conf.RequestedPort; requestedPort >= g.MinPort && requestedPort <= g.MaxPort {
		if conn, addr, err := g.bindOne(conf.Network, requestedPort); err == nil {
			return conn, addr, nil
		}
	}
	// Walk the whole range at least once; using a clock-derived probe here
	// would keep retrying the same port while 8000-8999 is mostly free.
	span := g.MaxPort - g.MinPort + 1
	start := time.Now().Nanosecond() % span
	for offset := 0; offset < span; offset++ {
		port := g.MinPort + (start+offset)%span
		if conn, addr, err := g.bindOne(conf.Network, port); err == nil {
			return conn, addr, nil
		}
	}
	return nil, nil, fmt.Errorf("p2p.relay_port_exhausted")
}

// AllocateListener and AllocateConn are never used for UDP-only relay sockets;
// they exist to satisfy the relay address generator interface.
func (g *portRangeAllocator) AllocateListener(turn.AllocateListenerConfig) (net.Listener, net.Addr, error) {
	return nil, nil, fmt.Errorf("p2p.invalid_relay_network")
}

func (g *portRangeAllocator) AllocateConn(turn.AllocateConnConfig) (net.Conn, error) {
	return nil, fmt.Errorf("p2p.invalid_relay_network")
}
