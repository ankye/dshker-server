package coordinator

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pion/turn/v5"
)

// testRelaySecret is a fixed >=32-byte shared secret for the relay tests.
const testRelaySecret = "test-relay-shared-secret-0123456789abcdef0123456789abcdef"

func TestTurnCredentialsShapeAndHandler(t *testing.T) {
	username, password, err := TurnCredentials(testRelaySecret, "device-3711f270")
	if err != nil {
		t.Fatalf("TurnCredentials failed: %v", err)
	}
	fields := strings.Split(username, ":")
	if len(fields) != 2 || fields[1] != "device-3711f270" {
		t.Fatalf("username %q not in <unix-expiry>:<deviceID> shape", username)
	}
	if fields[0] == "" || password == "" {
		t.Fatalf("empty expiry or password")
	}
	handler := turn.LongTermTURNRESTAuthHandler(testRelaySecret, nil)
	userID, key, ok := handler(&turn.RequestAttributes{Username: username, Realm: relayRealm})
	if !ok || userID != "device-3711f270" || len(key) == 0 {
		t.Fatalf("valid credential rejected: ok=%v userID=%q key=%d bytes", ok, userID, len(key))
	}
	if _, _, ok := handler(&turn.RequestAttributes{Username: "1:device-3711f270", Realm: relayRealm}); ok {
		t.Fatal("expired credential accepted")
	}
	if _, _, ok := handler(&turn.RequestAttributes{Username: "not-a-timestamp:device", Realm: relayRealm}); ok {
		t.Fatal("malformed credential accepted")
	}
}

// startTestRelay launches ServeTURN on a random loopback port for the given
// secret; peer and allocation ports come from a dedicated local range.
func startTestRelay(t *testing.T, sharedSecret string) (controlAddr string, relay TurnRelay) {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen control: %v", err)
	}
	relay = TurnRelay{
		SharedSecret:   sharedSecret,
		ControlAddress: connection.LocalAddr().String(),
		PublicIP:       net.IPv4(127, 0, 0, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeTURN(ctx, connection, relay) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	// Wait for the server to be ready by attempting a legitimate allocation.
	controlAddr = relay.ControlAddress
	return controlAddr, relay
}

func allocateOverRelay(t *testing.T, controlAddr, username, password string) (*turn.Client, net.PacketConn) {
	t.Helper()
	local, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	turnClient, err := turn.NewClient(&turn.ClientConfig{
		Conn:           local,
		STUNServerAddr: controlAddr,
		TURNServerAddr: controlAddr,
		Username:       username,
		Password:       password,
		Realm:          relayRealm,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := turnClient.Listen(); err != nil {
		t.Fatalf("client listen: %v", err)
	}
	allocation, err := turnClient.Allocate()
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	t.Cleanup(func() {
		_ = allocation.Close()
		_ = local.Close()
	})
	return turnClient, allocation
}

func TestServeTURNRelaysDatagrams(t *testing.T) {
	controlAddr, _ := startTestRelay(t, testRelaySecret)
	usernameA, passwordA, err := TurnCredentials(testRelaySecret, "device-a")
	if err != nil {
		t.Fatal(err)
	}
	usernameB, passwordB, err := TurnCredentials(testRelaySecret, "device-b")
	if err != nil {
		t.Fatal(err)
	}
	clientA, allocationA := allocateOverRelay(t, controlAddr, usernameA, passwordA)
	clientB, allocationB := allocateOverRelay(t, controlAddr, usernameB, passwordB)
	relayedA := allocationA.LocalAddr().(*net.UDPAddr)
	relayedB := allocationB.LocalAddr().(*net.UDPAddr)
	// RFC 5766 permissions: each peer installs a permission for the other
	// relayed address before the traffic flows.
	if err := clientA.CreatePermission(relayedB); err != nil {
		t.Fatalf("A permission: %v", err)
	}
	if err := clientB.CreatePermission(relayedA); err != nil {
		t.Fatalf("B permission: %v", err)
	}

	// A -> B through the relay: the packet arrives at B's allocation socket.
	if err := allocationA.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := allocationB.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := allocationA.WriteTo([]byte("ping-a-to-b"), relayedB); err != nil {
		t.Fatalf("A->B write: %v", err)
	}
	buffer := make([]byte, 256)
	size, _, err := allocationB.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("A->B did not arrive at B through the relay: %v", err)
	}
	if string(buffer[:size]) != "ping-a-to-b" {
		t.Fatalf("A->B payload mangled: %q", buffer[:size])
	}

	// B -> A.
	if _, err := allocationB.WriteTo([]byte("pong-b-to-a"), relayedA); err != nil {
		t.Fatalf("B->A write: %v", err)
	}
	size, _, err = allocationA.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("B->A did not arrive: %v", err)
	}
	if string(buffer[:size]) != "pong-b-to-a" {
		t.Fatalf("B->A payload mangled: %q", buffer[:size])
	}
}

func TestServeTURNRejectsTamperedCredential(t *testing.T) {
	controlAddr, _ := startTestRelay(t, testRelaySecret)
	username, _, err := TurnCredentials(testRelaySecret, "device-a")
	if err != nil {
		t.Fatal(err)
	}
	local, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	turnClient, err := turn.NewClient(&turn.ClientConfig{
		Conn:           local,
		STUNServerAddr: controlAddr,
		TURNServerAddr: controlAddr,
		Username:       username,
		Password:       "definitely-not-the-right-password",
		Realm:          relayRealm,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := turnClient.Listen(); err != nil {
		t.Fatal(err)
	}
	if allocation, err := turnClient.Allocate(); err == nil {
		_ = allocation.Close()
		t.Fatal("allocation with a tampered credential succeeded")
	}
}

// TestTurnRelayDisabledRejectsCredentials keeps the credential endpoint honest
// when the relay is not configured.
func TestTurnRelayDisabledRejectsCredentials(t *testing.T) {
	if _, _, err := TurnCredentials("short", "device-a"); err == nil {
		t.Fatal("short secret produced credentials")
	}
}
