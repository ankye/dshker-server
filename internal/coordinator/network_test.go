package coordinator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
	"github.com/coder/websocket"
	"github.com/pion/stun/v3"
)

func networkServer(t *testing.T) (*Server, *httptest.Server, *http.Client, time.Time) {
	t.Helper()
	store, db, key, now := newStore(t)
	config := Config{HTTPSOrigin: "https://localhost:443", WSSURL: "wss://localhost:443/v1/signals", STUNAddress: "localhost:3478", HTTPSListen: "127.0.0.1:443", STUNListen: "127.0.0.1:3478", TLSCertPath: db + ".crt", TLSKeyPath: db + ".key", DatabasePath: db, IdentityKeyPath: key}
	server, err := NewServer(config, store)
	if err != nil {
		t.Fatal(err)
	}
	surface := httptest.NewUnstartedServer(server)
	roots := x509.NewCertPool()
	roots.AddCert(store.CA)
	surface.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots}
	surface.StartTLS()
	t.Cleanup(func() { server.hub.close(); surface.Close() })
	server.config.HTTPSOrigin = surface.URL
	server.config.WSSURL = "wss" + surface.URL[5:] + "/v1/signals"
	return server, surface, surface.Client(), now
}

func post(t *testing.T, client *http.Client, address string, body any, target any) int {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(address, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if err = json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func TestRealTLSIdentityEnrollmentAndReadback(t *testing.T) {
	server, surface, client, now := networkServer(t)
	nonce := protocol.NewID()
	var identity Identity
	if status := post(t, client, surface.URL+"/v1/identity", identityRequest{nonce}, &identity); status != http.StatusOK {
		t.Fatal(status)
	}
	signature, err := base64.RawURLEncoding.DecodeString(identity.Signature)
	if err != nil || identity.Nonce != nonce || identity.ServiceID != server.store.ServiceID || identity.HTTPSOrigin != surface.URL || !ed25519.Verify(identity.PublicKey, identity.SigningBytes(), signature) {
		t.Fatal("identity does not bind live endpoint/challenge")
	}
	private, csr := makeCSR(t)
	token, err := fixtureToken(t, server.store, now)
	if err != nil {
		t.Fatal(err)
	}
	var device Device
	if status := post(t, client, surface.URL+"/v1/enroll", Enrollment{protocol.NewID(), token, csr, "TLS device"}, &device); status != 200 {
		t.Fatal(status)
	}
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{device.Certificate}, PrivateKey: private}}
	authenticated := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	response, err := authenticated.Get(surface.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var readback Device
	if err = json.NewDecoder(response.Body).Decode(&readback); err != nil || readback.ID != device.ID || readback.Name != "TLS device" || !bytes.Equal(readback.PublicKey, private.Public().(ed25519.PublicKey)) {
		t.Fatal("mTLS readback mismatch", err)
	}
	response, err = client.Get(surface.URL + "/v1/me")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("unauthenticated device endpoint admitted")
	}
	var failure map[string]string
	if status := post(t, client, surface.URL+"/v1/identity", map[string]any{}, &failure); status == 200 || failure["code"] != "p2p.missing_field" {
		t.Fatal("missing nonce silently defaulted", failure)
	}
}

func TestRealWSSForwardsOnlyAuthorizedSignedSignal(t *testing.T) {
	server, surface, client, now := networkServer(t)
	a, aKey, _, _ := enroll(t, server.store, now)
	b, bKey, _, _ := enroll(t, server.store, now)
	pair := pairDevices(t, server.store, a, b, now)
	_ = pair
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dial := func(device Device, key ed25519.PrivateKey) *websocket.Conn {
		transport := client.Transport.(*http.Transport).Clone()
		transport.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{device.Certificate}, PrivateKey: key}}
		t.Cleanup(transport.CloseIdleConnections)
		connection, _, err := websocket.Dial(ctx, "wss"+surface.URL[5:]+"/v1/signals", &websocket.DialOptions{HTTPClient: &http.Client{Transport: transport}, Subprotocols: []string{"dshker.signal.v1"}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { connection.CloseNow() })
		_, ready, err := connection.Read(ctx)
		var value map[string]any
		if err != nil || json.Unmarshal(ready, &value) != nil || value["deviceId"] != device.ID || value["type"] != "ready" {
			t.Fatal("ready identity mismatch", err)
		}
		return connection
	}
	first, second := dial(a, aKey), dial(b, bKey)
	lease, err := server.sessions.Begin(a.ID, b.ID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	sdp, _ := json.Marshal(protocol.SDP{SDP: "v=0\r\n"})
	signal := protocol.Signal{Version: 1, Type: "offer", MessageID: protocol.NewID(), AttemptID: lease.AttemptID, Generation: 1, FromDeviceID: a.ID, ToDeviceID: b.ID, PairID: b.ID, Sequence: 1, ExpiresAt: now.Unix() + 60, Payload: base64.RawURLEncoding.EncodeToString(sdp)}
	signal.Sign(aKey)
	data, _ := json.Marshal(signal)
	if err = first.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	_, received, err := second.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var event struct {
		Type   string          `json:"type"`
		Signal protocol.Signal `json:"signal"`
	}
	if err = json.Unmarshal(received, &event); err != nil || event.Type != "signal" || event.Signal != signal {
		t.Fatal("forward changed signed scope", err)
	}
	if err = first.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatal(err)
	}
	if _, _, err = first.Read(ctx); err == nil {
		t.Fatal("replayed signal connection not rejected")
	}
}

func TestRealSTUNReportsSourceAndRejectsOtherMethods(t *testing.T) {
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- ServeSTUN(ctx, listener) }()
	client, err := net.DialUDP("udp", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err = client.Write(request.Raw); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1024)
	size, err := client.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	response := &stun.Message{Raw: buffer[:size]}
	var mapped stun.XORMappedAddress
	if response.Decode() != nil || mapped.GetFrom(response) != nil || response.Type != stun.BindingSuccess || response.TransactionID != request.TransactionID {
		t.Fatal("invalid Binding response")
	}
	source := client.LocalAddr().(*net.UDPAddr)
	if !mapped.IP.Equal(source.IP) || mapped.Port != source.Port {
		t.Fatal("STUN did not report actual source", mapped, source)
	}
	invalid := stun.MustBuild(stun.TransactionID, stun.NewType(stun.MethodAllocate, stun.ClassRequest))
	if _, err = stunResponse(invalid.Raw, source); err == nil {
		t.Fatal("TURN Allocate accepted")
	}
	cancel()
	select {
	case err = <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP listener leaked")
	}
}

func TestPresenceLeaseExpiryAndRevocation(t *testing.T) {
	store, _, _, now := newStore(t)
	a, _, _, _ := enroll(t, store, now)
	b, _, _, _ := enroll(t, store, now)
	pair := pairDevices(t, store, a, b, now)
	sessions := NewSessions(store)
	if _, err := sessions.Begin(a.ID, b.ID, 1, now); err == nil {
		t.Fatal("offline accepted")
	}
	for _, id := range []string{a.ID, b.ID} {
		if err := sessions.Heartbeat(id, now); err != nil {
			t.Fatal(err)
		}
	}
	if sessions.Presence(a.ID, now.Add(30*time.Second)) != "stale" {
		t.Fatal("presence did not expire")
	}
	lease, err := sessions.Begin(a.ID, b.ID, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.Begin(b.ID, a.ID, 1, now); err == nil {
		t.Fatal("simultaneous dial accepted")
	}
	if _, err = sessions.Renew(a.ID, b.ID, lease.AttemptID, now.Add(time.Minute)); err == nil {
		t.Fatal("expired lease revived")
	}
	if _, err = sessions.Renew(a.ID, b.ID, lease.AttemptID, now.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ActOnPair(b.ID, pair.ID, "revoke", "", now); err != nil {
		t.Fatal(err)
	}
	if err = store.UnbindDevice(lease.UserID, lease.NetworkID, b.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = sessions.Renew(a.ID, b.ID, lease.AttemptID, now.Add(21*time.Second)); err == nil {
		t.Fatal("unbound lease renewed")
	}
	if NewSessions(store).Presence(a.ID, now) != "offline" {
		t.Fatal("restart restored stale online presence")
	}
}

// Compile-time proof: production handler serves the normal net/http surface, not a test transport.
var _ http.Handler = (*Server)(nil)
