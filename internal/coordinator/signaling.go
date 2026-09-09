package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
	"github.com/coder/websocket"
)

type signalPeer struct {
	connection *websocket.Conn
	outgoing   chan []byte
}
type signalHub struct {
	mu    sync.Mutex
	peers map[string]*signalPeer
}

func newSignalHub() *signalHub { return &signalHub{peers: map[string]*signalPeer{}} }

func (hub *signalHub) send(id string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > protocol.MaxControlBytes {
		return errors.New("p2p.protocol_limit")
	}
	hub.mu.Lock()
	defer hub.mu.Unlock()
	peer, exists := hub.peers[id]
	if !exists {
		return errors.New("p2p.peer_offline")
	}
	select {
	case peer.outgoing <- data:
		return nil
	default:
		return errors.New("p2p.signal_limit")
	}
}

func (hub *signalHub) notifyPair(pair Pair, value any) {
	for _, id := range []string{pair.Initiator, pair.Target} {
		if hub.send(id, value) != nil {
			hub.mu.Lock()
			peer := hub.peers[id]
			hub.mu.Unlock()
			if peer != nil {
				peer.connection.CloseNow()
			}
		}
	}
}

func (hub *signalHub) close() {
	hub.mu.Lock()
	defer hub.mu.Unlock()
	for _, peer := range hub.peers {
		peer.connection.CloseNow()
	}
}

func (server *Server) serveSignals(writer http.ResponseWriter, request *http.Request, device Device) {
	if request.Method != http.MethodGet || request.Header.Get("Origin") != "" {
		writeFailure(writer, "p2p.invalid_signal_origin", http.StatusForbidden)
		return
	}
	server.hub.mu.Lock()
	if _, exists := server.hub.peers[device.ID]; exists {
		server.hub.mu.Unlock()
		writeFailure(writer, "p2p.device_busy", http.StatusConflict)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{Subprotocols: []string{"dshker.signal.v1"}})
	if err != nil {
		server.hub.mu.Unlock()
		return
	}
	if connection.Subprotocol() != "dshker.signal.v1" {
		server.hub.mu.Unlock()
		connection.Close(websocket.StatusProtocolError, "protocol required")
		return
	}
	peer := &signalPeer{connection: connection, outgoing: make(chan []byte, 32)}
	server.hub.peers[device.ID] = peer
	server.hub.mu.Unlock()
	defer func() {
		connection.CloseNow()
		server.hub.mu.Lock()
		delete(server.hub.peers, device.ID)
		server.sessions.Offline(device.ID)
		server.hub.mu.Unlock()
	}()
	connection.SetReadLimit(protocol.MaxControlBytes)
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	// Opening the signal socket proves liveness but reports nothing about the
	// build; empty telemetry leaves whatever the device last reported intact.
	if err = server.sessions.Heartbeat(device.ID, DeviceTelemetry{}, time.Now()); err != nil {
		return
	}
	if err = server.hub.send(device.ID, map[string]any{"type": "ready", "version": protocol.Version, "deviceId": device.ID}); err != nil {
		return
	}
	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case data := <-peer.outgoing:
				writeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
				err := connection.Write(writeCtx, websocket.MessageText, data)
				stop()
				if err != nil {
					return
				}
			}
		}
	}()
	server.readSignals(ctx, peer, device)
}

func (server *Server) readSignals(ctx context.Context, peer *signalPeer, device Device) {
	for {
		kind, data, err := peer.connection.Read(ctx)
		if err != nil {
			return
		}
		var signal protocol.Signal
		if kind != websocket.MessageText || protocol.Decode(data, &signal) != nil || server.sessions.Admit(device.ID, signal, time.Now()) != nil {
			peer.connection.Close(websocket.StatusPolicyViolation, "signal rejected")
			return
		}
		if err = server.hub.send(signal.ToDeviceID, map[string]any{"type": "signal", "signal": signal}); err != nil {
			peer.connection.Close(websocket.StatusTryAgainLater, "peer unavailable")
			return
		}
	}
}
