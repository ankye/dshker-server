package coordinator

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
	"github.com/gin-gonic/gin"
)

type Server struct {
	config   Config
	store    *Store
	sessions *Sessions
	budget   *limiter
	hub      *signalHub
	router   *gin.Engine
}

func NewServer(config Config, store *Store) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if store == nil || store.CA == nil {
		return nil, errors.New("p2p.identity_unavailable")
	}
	server := &Server{config: config, store: store, sessions: NewSessions(store), budget: newLimiter(), hub: newSignalHub()}
	server.router = server.routes()
	return server, nil
}

func (server *Server) TLSConfig() (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(server.config.TLSCertPath, server.config.TLSKeyPath)
	if err != nil {
		return nil, errors.New("p2p.tls_unavailable")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.store.CA)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven}, nil
}

func (server *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.router.ServeHTTP(writer, request)
}

func (server *Server) admission(c *gin.Context) {
	writer, request := c.Writer, c.Request
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	ip, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || !server.budget.allow(ip, time.Now()) {
		writeFailure(writer, "p2p.rate_limited", http.StatusTooManyRequests)
		c.Abort()
		return
	}
	if request.TLS == nil {
		writeFailure(writer, "p2p.tls_required", http.StatusForbidden)
		c.Abort()
		return
	}
	if request.URL.RawQuery != "" {
		writeFailure(writer, "p2p.invalid_request", http.StatusBadRequest)
		c.Abort()
		return
	}
	c.Next()
}

func (server *Server) routes() *gin.Engine {
	router := gin.New()
	router.RedirectTrailingSlash = false
	router.RedirectFixedPath = false
	_ = router.SetTrustedProxies(nil)
	router.Use(server.admission)
	router.NoRoute(func(c *gin.Context) { writeFailure(c.Writer, "p2p.unknown_operation", http.StatusNotFound) })
	router.GET("/health/https", func(c *gin.Context) {
		writeJSON(c.Writer, map[string]any{"version": protocol.Version, "serviceId": server.store.ServiceID})
	})
	router.POST("/v1/identity", endpoint(func(body identityRequest) (any, error) { return server.identity(body.Nonce) }))
	router.POST("/v1/enroll", endpoint(func(body Enrollment) (any, error) { return server.store.Enroll(body, time.Now()) }))
	router.POST("/v1/network/join", endpoint(func(body NetworkJoin) (any, error) { return server.store.JoinNetwork(body, time.Now()) }))
	router.POST("/v1/enrollment-query", endpoint(func(body EnrollmentQuery) (any, error) { return server.store.ReadEnrollment(body, time.Now()) }))
	router.POST("/v1/recover-certificate", endpoint(func(body CertificateRecovery) (any, error) {
		certificate, err := server.store.RecoverCertificate(body, time.Now())
		return map[string]any{"certificate": certificate}, err
	}))
	server.userRoutes(router)
	devices := router.Group("/v1", func(c *gin.Context) {
		device, err := server.authenticate(c.Request)
		if err != nil {
			writeError(c.Writer, err)
			c.Abort()
			return
		}
		c.Set("device", device)
		c.Next()
	})
	devices.GET("/me", func(c *gin.Context) { writeJSON(c.Writer, c.MustGet("device")) })
	devices.GET("/pairs", func(c *gin.Context) {
		pairs, err := server.store.Pairs(c.MustGet("device").(Device).ID)
		respond(c, pairs, err)
	})
	devices.GET("/pairs/:pairId/identity", func(c *gin.Context) {
		identity, err := server.pairIdentity(c.MustGet("device").(Device).ID, c.Param("pairId"), time.Now())
		respond(c, identity, err)
	})
	devices.POST("/turn-credentials", func(c *gin.Context) {
		if server.config.turnRelay().Enabled() {
			device := c.MustGet("device").(Device)
			username, password, err := TurnCredentials(server.config.TurnSharedSecret, device.ID)
			if err != nil {
				writeError(c.Writer, err)
				return
			}
			writeJSON(c.Writer, map[string]any{
				"urls":       []string{"turn:" + server.turnURL()},
				"username":   username,
				"credential": password,
			})
			return
		}
		writeError(c.Writer, errors.New("p2p.relay_unconfigured"))
	})
	devices.GET("/signals", func(c *gin.Context) { server.serveSignals(c.Writer, c.Request, c.MustGet("device").(Device)) })
	for _, path := range []string{"/share", "/heartbeat", "/invite", "/adopt-network", "/pair-action", "/renew-certificate", "/attempt", "/lease", "/end"} {
		devices.POST(path, func(c *gin.Context) {
			value, err := server.deviceOperation(c.Request, c.MustGet("device").(Device), time.Now())
			respond(c, value, err)
		})
	}
	return router
}

func endpoint[T any](operation func(T) (any, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := readBody[T](c.Request)
		if err != nil {
			writeError(c.Writer, err)
			return
		}
		value, err := operation(body)
		respond(c, value, err)
	}
}

func respond(c *gin.Context, value any, err error) {
	if err != nil {
		writeError(c.Writer, err)
		return
	}
	writeJSON(c.Writer, value)
}

type identityRequest struct {
	Nonce string `json:"nonce"`
}
type inviteRequest struct {
	Share string `json:"share"`
}
type pairAction struct {
	PairID      string `json:"pairId"`
	Action      string `json:"action"`
	Fingerprint string `json:"fingerprint"`
}
type beginRequest struct {
	PairID     string `json:"pairId"`
	Generation uint64 `json:"generation"`
}
type leaseRequest struct {
	PairID    string `json:"pairId"`
	AttemptID string `json:"attemptId"`
}

func (server *Server) deviceOperation(request *http.Request, device Device, now time.Time) (any, error) {
	switch request.URL.Path {
	case "/v1/share":
		body, err := readBody[networkRequest](request)
		if err != nil {
			return nil, err
		}
		return server.store.Share(device.ID, body.NetworkID, now)
	case "/v1/heartbeat":
		// The body is the device's own report about its build, plus the account it is
		// signed in to. Both stay optional: a client that sends {} keeps working and
		// simply reports nothing, and a machine that is signed in nowhere records no
		// presence and reads as offline.
		telemetry, err := readBody[heartbeatRequest](request)
		if err != nil {
			return nil, err
		}
		return map[string]any{"deviceId": device.ID, "at": now.Unix()}, server.sessions.Heartbeat(device.ID, telemetry.UserID, telemetry.telemetry(), now)
	case "/v1/invite":
		body, err := readBody[inviteRequest](request)
		if err != nil {
			return nil, err
		}
		var share Share
		encoded, err := base64.RawURLEncoding.DecodeString(body.Share)
		if err != nil {
			return nil, errors.New("p2p.invalid_pairing_code")
		}
		if err = protocol.Decode(encoded, &share); err != nil {
			return nil, err
		}
		return server.store.Invite(device.ID, share, now)
	case "/v1/adopt-network":
		// No body: the caller cannot choose its peers. They are derived from the
		// bindings it already holds, so this cannot be aimed at another account.
		pairs, err := server.store.AdoptNetwork(device.ID, now)
		if err != nil {
			return nil, err
		}
		return map[string]any{"pairs": pairs}, nil
	case "/v1/pair-action":
		body, err := readBody[pairAction](request)
		if err != nil {
			return nil, err
		}
		pair, err := server.store.ActOnPair(device.ID, body.PairID, body.Action, body.Fingerprint, now)
		if err == nil && pair.State == "revoked" {
			server.hub.notifyPair(pair, map[string]any{"type": "revoked", "pairId": pair.ID, "revision": pair.Revision})
		}
		return pair, err
	case "/v1/renew-certificate":
		body, err := readBody[Renewal](request)
		if err != nil {
			return nil, err
		}
		certificate, err := server.store.Renew(request.TLS.PeerCertificates[0], body, now)
		return map[string]any{"certificate": certificate}, err
	case "/v1/attempt":
		body, err := readBody[beginRequest](request)
		if err != nil {
			return nil, err
		}
		lease, err := server.sessions.Begin(device.ID, body.PairID, body.Generation, now)
		if err != nil {
			return nil, err
		}
		if err = server.hub.send(lease.ToDeviceID, map[string]any{"type": "attempt", "lease": lease}); err != nil {
			server.sessions.End(device.ID, lease.PairID, lease.AttemptID)
			return nil, err
		}
		return lease, nil
	case "/v1/lease", "/v1/end":
		body, err := readBody[leaseRequest](request)
		if err != nil {
			return nil, err
		}
		if request.URL.Path == "/v1/end" {
			return map[string]any{"attemptId": body.AttemptID, "ended": true}, server.sessions.End(device.ID, body.PairID, body.AttemptID)
		}
		return server.sessions.Renew(device.ID, body.PairID, body.AttemptID, now)
	}
	return nil, errors.New("p2p.unknown_operation")
}

func (server *Server) authenticate(request *http.Request) (Device, error) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) != 1 {
		return Device{}, errors.New("p2p.device_unauthorized")
	}
	return server.store.Authenticate(request.TLS.PeerCertificates[0], time.Now())
}

type Identity struct {
	Version     int    `json:"version"`
	ServiceID   string `json:"serviceId"`
	PublicKey   []byte `json:"publicKey"`
	Certificate []byte `json:"certificate"`
	Nonce       string `json:"nonce"`
	HTTPSOrigin string `json:"httpsOrigin"`
	WSSURL      string `json:"wssUrl"`
	STUNAddress string `json:"stunAddress"`
	Signature   string `json:"signature"`
}

func (identity Identity) SigningBytes() []byte {
	encoded, _ := json.Marshal([]any{"dshker.service.v1", identity.Version, identity.ServiceID, identity.PublicKey, identity.Certificate, identity.Nonce, identity.HTTPSOrigin, identity.WSSURL, identity.STUNAddress})
	return encoded
}

func (server *Server) identity(nonce string) (Identity, error) {
	if !protocol.ValidID(nonce) {
		return Identity{}, errors.New("p2p.invalid_challenge")
	}
	identity := Identity{protocol.Version, server.store.ServiceID, server.store.key.Public().(ed25519.PublicKey), server.store.CA.Raw, nonce, server.config.HTTPSOrigin, server.config.WSSURL, server.config.STUNAddress, ""}
	identity.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(server.store.key, identity.SigningBytes()))
	return identity, nil
}

func readBody[T any](request *http.Request) (T, error) {
	var body T
	if request.Header.Get("Content-Type") != "application/json" {
		return body, errors.New("p2p.invalid_content_type")
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, protocol.MaxControlBytes+1))
	if err != nil {
		return body, errors.New("p2p.request_interrupted")
	}
	err = protocol.Decode(data, &body)
	return body, err
}

func writeJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	json.NewEncoder(writer).Encode(value)
}

func writeFailure(writer http.ResponseWriter, code string, status int) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	json.NewEncoder(writer).Encode(map[string]string{"code": code})
}

func writeError(writer http.ResponseWriter, err error) {
	code := err.Error()
	if !strings.HasPrefix(code, "p2p.") || strings.ContainsAny(code, " \n\r") {
		writeFailure(writer, "p2p.internal_error", http.StatusInternalServerError)
		return
	}
	status := http.StatusBadRequest
	switch code {
	case "p2p.user_unauthorized", "p2p.device_unauthorized", "p2p.login_failed":
		status = http.StatusUnauthorized
	case "p2p.network_unauthorized", "p2p.binding_unauthorized", "p2p.pair_unauthorized":
		status = http.StatusForbidden
	case "p2p.rate_limited":
		status = http.StatusTooManyRequests
	case "p2p.user_conflict", "p2p.request_conflict", "p2p.pair_state_conflict", "p2p.connection_busy", "p2p.pairing_busy":
		status = http.StatusConflict
	}
	writeFailure(writer, code, status)
}

// Run owns both listeners and shuts both down on any listener failure.
func (server *Server) Run(ctx context.Context) error {
	tlsConfig, err := server.TLSConfig()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", server.config.HTTPSListen)
	if err != nil {
		return err
	}
	defer listener.Close()
	udpListen := server.config.STUNListen
	if server.config.turnRelay().Enabled() {
		udpListen = server.config.turnListen()
	}
	address, err := net.ResolveUDPAddr("udp", udpListen)
	if err != nil {
		return err
	}
	udp, err := net.ListenUDP("udp", address)
	if err != nil {
		return err
	}
	defer udp.Close()
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	service := &http.Server{Handler: server, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	defer server.hub.close()
	results := make(chan error, 2)
	go func() { results <- service.Serve(tls.NewListener(listener, tlsConfig)) }()
	go func() {
		relay := server.config.turnRelay()
		if relay.Enabled() {
			results <- ServeTURN(child, udp, relay)
		} else {
			results <- ServeSTUN(child, udp)
		}
	}()
	select {
	case err = <-results:
	case <-ctx.Done():
	}
	cancel()
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	closeErr := service.Shutdown(shutdown)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return closeErr
}
