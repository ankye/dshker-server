package coordinator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ankye/dshker-server/internal/protocol"
)

type Config struct {
	HTTPSOrigin     string `json:"httpsOrigin"`
	WSSURL          string `json:"wssUrl"`
	STUNAddress     string `json:"stunAddress"`
	HTTPSListen     string `json:"httpsListen"`
	STUNListen      string `json:"stunListen"`
	TLSCertPath     string `json:"tlsCertPath"`
	TLSKeyPath      string `json:"tlsKeyPath"`
	DatabasePath    string `json:"databasePath"`
	IdentityKeyPath string `json:"identityKeyPath"`
	// TurnSharedSecret, when set (hex, 32+ bytes), turns the STUN socket into
	// an RFC 8656 relay that also serves TURN allocations. Credentials are
	// derived per device (TURN REST shape), never persisted.
	TurnSharedSecret string `json:"turnSharedSecret"`
	// TurnListen defaults to STUNListen when empty (one socket serves both
	// Binding and TURN control).
	TurnListen string `json:"turnListen"`
	// RelayPublicIP is the address allocations advertise to peers; required
	// when the relay is enabled (the box may sit behind a NAT or a cloud LB).
	RelayPublicIP string `json:"relayPublicIP"`
}

func ReadConfig(path string) (Config, error) {
	var config Config
	file, err := os.Open(path)
	if err != nil {
		return config, errors.New("p2p.config_unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > protocol.MaxControlBytes {
		return config, errors.New("p2p.invalid_config")
	}
	data, err := io.ReadAll(io.LimitReader(file, protocol.MaxControlBytes+1))
	if err != nil {
		return config, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return config, errors.New("p2p.invalid_fields")
	}
	if token, err := decoder.Token(); err != io.EOF {
		_ = token
		return config, errors.New("p2p.invalid_fields")
	}
	// Validate() enforces the core fields; the relay options stay additive
	// so existing configuration files keep working unchanged.
	return config, config.Validate()
}

func (config Config) Validate() error {
	origin, err := url.Parse(config.HTTPSOrigin)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("p2p.invalid_https_origin")
	}
	wss, err := url.Parse(config.WSSURL)
	if err != nil || wss.Scheme != "wss" || wss.Host != origin.Host || wss.User != nil || wss.Path != "/v1/signals" || wss.RawQuery != "" || wss.Fragment != "" {
		return errors.New("p2p.invalid_wss_endpoint")
	}
	for _, address := range []string{config.STUNAddress, config.HTTPSListen, config.STUNListen} {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host == "" {
			return errors.New("p2p.invalid_endpoint")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return errors.New("p2p.invalid_endpoint")
		}
	}
	for _, path := range []string{config.TLSCertPath, config.TLSKeyPath, config.DatabasePath, config.IdentityKeyPath} {
		if !filepath.IsAbs(path) {
			return errors.New("p2p.explicit_absolute_path_required")
		}
	}
	if config.DatabasePath == config.IdentityKeyPath || config.TLSCertPath == config.TLSKeyPath || config.IdentityKeyPath == config.TLSKeyPath || config.DatabasePath == config.TLSCertPath || config.DatabasePath == config.TLSKeyPath || config.IdentityKeyPath == config.TLSCertPath {
		return errors.New("p2p.path_conflict")
	}
	if config.TurnSharedSecret != "" {
		if len(config.TurnSharedSecret) < 32 {
			return errors.New("p2p.invalid_turn_shared_secret")
		}
		listen := config.TurnListen
		if listen == "" {
			listen = config.STUNListen
		}
		host, port, err := net.SplitHostPort(listen)
		if err != nil || host == "" {
			return errors.New("p2p.invalid_endpoint")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return errors.New("p2p.invalid_endpoint")
		}
		if config.RelayPublicIP == "" || net.ParseIP(config.RelayPublicIP) == nil {
			return errors.New("p2p.invalid_relay_public_ip")
		}
	}
	return nil
}

// turnListen resolves the relay listening endpoint; it defaults to the STUN
// socket so one UDP port serves both Binding and TURN control.
func (config Config) turnListen() string {
	if config.TurnListen != "" {
		return config.TurnListen
	}
	return config.STUNListen
}

// turnRelay resolves the relay wiring.
func (config Config) turnRelay() TurnRelay {
	relay := TurnRelay{SharedSecret: config.TurnSharedSecret, ControlAddress: config.turnListen()}
	if relay.Enabled() {
		relay.PublicIP = net.ParseIP(config.RelayPublicIP)
	}
	return relay
}

// turnURL returns the "turn:host:port" URL clients are told to reach the relay
// on: the public DNS name from stunAddress (the name peers already trust for
// this server) with the relay control port.
func (server *Server) turnURL() string {
	host, _, err := net.SplitHostPort(server.config.STUNAddress)
	if err != nil {
		return ""
	}
	_, port, err := net.SplitHostPort(server.config.turnListen())
	if err != nil {
		return ""
	}
	return net.JoinHostPort(host, port)
}
