package coordinator

import (
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
	if err = protocol.Decode(data, &config); err != nil {
		return config, err
	}
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
	return nil
}
