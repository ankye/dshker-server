// 仅用于验证已构建二进制的真实进程、HTTPS 和持久化链路，不进入服务器制品。
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ankye/dshker-server/internal/coordinator"
)

type event struct {
	Step       string `json:"step"`
	Status     int    `json:"status"`
	ResourceID string `json:"resourceId"`
}

func main() {
	binary := flag.String("binary", "", "已构建服务器二进制绝对路径")
	report := flag.String("report", "", "原始检查结果路径")
	flag.Parse()
	if err := run(*binary, *report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(binary, report string) error {
	if !filepath.IsAbs(binary) || report == "" {
		return fmt.Errorf("explicit binary and report required")
	}
	root, err := os.MkdirTemp("", "dshker-server-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	tcpAddress := tcp.Addr().String()
	tcp.Close()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	udpAddress := udp.LocalAddr().String()
	udp.Close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DSHKer smoke"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		return err
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return err
	}
	config := coordinator.Config{HTTPSOrigin: "https://" + tcpAddress, WSSURL: "wss://" + tcpAddress + "/v1/signals", HTTPSListen: tcpAddress, STUNListen: udpAddress, STUNAddress: udpAddress, TLSCertPath: filepath.Join(root, "tls.crt"), TLSKeyPath: filepath.Join(root, "tls.key"), DatabasePath: filepath.Join(root, "state.db"), IdentityKeyPath: filepath.Join(root, "identity.key")}
	configData, err := json.Marshal(config)
	if err != nil {
		return err
	}
	configPath := filepath.Join(root, "config.json")
	for path, data := range map[string][]byte{config.TLSCertPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), config.TLSKeyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), configPath: configData} {
		if err = os.WriteFile(path, data, 0600); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = exec.CommandContext(ctx, binary, "init", "--config", configPath).Run(); err != nil {
		return fmt.Errorf("binary init failed: %w", err)
	}
	password := randomText()
	create := exec.CommandContext(ctx, binary, "user-add", "--config", configPath, "--username", "smoke@test.com")
	create.Stdin = strings.NewReader(password + "\n")
	if err = create.Run(); err != nil {
		return fmt.Errorf("binary account creation failed: %w", err)
	}
	process := exec.CommandContext(ctx, binary, "serve", "--config", configPath)
	if err = process.Start(); err != nil {
		return err
	}
	defer func() { process.Process.Signal(os.Interrupt); process.Wait() }()
	trusted, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(trusted)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		response, e := client.Get(config.HTTPSOrigin + "/health/https")
		if e == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		return fmt.Errorf("production binary HTTPS startup failed")
	}
	events := []event{{"binary-init-and-start", 200, ""}}
	call := func(method, path, token string, body any, target any, want int) error {
		data, e := json.Marshal(body)
		if e != nil {
			return e
		}
		req, e := http.NewRequestWithContext(ctx, method, config.HTTPSOrigin+path, bytes.NewReader(data))
		if e != nil {
			return e
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, e := client.Do(req)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		if response.StatusCode != want {
			return fmt.Errorf("%s %s status %d, want %d", method, path, response.StatusCode, want)
		}
		if e = json.NewDecoder(response.Body).Decode(target); e != nil {
			return e
		}
		events = append(events, event{method + " " + path, response.StatusCode, ""})
		return nil
	}
	var session coordinator.UserSession
	if err = call("POST", "/v1/login", "", map[string]string{"username": "smoke@test.com", "password": password}, &session, 200); err != nil {
		return err
	}
	if session.User.Username != "smoke@test.com" || session.User.ID == "" || len(session.Token) != 64 {
		return fmt.Errorf("login identity readback mismatch")
	}
	var network coordinator.Network
	if err = call("POST", "/v1/networks", session.Token, map[string]string{"name": "runtime-network"}, &network, 200); err != nil {
		return err
	}
	if network.UserID != session.User.ID || network.Name != "runtime-network" || network.ID == "" {
		return fmt.Errorf("network ownership readback mismatch")
	}
	events[len(events)-1].ResourceID = network.ID
	var networks []coordinator.Network
	if err = call("GET", "/v1/networks", session.Token, nil, &networks, 200); err != nil {
		return err
	}
	if len(networks) != 1 || networks[0] != network {
		return fmt.Errorf("persisted network readback mismatch")
	}
	var grant struct {
		Token     string `json:"token"`
		NetworkID string `json:"networkId"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err = call("POST", "/v1/networks/"+network.ID+"/enrollment-tokens", session.Token, struct{}{}, &grant, 200); err != nil {
		return err
	}
	if grant.NetworkID != network.ID || len(grant.Token) != 64 {
		return fmt.Errorf("binding token scope mismatch")
	}
	_, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, deviceKey)
	if err != nil {
		return err
	}
	var device coordinator.Device
	if err = call("POST", "/v1/enroll", "", coordinator.Enrollment{RequestID: randomText()[:32], Token: grant.Token, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), Name: "runtime-device"}, &device, 200); err != nil {
		return err
	}
	if device.UserID != session.User.ID || device.Name != "runtime-device" || !bytes.Equal(device.PublicKey, deviceKey.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("device binding readback mismatch")
	}
	var devices []coordinator.Device
	if err = call("GET", "/v1/networks/"+network.ID+"/devices", session.Token, nil, &devices, 200); err != nil {
		return err
	}
	if len(devices) != 1 || devices[0].ID != device.ID || devices[0].UserID != session.User.ID {
		return fmt.Errorf("network membership readback mismatch")
	}
	// A second device in the same network must become usable without an invite
	// code: joining is the authorization. This exercises the real mTLS path, since
	// adoption is a device-authenticated call.
	// Each machine enrolls with its own token: a grant is single use, which is
	// exactly how a second computer joins in practice.
	var secondGrant struct {
		Token     string `json:"token"`
		NetworkID string `json:"networkId"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err = call("POST", "/v1/networks/"+network.ID+"/enrollment-tokens", session.Token, struct{}{}, &secondGrant, 200); err != nil {
		return err
	}
	secondKey, secondCert, err := enrollDevice(ctx, call, secondGrant.Token, "runtime-device-2")
	if err != nil {
		return err
	}
	deviceClient := mutualClient(roots, secondCert, secondKey)
	defer deviceClient.CloseIdleConnections()
	var adopted struct {
		Pairs []coordinator.Pair `json:"pairs"`
	}
	if err = deviceCall(ctx, deviceClient, config.HTTPSOrigin, "/v1/adopt-network", &adopted); err != nil {
		return err
	}
	if len(adopted.Pairs) != 1 {
		return fmt.Errorf("adoption produced %d pairs, want 1", len(adopted.Pairs))
	}
	if adopted.Pairs[0].State != "active" {
		return fmt.Errorf("adopted pair state %q, want active", adopted.Pairs[0].State)
	}
	if adopted.Pairs[0].NetworkID != network.ID {
		return fmt.Errorf("adopted pair is not in the shared network")
	}
	events = append(events, event{"POST /v1/adopt-network", 200, adopted.Pairs[0].ID})
	// Idempotent: startup runs this on every launch.
	var again struct {
		Pairs []coordinator.Pair `json:"pairs"`
	}
	if err = deviceCall(ctx, deviceClient, config.HTTPSOrigin, "/v1/adopt-network", &again); err != nil {
		return err
	}
	if len(again.Pairs) != 0 {
		return fmt.Errorf("second adoption duplicated %d pairs", len(again.Pairs))
	}
	var result map[string]any
	if err = call("DELETE", "/v1/networks/"+network.ID, session.Token, struct{}{}, &result, 200); err != nil {
		return err
	}
	if result["deleted"] != true {
		return fmt.Errorf("network delete did not confirm")
	}
	if err = call("GET", "/v1/networks/"+network.ID+"/devices", session.Token, nil, &result, 403); err != nil {
		return err
	}
	if result["code"] != "p2p.network_unauthorized" {
		return fmt.Errorf("deleted network remained authorized")
	}
	if err = call("POST", "/v1/logout", session.Token, struct{}{}, &result, 200); err != nil {
		return err
	}
	if err = call("GET", "/v1/networks", session.Token, nil, &result, 401); err != nil {
		return err
	}
	if result["code"] != "p2p.user_unauthorized" {
		return fmt.Errorf("logout retained authorization")
	}
	if err = os.MkdirAll(filepath.Dir(report), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(map[string]any{"kind": "local-production-process-diagnostic", "userId": session.User.ID, "networkId": network.ID, "deviceId": device.ID, "events": events}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(report, append(data, '\n'), 0600); err != nil {
		return err
	}
	fmt.Println("production process HTTPS and persistence smoke: PASS")
	return nil
}

// enrollDevice enrolls one more device with the same network token and returns
// the material needed to speak as that device over mTLS.
func enrollDevice(
	ctx context.Context,
	call func(method, path, token string, body any, target any, want int) error,
	enrollmentToken string,
	name string,
) (ed25519.PrivateKey, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, err
	}
	var device coordinator.Device
	request := coordinator.Enrollment{
		RequestID: randomText()[:32],
		Token:     enrollmentToken,
		CSR:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
		Name:      name,
	}
	if err = call("POST", "/v1/enroll", "", request, &device, 200); err != nil {
		return nil, nil, err
	}
	return key, device.Certificate, nil
}

// mutualClient builds a client that presents a device certificate, which is how
// the coordinator authenticates device-scoped endpoints.
func mutualClient(
	roots *x509.CertPool,
	certificate []byte,
	key ed25519.PrivateKey,
) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: key}},
			MinVersion:   tls.VersionTLS13,
		}},
	}
}

// deviceCall posts an empty body to a device-authenticated endpoint.
func deviceCall(
	ctx context.Context,
	client *http.Client,
	origin string,
	path string,
	target any,
) error {
	request, err := http.NewRequestWithContext(ctx, "POST", origin+path, bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("POST %s status %d, want 200", path, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(target)
}

func randomText() string {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", data)
}
