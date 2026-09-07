package coordinator

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

type sourceBudget struct {
	at    time.Time
	count int
}

type limiter struct {
	mu      sync.Mutex
	sources map[string]sourceBudget
	global  sourceBudget
}

func newLimiter() *limiter { return &limiter{sources: map[string]sourceBudget{}} }

func (budget *limiter) allow(source string, now time.Time) bool {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	if !budget.global.at.Add(time.Second).After(now) {
		budget.global = sourceBudget{at: now}
	}
	if budget.global.count >= 1000 {
		return false
	}
	for key, value := range budget.sources {
		if !value.at.Add(time.Minute).After(now) {
			delete(budget.sources, key)
		}
	}
	value, exists := budget.sources[source]
	if !exists && len(budget.sources) >= 1024 {
		return false
	}
	if !value.at.Add(time.Second).After(now) {
		value = sourceBudget{at: now}
	}
	if value.count >= 20 {
		return false
	}
	value.count++
	budget.global.count++
	budget.sources[source] = value
	return true
}

// ServeSTUN only answers bounded UDP Binding requests; no TURN or forwarding exists.
func ServeSTUN(ctx context.Context, connection *net.UDPConn) error {
	budget := newLimiter()
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	buffer := make([]byte, 1025)
	for {
		size, source, err := connection.ReadFromUDP(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if size < 20 || size > 1024 || !budget.allow(source.IP.String(), time.Now()) {
			continue
		}
		response, err := stunResponse(buffer[:size], source)
		if err != nil {
			continue
		}
		if _, err = connection.WriteToUDP(response, source); err != nil {
			return err
		}
	}
}

func stunResponse(data []byte, source *net.UDPAddr) ([]byte, error) {
	message := &stun.Message{Raw: data}
	if err := message.Decode(); err != nil || message.Type != stun.BindingRequest || int(message.Length)+20 != len(data) {
		return nil, errors.New("p2p.invalid_stun_binding")
	}
	response, err := stun.Build(message, stun.BindingSuccess, &stun.XORMappedAddress{IP: source.IP, Port: source.Port}, stun.Fingerprint)
	if err != nil {
		return nil, err
	}
	return response.Raw, nil
}
