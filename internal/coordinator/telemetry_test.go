package coordinator

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ankye/dshker-server/internal/protocol"
)

// Telemetry is descriptive: a device reports its own build, and the value is
// carried into the directory the operator reads.
func TestHeartbeatRecordsTelemetryAndLastSeen(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	device, _, _ := joinEnroll(t, store, network.ID, now)
	sessions := NewSessions(store)

	report := DeviceTelemetry{Version: "1.4.2", Platform: "darwin", Architecture: "arm64"}
	if err := sessions.Heartbeat(device.ID, device.UserID, report, now); err != nil {
		t.Fatal(err)
	}
	entries, err := store.NetworkDevices(network.UserID, network.ID)
	if err != nil || len(entries) != 1 {
		t.Fatal("device directory unreadable", err)
	}
	entry := entries[0]
	if entry.Version != "1.4.2" || entry.Platform != "darwin" || entry.Architecture != "arm64" {
		t.Fatalf("reported build not stored: %+v", entry)
	}
	if entry.LastSeen != now.Unix() {
		t.Fatalf("last seen = %d, want %d", entry.LastSeen, now.Unix())
	}
	// The directory identifies devices; it must not carry credential material.
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "certificate") {
		t.Fatalf("device directory leaked credential material: %s", encoded)
	}
}

// An empty report means "unchanged": a heartbeat that carries nothing must not
// erase what the device previously told us.
func TestHeartbeatWithoutTelemetryKeepsStoredBuild(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	device, _, _ := joinEnroll(t, store, network.ID, now)
	sessions := NewSessions(store)

	if err := sessions.Heartbeat(device.ID, device.UserID, DeviceTelemetry{Version: "2.0.0", Platform: "linux", Architecture: "amd64"}, now); err != nil {
		t.Fatal(err)
	}
	later := now.Add(2 * time.Minute)
	if err := sessions.Heartbeat(device.ID, device.UserID, DeviceTelemetry{}, later); err != nil {
		t.Fatal(err)
	}
	entries, err := store.NetworkDevices(network.UserID, network.ID)
	if err != nil || len(entries) != 1 {
		t.Fatal(err)
	}
	if entries[0].Version != "2.0.0" || entries[0].Platform != "linux" {
		t.Fatalf("empty report erased the stored build: %+v", entries[0])
	}
	if entries[0].LastSeen != later.Unix() {
		t.Fatalf("last seen not advanced: %d", entries[0].LastSeen)
	}
}

// Presence stays exact in memory while the durable value is throttled, so a
// burst of heartbeats must not produce a burst of writes.
func TestLastSeenPersistenceIsThrottled(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	device, _, _ := joinEnroll(t, store, network.ID, now)
	sessions := NewSessions(store)

	if err := sessions.Heartbeat(device.ID, device.UserID, DeviceTelemetry{}, now); err != nil {
		t.Fatal(err)
	}
	// Well inside the throttle window: durable last-seen must not move.
	soon := now.Add(10 * time.Second)
	if err := sessions.Heartbeat(device.ID, device.UserID, DeviceTelemetry{}, soon); err != nil {
		t.Fatal(err)
	}
	entries, _ := store.NetworkDevices(network.UserID, network.ID)
	if entries[0].LastSeen != now.Unix() {
		t.Fatalf("throttled write still hit the database: %d", entries[0].LastSeen)
	}
	// Presence itself is unthrottled and still exact.
	if sessions.Presence(device.ID, device.UserID, soon) != "online" {
		t.Fatal("throttling the write also delayed presence")
	}
	// Past the window the value becomes durable again.
	past := now.Add(persistedSeenInterval + time.Second)
	if err := sessions.Heartbeat(device.ID, device.UserID, DeviceTelemetry{}, past); err != nil {
		t.Fatal(err)
	}
	entries, _ = store.NetworkDevices(network.UserID, network.ID)
	if entries[0].LastSeen != past.Unix() {
		t.Fatalf("last seen never became durable: %d", entries[0].LastSeen)
	}
}

// Display strings must not be able to carry a payload or break a table.
func TestTelemetryRejectsUnusableStrings(t *testing.T) {
	store, _, _, now := newStore(t)
	network := fixtureNetwork(t, store)
	device, _, _ := joinEnroll(t, store, network.ID, now)
	sessions := NewSessions(store)

	for _, bad := range []DeviceTelemetry{
		{Version: strings.Repeat("v", 65)},
		{Platform: "line\nbreak"},
		{Architecture: " untrimmed"},
		{Version: "null\x00byte"},
	} {
		if err := sessions.Heartbeat(device.ID, device.UserID, bad, now); err != nil {
			t.Fatalf("heartbeat must survive a cosmetic refusal: %v", err)
		}
		entries, _ := store.NetworkDevices(network.UserID, network.ID)
		if entries[0].Version != "" || entries[0].Platform != "" || entries[0].Architecture != "" {
			t.Fatalf("unusable telemetry was stored: %+v", entries[0])
		}
	}
	// Liveness is still recorded even when the report is dropped.
	if sessions.Presence(device.ID, device.UserID, now) != "online" {
		t.Fatal("a rejected report took the device offline")
	}
}

// An unknown device cannot register presence at all.
func TestHeartbeatRejectsUnknownDevice(t *testing.T) {
	store, _, _, now := newStore(t)
	sessions := NewSessions(store)
	if err := sessions.Heartbeat(protocol.NewID(), "", DeviceTelemetry{}, now); err == nil {
		t.Fatal("unknown device accepted a heartbeat")
	}
}
