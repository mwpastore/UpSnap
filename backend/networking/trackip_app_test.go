package networking

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"

	// register the app migrations so test apps get the real schema
	_ "github.com/seriousm4x/upsnap/migrations"
)

// newTestApp returns a throwaway app with all migrations applied.
func newTestApp(t *testing.T) *tests.TestApp {
	t.Helper()
	app, err := tests.NewTestApp(t.TempDir())
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	t.Cleanup(app.Cleanup)
	return app
}

func newDevice(t *testing.T, app core.App, name, ip, mac string, trackIp bool) *core.Record {
	t.Helper()
	collection, err := app.FindCollectionByNameOrId("devices")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	device := core.NewRecord(collection)
	device.Set("name", name)
	device.Set("ip", ip)
	device.Set("netmask", "255.255.0.0")
	device.Set("mac", mac)
	device.Set("track_ip", trackIp)
	if err := app.Save(device); err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	return device
}

func newSettings(t *testing.T, app core.App, trackIpInterval string) *core.Record {
	t.Helper()
	collection, err := app.FindCollectionByNameOrId("settings_private")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	settings := core.NewRecord(collection)
	settings.Set("track_ip_interval", trackIpInterval)
	if err := app.SaveNoValidate(settings); err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	return settings
}

func TestDeviceTrackingEnabled(t *testing.T) {
	app := newTestApp(t)
	tracked := newDevice(t, app, "tracked", "127.0.0.50", "AA:BB:CC:DD:0B:01", true)
	untracked := newDevice(t, app, "untracked", "127.0.0.51", "AA:BB:CC:DD:0B:02", false)

	// without a settings record tracking is off
	if DeviceTrackingEnabled(app, tracked) {
		t.Error("Expected tracking to be disabled without a settings record")
	}

	// an empty interval disables tracking globally
	settings := newSettings(t, app, "")
	if DeviceTrackingEnabled(app, tracked) {
		t.Error("Expected tracking to be disabled with an empty interval")
	}

	// the global interval and the device toggle together enable tracking
	settings.Set("track_ip_interval", "@every 60s")
	if err := app.SaveNoValidate(settings); err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	if !DeviceTrackingEnabled(app, tracked) {
		t.Error("Expected tracking to be enabled")
	}
	if DeviceTrackingEnabled(app, untracked) {
		t.Error("Expected tracking to be disabled for a device without track_ip")
	}
}

func TestDeviceIPFunc(t *testing.T) {
	app := newTestApp(t)
	newSettings(t, app, "@every 60s")
	tracked := newDevice(t, app, "tracked", "127.0.0.50", "AA:BB:CC:DD:0C:01", true)
	untracked := newDevice(t, app, "untracked", "127.0.0.60", "AA:BB:CC:DD:0C:02", false)

	trackedIp := DeviceIPFunc(app, tracked)
	untrackedIp := DeviceIPFunc(app, untracked)
	if ip := trackedIp(); ip != "127.0.0.50" {
		t.Errorf("Ip mismatch: expected 127.0.0.50, got %s", ip)
	}
	if ip := untrackedIp(); ip != "127.0.0.60" {
		t.Errorf("Ip mismatch: expected 127.0.0.60, got %s", ip)
	}

	// change both ips in the database behind the records' backs
	for _, d := range []*core.Record{tracked, untracked} {
		fresh, err := app.FindRecordById("devices", d.Id)
		if err != nil {
			t.Fatalf("Got unexpected error: %v", err)
		}
		fresh.Set("ip", "127.0.9.9")
		if err := app.Save(fresh); err != nil {
			t.Fatalf("Got unexpected error: %v", err)
		}
	}

	// only the tracked device's getter follows the change
	if ip := trackedIp(); ip != "127.0.9.9" {
		t.Errorf("Ip mismatch: expected 127.0.9.9, got %s", ip)
	}
	if ip := untrackedIp(); ip != "127.0.0.60" {
		t.Errorf("Ip mismatch: expected 127.0.0.60, got %s", ip)
	}

	// a deleted device falls back to the last known ip
	fresh, err := app.FindRecordById("devices", tracked.Id)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	if err := app.Delete(fresh); err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	if ip := trackedIp(); ip != "127.0.9.9" {
		t.Errorf("Ip mismatch after delete: expected 127.0.9.9, got %s", ip)
	}
}
