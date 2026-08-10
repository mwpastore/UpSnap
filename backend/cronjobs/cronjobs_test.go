package cronjobs

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"

	// register the app migrations so test apps get the real schema
	_ "github.com/seriousm4x/upsnap/migrations"
)

// A failed scheduled wake must persist the revert to the pre-wake status.
// With IgnoreUnchangedFields set, that only works because the save baseline
// is refreshed after the intermediate pending write — otherwise the revert
// equals the load-time status and is dropped from the update, leaving the
// device wedged at "pending" and skipped by every cron from then on.
func TestWakeCronPersistsRevertedStatus(t *testing.T) {
	app, err := tests.NewTestApp(t.TempDir())
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	t.Cleanup(app.Cleanup)

	collection, err := app.FindCollectionByNameOrId("devices")
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	device := core.NewRecord(collection)
	device.Set("name", "wake-fails")
	device.Set("ip", "127.0.0.1")
	device.Set("netmask", "255.255.255.0")
	device.Set("mac", "AA:BB:CC:DD:0A:01")
	device.Set("status", "offline")
	device.Set("wake_cron", "0 0 * * *")
	device.Set("wake_cron_enabled", true)
	// the wake command fails immediately, the ping command reports offline
	device.Set("wake_cmd", "exit 1")
	device.Set("wake_timeout", 1)
	device.Set("ping_cmd", "exit 1")
	if err := app.Save(device); err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}

	SetWakeShutdownJobs(app)
	entries := CronWakeShutdown.Entries()
	if len(entries) != 1 {
		t.Fatalf("Expected one wake cron entry, got %d", len(entries))
	}
	entries[0].Job.Run()

	fresh, err := app.FindRecordById("devices", device.Id)
	if err != nil {
		t.Fatalf("Got unexpected error: %v", err)
	}
	if status := fresh.GetString("status"); status != "offline" {
		t.Errorf("Status mismatch: expected offline, got %s", status)
	}
}
