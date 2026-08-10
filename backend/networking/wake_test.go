package networking

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
)

// WakeDevice consults getIp for the address of every ping attempt during
// its wait. The wait's outcome depends on the environment's ping
// privileges, so only the consultation itself is asserted.
func TestWakeDeviceConsultsGetIp(t *testing.T) {
	device := core.NewRecord(&core.Collection{})
	device.Set("name", "test")
	device.Set("ip", "127.0.0.2")
	device.Set("netmask", "255.255.255.0")
	device.Set("mac", "AA:BB:CC:DD:EE:0F")
	device.Set("wake_timeout", 1)

	calls := 0
	_ = WakeDevice(device, func() string {
		calls++
		return "127.0.0.2"
	})
	if calls == 0 {
		t.Error("Expected getIp to be consulted during the wake wait")
	}
}
