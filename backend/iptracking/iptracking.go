// Package iptracking updates the stored ip addresses of opted-in devices by
// scanning their local subnets for their mac addresses.
package iptracking

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/seriousm4x/upsnap/logger"
	"github.com/seriousm4x/upsnap/networking"
	"golang.org/x/sync/singleflight"
)

var sweepRunning atomic.Bool

// sweepOwed marks that a periodic sweep was skipped while no realtime
// clients were connected, so the next client to connect gets a catch-up
// sweep. Starts true so the first client after boot gets fresh ips.
var sweepOwed atomic.Bool

func init() {
	sweepOwed.Store(true)
}

// nmapScan is a seam for tests to stub out the privileged nmap invocation
var nmapScan = networking.NmapScan

// scanGroup joins concurrent scans of the same subnet into one nmap run
var scanGroup singleflight.Group

// wakeScanDelay gives a woken device time to boot and renew its dhcp lease
// before its subnet is scanned; a variable so tests can shorten it
var wakeScanDelay = 15 * time.Second

// TrackAllSubnets scans the local subnets of devices with ip tracking enabled
// and updates their ip address if their mac address is found at a different
// one. Non-scannable subnets are silently skipped, but their devices can
// still be updated by another subnet's scan that finds their mac address,
// as long as the new ip stays within the device's own subnet.
func TrackAllSubnets(app core.App) {
	// skip if the previous sweep is still running
	if !sweepRunning.CompareAndSwap(false, true) {
		return
	}
	defer sweepRunning.Store(false)

	devices, err := app.FindRecordsByFilter("devices", "track_ip = true", "", 0, 0)
	if err != nil {
		logger.Error.Println(err)
		return
	}

	// collect the unique scannable subnets of the tracked devices
	subnets := make(map[string]*net.IPNet)
	for _, device := range devices {
		subnet, err := networking.DeviceSubnet(device.GetString("ip"), device.GetString("netmask"))
		if err != nil {
			logger.Error.Println("Ip tracking for", device.GetString("name")+":", err)
			continue
		}
		if networking.ValidateScannableSubnet(subnet) != nil {
			continue
		}
		subnets[subnet.String()] = subnet
	}

	for cidr, subnet := range subnets {
		if err := TrackOneSubnet(app, subnet); err != nil {
			logger.Error.Println("Ip tracking scan for", cidr+":", err)
		}
	}
}

// PeriodicSweep runs the scheduled sweep, or skips it when paused — no
// realtime clients connected while lazy_ping is on — owing a catch-up
// sweep to the next client that connects.
func PeriodicSweep(app core.App, pause bool) {
	if pause {
		sweepOwed.Store(true)
		return
	}
	TrackAllSubnets(app)
}

// CatchUpSweep runs a sweep if one is owed, i.e. the periodic sweep was
// skipped while nobody was connected or hasn't run since boot. Clients
// connecting while sweeps run on schedule trigger nothing.
func CatchUpSweep(app core.App) {
	if !sweepOwed.CompareAndSwap(true, false) {
		return
	}
	TrackAllSubnets(app)
}

// TrackDeviceAfterWake schedules a scan of the device's subnet to pick up
// the ip address the device acquired while booting. Does nothing unless ip
// tracking is enabled globally and for the device.
func TrackDeviceAfterWake(app core.App, device *core.Record) {
	if !networking.DeviceTrackingEnabled(app, device) {
		return
	}
	subnet, err := networking.DeviceSubnet(device.GetString("ip"), device.GetString("netmask"))
	if err != nil {
		logger.Error.Println("Ip tracking for", device.GetString("name")+":", err)
		return
	}
	// the timer fires regardless of how the wake attempt ends and is not
	// cancelled on app shutdown: a scan is harmless when the device never
	// came up, and at worst runs once against a closing app
	time.AfterFunc(wakeScanDelay, func() {
		if err := TrackOneSubnet(app, subnet); err != nil {
			logger.Error.Println("Ip tracking scan for", subnet.String()+":", err)
		}
	})
}

// TrackOneSubnet runs an nmap scan of the given subnet and updates the ip
// address of any ip-tracked device whose mac address is found at a new
// address within its own subnet. Returns an error for a non-scannable subnet.
func TrackOneSubnet(app core.App, subnet *net.IPNet) error {
	if err := networking.ValidateScannableSubnet(subnet); err != nil {
		return err
	}

	// a caller whose subnet is already being scanned waits for that scan's
	// result instead of spawning another nmap run. The joined scan may have
	// started before the caller's trigger and miss a very recent change;
	// the periodic sweep covers that gap
	_, err, _ := scanGroup.Do(subnet.String(), func() (any, error) {
		return nil, scanSubnet(app, subnet)
	})
	return err
}

func scanSubnet(app core.App, subnet *net.IPNet) error {
	scan, err := nmapScan(subnet.String())
	if err != nil {
		return err
	}
	macToIp := scan.MacToIP()

	devices, err := app.FindRecordsByFilter("devices", "track_ip = true", "", 0, 0)
	if err != nil {
		return err
	}

	for _, device := range devices {
		parsedMac, err := net.ParseMAC(device.GetString("mac"))
		if err != nil {
			continue
		}
		newIp, ok := macToIp[parsedMac.String()]
		if !ok || newIp == device.GetString("ip") {
			continue
		}
		// only move a device within its own subnet, so that a scan can't
		// relocate devices tracked on other subnets that see the same mac
		deviceSubnet, err := networking.DeviceSubnet(device.GetString("ip"), device.GetString("netmask"))
		if err != nil || !deviceSubnet.Contains(net.ParseIP(newIp)) {
			continue
		}
		logger.Info.Println("Ip tracking: updating", device.GetString("name"), "from", device.GetString("ip"), "to", newIp)
		device.Set("ip", newIp)
		// only write the changed ip field to avoid clobbering concurrent
		// status updates from the ping and wake/shutdown cronjobs
		device.IgnoreUnchangedFields(true)
		if err := app.Save(device); err != nil {
			logger.Error.Println("Failed to save record:", err)
		}
	}
	return nil
}
