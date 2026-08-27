//go:build linux

package networking

import (
	"fmt"
	"sync"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// nmapMu serializes scans: raising and restoring NET_RAW mutates
// process-wide state, so concurrent scans would race the capability
// dance and could leave it raised for unrelated child processes
var nmapMu sync.Mutex

func NmapScan(scanRange string) (Nmaprun, error) {
	nmapMu.Lock()
	defer nmapMu.Unlock()

	orig := cap.GetProc()
	defer orig.SetProc() // restore original caps on exit.

	c, err := orig.Dup()
	if err != nil {
		return Nmaprun{}, fmt.Errorf("Failed to dup existing capabilities: %v", err)
	}

	if on, _ := c.GetFlag(cap.Permitted, cap.NET_RAW); !on {
		return Nmaprun{}, fmt.Errorf("unable to get NET_RAW permissions")
	}

	if err := c.SetFlag(cap.Effective, true, cap.NET_RAW); err != nil {
		return Nmaprun{}, fmt.Errorf("unable to set NET_RAW capability effective")
	}

	if err := c.SetFlag(cap.Inheritable, true, cap.NET_RAW); err != nil {
		return Nmaprun{}, fmt.Errorf("unable to set NET_RAW capability inheritable")
	}

	if err := c.SetProc(); err != nil {
		return Nmaprun{}, fmt.Errorf("unable to raise NET_RAW capability")
	}

	if err := cap.SetAmbient(true, cap.NET_RAW); err != nil {
		return Nmaprun{}, fmt.Errorf("unable to set NET_RAW capability ambient")
	}

	return runNmap(scanRange)
}
