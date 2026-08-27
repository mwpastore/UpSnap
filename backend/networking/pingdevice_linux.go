//go:build linux

package networking

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/pocketbase/pocketbase/core"
	probing "github.com/prometheus-community/pro-bing"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// PingDevice reports whether the device answers a ping. getIp is called for
// the address to ping, so it can follow ip changes written by concurrent
// tracking scans (see DeviceIPFunc); a nil getIp pings the record's ip. A
// custom ping_cmd runs verbatim and ignores the ip either way.
func PingDevice(device *core.Record, getIp func() string) (bool, error) {
	ping_cmd := device.GetString("ping_cmd")
	if ping_cmd == "" {
		ip := device.GetString("ip")
		if getIp != nil {
			ip = getIp()
		}
		pinger, err := probing.NewPinger(ip)
		if err != nil {
			return false, err
		}
		pinger.Count = 1
		pinger.Timeout = 500 * time.Millisecond

		privileged := true
		privilegedEnv := os.Getenv("UPSNAP_PING_PRIVILEGED")
		if privilegedEnv != "" {
			privileged, err = strconv.ParseBool(privilegedEnv)
			if err != nil {
				privileged = false
			}
		}
		if privileged {
			orig := cap.GetProc()
			defer orig.SetProc() // restore original caps on exit.

			c, err := orig.Dup()
			if err != nil {
				return false, fmt.Errorf("Failed to dup existing capabilities: %v", err)
			}

			if on, _ := c.GetFlag(cap.Permitted, cap.NET_RAW); !on {
				return false, fmt.Errorf("Privileged ping selected but NET_RAW capability not permitted")
			}

			if err := c.SetFlag(cap.Effective, true, cap.NET_RAW); err != nil {
				return false, fmt.Errorf("unable to set NET_RAW capability")
			}

			if err := c.SetProc(); err != nil {
				return false, fmt.Errorf("unable to raise NET_RAW capability")
			}
		}
		pinger.SetPrivileged(privileged)

		err = pinger.Run()
		if err != nil {
			if isNoRouteOrDownError(err) {
				return false, nil
			}
			return false, err
		}
		stats := pinger.Statistics()
		return stats.PacketLoss == 0, nil
	} else {
		var shell string
		var shell_arg string

		shell = "/bin/sh"
		shell_arg = "-c"

		cmd := exec.Command(shell, shell_arg, ping_cmd)
		err := cmd.Run()

		if err != nil {
			if _, ok := err.(*exec.ExitError); ok {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
}
