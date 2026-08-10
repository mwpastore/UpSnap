//go:build !linux

package networking

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/pocketbase/pocketbase/core"
	probing "github.com/prometheus-community/pro-bing"
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

		privileged := true // default to privileged ping, required by Windows
		if runtime.GOOS == "darwin" {
			// macOS pings will fail when using privileged ping as non root, but works with non-privileged.
			privileged = false
		}
		privilegedEnv := os.Getenv("UPSNAP_PING_PRIVILEGED")
		if privilegedEnv != "" {
			privileged, err = strconv.ParseBool(privilegedEnv)
			if err != nil {
				privileged = false
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
		if runtime.GOOS == "windows" {
			shell = "cmd"
			shell_arg = "/C"
		} else {
			shell = "/bin/sh"
			shell_arg = "-c"
		}

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
