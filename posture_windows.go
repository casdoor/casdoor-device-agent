// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func readRegistryString(root registry.Key, path string, name string) string {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}

func readRegistryInt(root registry.Key, path string, name string) uint64 {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue(name)
	if err != nil {
		return 0
	}
	return value
}

// isSystemDriveEncrypted reads the BitLocker protection of the system drive from the shell, which a standard user
// may do, unlike manage-bde: 1 is on, 3 is encrypting, 6 is on and locked
func isSystemDriveEncrypted() bool {
	drive := os.Getenv("SystemDrive")
	if drive == "" {
		drive = "C:"
	}
	script := fmt.Sprintf("(New-Object -ComObject Shell.Application).NameSpace('%s').Self.ExtendedProperty('System.Volume.BitLockerProtection')", drive)
	output := runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	switch strings.TrimSpace(output) {
	case "1", "3", "6":
		return true
	}
	return false
}

// isFirewallEnabled needs every profile of the Windows firewall on
func isFirewallEnabled() bool {
	output := runCommand("netsh", "advfirewall", "show", "allprofiles", "state")
	if output == "" {
		return false
	}
	on, off := 0, 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToUpper(fields[len(fields)-1]) {
		case "ON":
			on++
		case "OFF":
			off++
		}
	}
	return on > 0 && off == 0
}

// isScreenLockEnabled takes a machine inactivity lock, or a screen saver that asks for the password
func isScreenLockEnabled() bool {
	if readRegistryInt(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "InactivityTimeoutSecs") > 0 {
		return true
	}
	for _, path := range []string{`Software\Policies\Microsoft\Windows\Control Panel\Desktop`, `Control Panel\Desktop`} {
		active := readRegistryString(registry.CURRENT_USER, path, "ScreenSaveActive")
		secure := readRegistryString(registry.CURRENT_USER, path, "ScreenSaverIsSecure")
		if active == "1" && secure == "1" {
			return true
		}
	}
	return false
}

func collectPosture() *Posture {
	const versionPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	name := readRegistryString(registry.LOCAL_MACHINE, versionPath, "ProductName")
	build := readRegistryString(registry.LOCAL_MACHINE, versionPath, "CurrentBuild")
	display := readRegistryString(registry.LOCAL_MACHINE, versionPath, "DisplayVersion")
	// Windows 11 still names itself Windows 10 in ProductName
	if buildNumber := atoi(build); buildNumber >= 22000 {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	return &Posture{
		DiskEncrypted:     isSystemDriveEncrypted(),
		FirewallEnabled:   isFirewallEnabled(),
		ScreenLockEnabled: isScreenLockEnabled(),
		OsName:            name,
		OsVersion:         strings.TrimSpace(display + " " + build),
	}
}

func atoi(text string) int {
	n := 0
	for _, r := range text {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}
