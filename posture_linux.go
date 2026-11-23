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

//go:build linux

package main

import (
	"os"
	"os/exec"
	"strings"
)

func hideWindow(cmd *exec.Cmd) {}

func readOsRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func isFirewallEnabled() bool {
	if strings.Contains(runCommand("ufw", "status"), "Status: active") {
		return true
	}
	if strings.TrimSpace(runCommand("firewall-cmd", "--state")) == "running" {
		return true
	}
	return strings.TrimSpace(runCommand("systemctl", "is-active", "nftables")) == "active"
}

func collectPosture() *Posture {
	return &Posture{
		DiskEncrypted:     strings.Contains(runCommand("lsblk", "-o", "TYPE"), "crypt"),
		FirewallEnabled:   isFirewallEnabled(),
		ScreenLockEnabled: strings.TrimSpace(runCommand("gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled")) == "true",
		OsName:            readOsRelease(),
		OsVersion:         runCommand("uname", "-r"),
	}
}
