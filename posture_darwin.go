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

//go:build darwin

package main

import (
	"os/exec"
	"strings"
)

func hideWindow(cmd *exec.Cmd) {}

func collectPosture() *Posture {
	lock := strings.ToLower(runCommand("sysadminctl", "-screenLock", "status"))
	return &Posture{
		DiskEncrypted:     strings.Contains(runCommand("fdesetup", "status"), "FileVault is On"),
		FirewallEnabled:   strings.Contains(strings.ToLower(runCommand("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")), "enabled"),
		ScreenLockEnabled: lock != "" && !strings.Contains(lock, "off"),
		OsName:            "macOS",
		OsVersion:         runCommand("sw_vers", "-productVersion"),
	}
}
