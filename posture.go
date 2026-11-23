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

package main

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Posture is the security state of the computer, as Casdoor's DevicePosture has it
type Posture struct {
	DiskEncrypted     bool   `json:"diskEncrypted"`
	FirewallEnabled   bool   `json:"firewallEnabled"`
	ScreenLockEnabled bool   `json:"screenLockEnabled"`
	OsName            string `json:"osName"`
	OsVersion         string `json:"osVersion"`
	Hostname          string `json:"hostname"`
	Platform          string `json:"-"`
}

var (
	postureCache     *Posture
	postureCacheTime time.Time
	postureLock      sync.Mutex
)

// getPosture checks the computer, at most once a minute since some checks start other programs
func getPosture() *Posture {
	postureLock.Lock()
	defer postureLock.Unlock()
	if postureCache != nil && time.Since(postureCacheTime) < time.Minute {
		return postureCache
	}
	posture := collectPosture()
	posture.Platform = runtime.GOOS
	if posture.Hostname == "" {
		posture.Hostname, _ = os.Hostname()
	}
	postureCache, postureCacheTime = posture, time.Now()
	return posture
}

// runCommand returns the combined output of a command, "" when it can't run within 10 seconds
func runCommand(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hideWindow(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) == 0 {
		return ""
	}
	return strings.TrimSpace(string(output))
}
