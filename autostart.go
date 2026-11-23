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

//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func getAutostartPath() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	exe, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	if runtime.GOOS == "darwin" {
		path := filepath.Join(home, "Library", "LaunchAgents", "org.casdoor.device-agent.plist")
		content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>org.casdoor.device-agent</string>
  <key>ProgramArguments</key><array><string>%s</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
`, exe)
		return path, content, nil
	}
	path := filepath.Join(home, ".config", "autostart", "casdoor-device-agent.desktop")
	content := fmt.Sprintf("[Desktop Entry]\nType=Application\nName=Casdoor device agent\nExec=%s run\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n", exe)
	return path, content, nil
}

func installAutostart() error {
	path, content, err := getAutostartPath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err = os.WriteFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	fmt.Printf("The agent starts at login (%s).\n", path)
	return nil
}

func uninstallAutostart() error {
	path, _, err := getAutostartPath()
	if err != nil {
		return err
	}
	if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Println("The agent no longer starts at login.")
	return nil
}
