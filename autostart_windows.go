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

	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// installAutostart starts the agent at the user's login from the per-user Run key, no administrator needed
func installAutostart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	// the headless console host runs the console program without a window
	if err = key.SetStringValue("CasdoorDeviceAgent", fmt.Sprintf(`conhost.exe --headless "%s" run`, exe)); err != nil {
		return err
	}
	fmt.Println("The agent starts at login.")
	return nil
}

func uninstallAutostart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if err = key.DeleteValue("CasdoorDeviceAgent"); err != nil && err != registry.ErrNotExist {
		return err
	}
	fmt.Println("The agent no longer starts at login.")
	return nil
}
