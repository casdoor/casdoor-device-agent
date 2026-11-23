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
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sync"
)

// Account is the enrollment of this device with one organization of one Casdoor
type Account struct {
	Server       string `json:"server"`
	Organization string `json:"organization"`
	Device       string `json:"device"`
	PrivateKey   string `json:"privateKey"`
	User         string `json:"user"`
	DisplayName  string `json:"displayName"`
	Status       string `json:"status"`
	Passwordless bool   `json:"passwordless"`
	// the other origins that may ask for an assertion, such as a sign-in page served from another host than the API
	ExtraOrigins []string `json:"extraOrigins,omitempty"`
}

func (account *Account) key() (ed25519.PrivateKey, error) {
	data, err := base64.StdEncoding.DecodeString(account.PrivateKey)
	if err != nil || len(data) != ed25519.PrivateKeySize {
		return nil, errors.New("the device key is broken, enroll the device again")
	}
	return data, nil
}

func (account *Account) origins() []string {
	res := []string{}
	if origin := getOrigin(account.Server); origin != "" {
		res = append(res, origin)
	}
	for _, item := range account.ExtraOrigins {
		if origin := getOrigin(item); origin != "" {
			res = append(res, origin)
		}
	}
	return res
}

func getOrigin(address string) string {
	u, err := url.Parse(address)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

type State struct {
	Accounts []*Account `json:"accounts"`
}

var stateLock sync.Mutex

func getStatePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "casdoor-device-agent", "state.json"), nil
}

func loadState() (*State, error) {
	path, err := getStatePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{Accounts: []*Account{}}, nil
	}
	if err != nil {
		return nil, err
	}
	state := &State{}
	if err = json.Unmarshal(data, state); err != nil {
		return nil, err
	}
	return state, nil
}

// saveState writes the state readable only by the user, it holds the private keys of the device
func saveState(state *State) error {
	path, err := getStatePath()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (state *State) find(server string, organization string) *Account {
	for _, account := range state.Accounts {
		if getOrigin(account.Server) == getOrigin(server) && account.Organization == organization {
			return account
		}
	}
	return nil
}

func (state *State) findDevice(device string) *Account {
	for _, account := range state.Accounts {
		if account.Device == device {
			return account
		}
	}
	return nil
}
