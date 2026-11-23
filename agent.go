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
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ListenAddress is where the sign-in page finds the agent, only on the loopback interface
const ListenAddress = "127.0.0.1:47630"

const reportInterval = 15 * time.Minute

func openBrowser(address string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", address)
	case "darwin":
		cmd = exec.Command("open", address)
	default:
		cmd = exec.Command("xdg-open", address)
	}
	_ = cmd.Start()
}

func enroll(server string, organization string, name string, browser bool) error {
	if getOrigin(server) == "" || organization == "" {
		return errors.New("--server (such as https://door.example.com) and --organization are required")
	}
	posture := getPosture()
	if name == "" {
		name = posture.Hostname
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	result, err := startEnrollment(server, organization, publicKey, name, posture)
	if err != nil {
		return err
	}

	account := &Account{
		Server:       server,
		Organization: organization,
		Device:       result.Device,
		PrivateKey:   base64.StdEncoding.EncodeToString(privateKey),
		DisplayName:  name,
		Status:       "Enrolling",
	}
	address := server + result.VerificationUri
	fmt.Printf("To enroll this device, sign in to %s as yourself and enter the code:\n\n    %s\n\n%s\n\nWaiting for the approval", server, result.EnrollCode, address)
	if browser {
		openBrowser(address)
	}

	deadline := time.Now().Add(15 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		status, policy, err := getDeviceStatus(account)
		if err != nil {
			fmt.Print("!")
			continue
		}
		fmt.Print(".")
		if status.Status == "Enrolling" {
			continue
		}
		account.Status, account.User, account.Passwordless = status.Status, status.User, policy.Passwordless
		stateLock.Lock()
		state, err := loadState()
		if err == nil {
			if old := state.find(server, organization); old != nil {
				*old = *account
			} else {
				state.Accounts = append(state.Accounts, account)
			}
			err = saveState(state)
		}
		stateLock.Unlock()
		if err != nil {
			return err
		}
		fmt.Printf("\n\nEnrolled as %s, the device is %s.\n", account.User, strings.ToLower(account.Status))
		if status.Status != "Trusted" {
			fmt.Println("An administrator approves it before it is trusted.")
		}
		if len(status.Problems) > 0 {
			fmt.Printf("It doesn't meet the security requirements yet: %s\n", strings.Join(status.Problems, ", "))
		}
		fmt.Println("Run \"casdoor-device-agent install\" to start the agent at login, or \"casdoor-device-agent run\" now.")
		return nil
	}
	return errors.New("the enrollment code expired before it was approved")
}

func unenroll(server string, organization string) error {
	stateLock.Lock()
	defer stateLock.Unlock()
	state, err := loadState()
	if err != nil {
		return err
	}
	accounts := []*Account{}
	found := false
	for _, account := range state.Accounts {
		if getOrigin(account.Server) == getOrigin(server) && account.Organization == organization {
			found = true
			continue
		}
		accounts = append(accounts, account)
	}
	if !found {
		return errors.New("this device is not enrolled with that organization")
	}
	state.Accounts = accounts
	if err = saveState(state); err != nil {
		return err
	}
	fmt.Println("The device key is deleted. An administrator can remove the device from the Devices page of Casdoor.")
	return nil
}

func status() error {
	state, err := loadState()
	if err != nil {
		return err
	}
	posture := getPosture()
	fmt.Printf("This computer: %s, %s %s\n", posture.Hostname, posture.OsName, posture.OsVersion)
	fmt.Printf("  disk encrypted: %v, firewall: %v, screen lock: %v\n\n", posture.DiskEncrypted, posture.FirewallEnabled, posture.ScreenLockEnabled)
	if len(state.Accounts) == 0 {
		fmt.Println("Not enrolled with any organization.")
		return nil
	}
	for _, account := range state.Accounts {
		line := fmt.Sprintf("%s (%s): user %s", account.Server, account.Organization, account.User)
		status, _, err := getDeviceStatus(account)
		if err != nil {
			line += ", can't reach Casdoor: " + err.Error()
		} else {
			line += ", " + strings.ToLower(status.Status)
			if len(status.Problems) > 0 {
				line += ", missing: " + strings.Join(status.Problems, ", ")
			}
		}
		fmt.Println(line)
	}
	return nil
}

// reportAll sends the posture to every Casdoor this device is enrolled with and keeps what they answer
func reportAll() {
	stateLock.Lock()
	defer stateLock.Unlock()
	state, err := loadState()
	if err != nil {
		log.Printf("the state is not read: %s", err.Error())
		return
	}
	posture := getPosture()
	changed := false
	for _, account := range state.Accounts {
		status, policy, err := reportPosture(account, posture)
		if err != nil {
			log.Printf("the posture is not reported to %s: %s", account.Server, err.Error())
			continue
		}
		if account.Status != status.Status || account.User != status.User || account.Passwordless != policy.Passwordless {
			account.Status, account.User, account.Passwordless = status.Status, status.User, policy.Passwordless
			changed = true
		}
	}
	if changed {
		if err = saveState(state); err != nil {
			log.Printf("the state is not saved: %s", err.Error())
		}
	}
}

func run() error {
	go func() {
		for {
			reportAll()
			time.Sleep(reportInterval)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/probe", handleProbe)
	mux.HandleFunc("/v1/assert", handleAssert)
	server := &http.Server{Addr: ListenAddress, Handler: withCors(mux), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("Casdoor device agent %s listening on %s", Version, ListenAddress)
	return server.ListenAndServe()
}

// findAccountsForOrigin returns the accounts whose Casdoor the page of the origin belongs to
func findAccountsForOrigin(origin string) []*Account {
	state, err := loadState()
	if err != nil || origin == "" {
		return nil
	}
	res := []*Account{}
	for _, account := range state.Accounts {
		for _, item := range account.origins() {
			if strings.EqualFold(item, origin) {
				res = append(res, account)
				break
			}
		}
	}
	return res
}

// withCors answers only the pages of the Casdoor this device enrolled with, and allows a public page to reach the
// loopback address (Private Network Access)
func withCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || len(findAccountsForOrigin(origin)) == 0 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
		w.Header().Set("Access-Control-Max-Age", "600")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJson(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type probeAccount struct {
	Server       string `json:"server"`
	Organization string `json:"organization"`
	Device       string `json:"device"`
	User         string `json:"user"`
	DisplayName  string `json:"displayName"`
	Status       string `json:"status"`
	Passwordless bool   `json:"passwordless"`
}

func handleProbe(w http.ResponseWriter, r *http.Request) {
	accounts := []probeAccount{}
	for _, account := range findAccountsForOrigin(r.Header.Get("Origin")) {
		accounts = append(accounts, probeAccount{
			Server:       account.Server,
			Organization: account.Organization,
			Device:       account.Device,
			User:         account.User,
			DisplayName:  account.User,
			Status:       account.Status,
			Passwordless: account.Passwordless,
		})
	}
	writeJson(w, http.StatusOK, map[string]interface{}{"version": Version, "accounts": accounts})
}

// handleAssert signs the challenge of the sign-in page: "casdoor-device|<device>|<origin>|<nonce>|<timestamp>|<sha256
// of the posture JSON>", with the posture checked now
func handleAssert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJson(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var form struct {
		Device string `json:"device"`
		Nonce  string `json:"nonce"`
	}
	data, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err := json.Unmarshal(data, &form); err != nil || form.Nonce == "" || len(form.Nonce) > 200 {
		writeJson(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}

	origin := r.Header.Get("Origin")
	var account *Account
	for _, item := range findAccountsForOrigin(origin) {
		if form.Device == "" || item.Device == form.Device {
			account = item
			break
		}
	}
	if account == nil {
		writeJson(w, http.StatusNotFound, map[string]string{"error": "not enrolled for this site"})
		return
	}
	key, err := account.key()
	if err != nil {
		writeJson(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	posture, _ := json.Marshal(getPosture())
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(posture)
	message := strings.Join([]string{"casdoor-device", account.Device, origin, form.Nonce, timestamp, hex.EncodeToString(sum[:])}, "|")
	assertion, _ := json.Marshal(map[string]string{
		"device":    account.Device,
		"origin":    origin,
		"nonce":     form.Nonce,
		"timestamp": timestamp,
		"posture":   string(posture),
		"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(message))),
	})
	writeJson(w, http.StatusOK, map[string]string{"assertion": base64.StdEncoding.EncodeToString(assertion)})
}

func init() {
	log.SetOutput(os.Stderr)
}
