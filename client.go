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
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

// response is the envelope of the Casdoor API
type response struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
	Data2  json.RawMessage `json:"data2"`
}

func readResponse(resp *http.Response) (*response, error) {
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	res := &response{}
	if err = json.Unmarshal(data, res); err != nil {
		return nil, fmt.Errorf("unexpected answer from Casdoor (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(data[:min(len(data), 200)])))
	}
	if res.Status != "ok" {
		return nil, errors.New(res.Msg)
	}
	return res, nil
}

type enrollResult struct {
	Device          string `json:"device"`
	EnrollCode      string `json:"enrollCode"`
	ExpireTime      string `json:"expireTime"`
	VerificationUri string `json:"verificationUri"`
}

func startEnrollment(server string, organization string, publicKey ed25519.PublicKey, name string, posture *Posture) (*enrollResult, error) {
	body, err := json.Marshal(map[string]interface{}{
		"organization": organization,
		"publicKey":    base64.StdEncoding.EncodeToString(publicKey),
		"displayName":  name,
		"platform":     posture.Platform,
		"agentVersion": Version,
		"posture":      posture,
	})
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Post(server+"/api/device/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	res, err := readResponse(resp)
	if err != nil {
		return nil, err
	}
	result := &enrollResult{}
	err = json.Unmarshal(res.Data, result)
	return result, err
}

// signedPost sends a request that the device signs with its key, as Casdoor's AuthenticateDeviceRequest expects
func signedPost(account *Account, path string, payload interface{}) (*response, error) {
	key, err := account.key()
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(body)
	message := "casdoor-device|" + account.Device + "|" + timestamp + "|" + hex.EncodeToString(sum[:])

	request, err := http.NewRequest(http.MethodPost, account.Server+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Casdoor-Device-Id", account.Device)
	request.Header.Set("X-Casdoor-Device-Timestamp", timestamp)
	request.Header.Set("X-Casdoor-Device-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(message))))
	resp, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	return readResponse(resp)
}

type deviceStatus struct {
	Status      string   `json:"status"`
	User        string   `json:"user"`
	IsCompliant bool     `json:"isCompliant"`
	Problems    []string `json:"problems"`
}

type devicePolicy struct {
	DeviceTrust      string `json:"deviceTrust"`
	RequireEncrypted bool   `json:"requireEncrypted"`
	RequireFirewall  bool   `json:"requireFirewall"`
	RequireLock      bool   `json:"requireLock"`
	Passwordless     bool   `json:"passwordless"`
}

func getDeviceStatus(account *Account) (*deviceStatus, *devicePolicy, error) {
	res, err := signedPost(account, "/api/device/status", map[string]string{})
	if err != nil {
		return nil, nil, err
	}
	return decodeStatus(res)
}

func reportPosture(account *Account, posture *Posture) (*deviceStatus, *devicePolicy, error) {
	res, err := signedPost(account, "/api/device/report", map[string]interface{}{"posture": posture, "agentVersion": Version})
	if err != nil {
		return nil, nil, err
	}
	return decodeStatus(res)
}

func decodeStatus(res *response) (*deviceStatus, *devicePolicy, error) {
	status := &deviceStatus{}
	policy := &devicePolicy{}
	if err := json.Unmarshal(res.Data, status); err != nil {
		return nil, nil, err
	}
	if len(res.Data2) > 0 {
		_ = json.Unmarshal(res.Data2, policy)
	}
	return status, policy, nil
}
