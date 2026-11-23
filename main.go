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
	"flag"
	"fmt"
	"os"
	"strings"
)

const Version = "0.1.0"

func usage() {
	fmt.Fprintf(os.Stderr, `Casdoor device agent %s

Enrolls this computer with a Casdoor organization that uses device trust, reports its security posture, and signs
the sign-ins of the Casdoor sign-in page in the browser.

Usage:
  casdoor-device-agent enroll --server https://door.example.com --organization acme [--name "My laptop"]
  casdoor-device-agent run                 serve the sign-in page and report the posture, normally started at login
  casdoor-device-agent status              show the enrolled accounts and the posture of this computer
  casdoor-device-agent unenroll --server https://door.example.com --organization acme
  casdoor-device-agent install             start the agent at login (and uninstall to stop that)
`, Version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ExitOnError)
		server := fs.String("server", "", "the address of Casdoor, as the browser opens it")
		organization := fs.String("organization", "", "the organization to enroll with")
		name := fs.String("name", "", "the name of this device, the host name by default")
		noBrowser := fs.Bool("no-browser", false, "don't open the browser, only print the address")
		_ = fs.Parse(os.Args[2:])
		err = enroll(strings.TrimRight(*server, "/"), *organization, *name, !*noBrowser)
	case "run":
		err = run()
	case "status":
		err = status()
	case "unenroll":
		fs := flag.NewFlagSet("unenroll", flag.ExitOnError)
		server := fs.String("server", "", "the address of Casdoor")
		organization := fs.String("organization", "", "the organization")
		_ = fs.Parse(os.Args[2:])
		err = unenroll(strings.TrimRight(*server, "/"), *organization)
	case "install":
		err = installAutostart()
	case "uninstall":
		err = uninstallAutostart()
	case "version", "--version", "-v":
		fmt.Println(Version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
