# Casdoor device agent

The device agent of [Casdoor](https://github.com/casdoor/casdoor) device trust. It enrolls a computer with a Casdoor
organization, reports the security posture of the computer, and lets the Casdoor sign-in page prove that a sign-in
comes from this computer, or sign in without a password from it.

An admin turns device trust on in the "Device trust" tab of the organization, and sees and approves the devices on
the "Devices" page. When the organization also uses adaptive risk (Casdoor commercial edition), an untrusted device
counts as a risk of the sign-in.

## How it works

- `enroll` creates an Ed25519 key pair on the computer and registers the public key with Casdoor. It shows a code that
  the user enters at `/device-enroll` of Casdoor while signed in, which binds the device to the user.
- `run` listens on `127.0.0.1:47630`, answers only the pages of the Casdoor it enrolled with, and reports the posture
  every 15 minutes. When the sign-in page asks, it signs a one-time challenge of Casdoor together with the origin of
  the page and the posture checked right then. Casdoor checks the signature, the device, its owner and the posture.
- The private key stays in the state file in the user's config directory, readable only by the user.

The posture is:

| | Windows | macOS | Linux |
|---|---|---|---|
| Disk encryption | BitLocker on the system drive | FileVault | a `crypt` device in `lsblk` |
| Firewall | every profile of Windows Firewall | the application firewall | ufw, firewalld or nftables |
| Screen lock | inactivity lock policy or a secure screen saver | `sysadminctl -screenLock` | GNOME `lock-enabled` |

## Usage

```
casdoor-device-agent enroll --server https://door.example.com --organization acme
casdoor-device-agent install    # start at login: the Run key on Windows, a LaunchAgent on macOS, autostart on Linux
casdoor-device-agent run        # or start it now
casdoor-device-agent status
casdoor-device-agent unenroll --server https://door.example.com --organization acme
```

`--server` is the address of Casdoor as the browser opens it. When the sign-in page is served from another origin than
`--server`, add that origin to `extraOrigins` of the account in the state file.

Chrome asks the user once whether the Casdoor site may reach devices on the local network, the agent being one.

## Build

```
go build -o casdoor-device-agent .
```

Pushing a `v*` tag builds the binaries for Windows, macOS and Linux and publishes them in a GitHub release.

## License

Apache-2.0
