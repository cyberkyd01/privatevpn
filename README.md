# Private VPN Pro

Members-only personal VPN gateways. Install Private VPN Pro on your computers and phone; switch on **Gateway mode** on any Windows, macOS or Linux computer and every other Private VPN Pro device can route its Internet traffic through that computer's connection.

* **Discoverable, but locked.** Every Private VPN Pro device on the LAN sees every gateway. Connecting needs that gateway's **network key** — entered (or scanned as a QR code) **once** per network, then remembered.
* **Rich gateway details.** Tap ⓘ on a gateway to see its country, region, city, latitude/longitude (approximate, from IP), current public IP (refreshed when it changes), ISP, time zone and its live local time — visible only to key holders.
* **Clients leave no trace.** A connecting device presents a fresh, random WireGuard key per session and nothing else. Gateways keep client state in memory only — no logs, no files.
* **Tray only.** On desktops Private VPN Pro lives in the system tray (no window, no Dock/taskbar icon); its interface is a local web page opened from the tray.
* Built on **WireGuard** (wireguard-go). The gateway runs entirely in userspace (gVisor netstack) — no admin rights or OS routing changes needed to share a connection.

| | Gateway | Client |
|---|---|---|
| Windows 10/11 | ✅ | ✅ (asks for admin when connecting) |
| macOS 11+ | ✅ | ✅ (asks for admin password when connecting) |
| Linux | ✅ | ✅ (polkit prompt, or `setcap cap_net_admin+ep`) |
| Android 8+ | — (client only) | ✅ |

## Install

Download from the [Releases](../../releases) page and check the file against `SHA256SUMS`.

### Windows
1. Run `private-vpn-pro-windows-amd64-setup.exe` (Windows on Arm: `private-vpn-pro-windows-arm64-setup.exe`). Builds are not code-signed yet: on the SmartScreen prompt choose **More info → Run anyway**, then accept the administrator prompt. The installer puts Private VPN Pro in `Program Files`, adds the Windows Firewall rules and starts it.
2. A shield icon appears in the tray (it may hide under the **^** arrow). Click it → **Open Private VPN Pro**.

Portable alternative: unzip `private-vpn-pro-windows-amd64.zip` and run `private-vpn-pro.exe` (keep it next to `wintun.dll`). Moving from the portable copy to the installer, **Disconnect** and **Quit** the portable one first. Uninstall from **Settings → Apps → Private VPN Pro**; this also removes the kill-switch block and the firewall rules.

### Android
1. Copy `private-vpn-pro-android.apk` to the phone and open it (allow "Install unknown apps" for your file manager/browser when asked).
2. Open Private VPN Pro: gateways on your Wi-Fi appear automatically.

### macOS
Open `private-vpn-pro-macos-universal.dmg` and drag **Private VPN Pro** to **Applications**. The build is ad-hoc signed, not notarised, so the first time right-click it → **Open** (macOS 15 and later: open it once, then **System Settings → Privacy & Security → Open Anyway**). The icon appears in the menu bar.

### Linux
Extract `private-vpn-pro-linux-<arch>.tar.gz` and run `./private-vpn-pro` (needs a StatusNotifier tray host, e.g. KDE or GNOME with the AppIndicator extension; otherwise run `./private-vpn-pro --no-tray` and open the printed URL). Install `app.privatevpnpro.policy` to `/usr/share/polkit-1/actions/` for a friendly password prompt.

## Quick start: Windows gateway, Android phone

1. **Windows:** tray icon → **Open Private VPN Pro** → **Gateway mode** → switch on. A network key is created automatically. The installer already added the Windows Firewall rule (UDP only; on networks Windows calls "Public", which is most home Wi-Fi, only devices on your local network are admitted); with the portable zip, Windows asks for administrator approval to add it the first time.
2. Still on Windows: **Networks** → your network → **Show key** — a QR code and the key text (`PVP1-…`) are displayed.
3. **Android:** open Private VPN Pro. The Windows PC appears in the list with a 🔒. Tap **Connect** → **Scan QR code** (or paste the key). The key is checked instantly against the gateway's announcement and saved — you won't be asked again for this network.
4. Android asks once to allow the VPN connection. Accept. You're connected: the status card shows the gateway, your tunnel address and traffic.
5. Tap **ⓘ** on the gateway to see its location, public IP, time zone and live local time.
6. Recommended: in Android **Settings → VPN → Private VPN Pro ⚙** turn on **Always-on VPN** and **Block connections without VPN** so the phone never leaks your IP, even after a restart (see *Leak protection* below).

Both devices must be on the same network (Wi-Fi/LAN), and the router must not isolate Wi-Fi clients from each other (guest networks usually do). On a Windows PC used only as a *client*, allow Private VPN Pro when Windows Firewall asks the first time (or use **Gateway mode → Add firewall rule** once) so it can discover gateways. To use a gateway from outside, forward UDP **51820** and **51821** on the gateway's router to the gateway PC and add it on the client with **Add gateway by address**. Phones on mobile data cannot be gateways (Android is client-only).

## Leak protection (kill switch) and restarts

Once you connect, Private VPN Pro **fails closed**: if anything goes wrong your traffic is blocked rather than sent with your real IP address.

| What happens | Result |
|---|---|
| Gateway PC switched off, asleep, or loses Wi-Fi | Traffic is held inside the tunnel ("Connection interrupted — traffic held"); Private VPN Pro reconnects by itself when the gateway is back. |
| Private VPN Pro or its tunnel helper crashes | The operating-system block stays in place ("Internet blocked to protect your IP"). Reconnect, or Disconnect to use the Internet without the VPN. |
| Computer restarts while connected | The block is active from boot, Private VPN Pro starts at login and reconnects to the same gateway (your OS asks once for administrator approval). |
| You press **Disconnect** or **Quit** | The tunnel and the block are removed; direct Internet access returns. |

The **Problems** panel at the top of the Private VPN Pro page (and in the tray menu / the Android app) lists everything that is wrong in plain words, with a button to fix it — for example a blocked connection, IPv6 or DNS that could not be protected, a missing Windows firewall rule, or the kill switch being off. The kill switch can be turned off in **Settings** (not recommended).

**Android:** the system itself must enforce the block when the app is not running. Open **Settings → Network & internet → VPN → Private VPN Pro ⚙** and turn on **Always-on VPN** and **Block connections without VPN** (Private VPN Pro shows a warning and a shortcut until you do). Then the phone is protected from the moment it boots.

**Getting your Internet back if Private VPN Pro cannot start:** the block deliberately survives restarts. Run the recovery command as administrator:

* Windows (Administrator Command Prompt): `"%ProgramFiles%\Private VPN Pro\recovery\private-vpn-pro.exe" unblock`
* macOS: `sudo "/Library/Application Support/Private VPN Pro/bin/private-vpn-pro" unblock`
* Linux: `sudo /var/lib/private-vpn-pro/bin/private-vpn-pro unblock`

Always **Disconnect** before deleting Private VPN Pro.

## Security model (short)

* One secret per network: the **network key** (256-bit). Anyone holding it can use your gateways, so share it only with your own devices or people you trust with your Internet connection. Revoke access by **Reset key** on the gateway (members re-enter the new key).
* Discovery beacons are public (name, OS, version, client count) and carry an HMAC tag only key holders can verify. Everything else — details, joining, the tunnel — is authenticated and encrypted (XChaCha20-Poly1305 control messages, WireGuard with a network-wide preshared key).
* Gateways forward clients' traffic to the Internet only; they never let clients reach the gateway computer itself, and they block your LAN unless you enable **Allow my local network**.
* Members' traffic exits with the gateway's public IP.
* The local web interface listens on `127.0.0.1` only and requires a one-time login link from the tray (protection against DNS rebinding, CSRF and other local users).

Full design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Building

Requirements: Go 1.27+, for Android the Android SDK + NDK 27/28 and JDK 21.

```sh
make test       # unit + integration tests
make windows    # dist/windows-*/private-vpn-pro.exe (+ wintun.dll, hash-verified)
make windows-installer  # dist/private-vpn-pro-windows-*-setup.exe (needs makensis)
make linux
make macos      # dist/macos/Private VPN Pro.app (run on a Mac)
make dmg        # dist/private-vpn-pro-macos-universal.dmg
make android    # dist/android/private-vpn-pro-android.apk
```

Releases are built by GitHub Actions on `v*` tags (`.github/workflows/release.yml`).

## License

Private VPN Pro is released under the MIT License (see `LICENSE`). Wintun is © WireGuard LLC and distributed under its own license (`WINTUN-LICENSE.txt` in the Windows zip).
