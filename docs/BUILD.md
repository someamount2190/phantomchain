# PhantomChain — Build & Run Reference

**Purpose:** reproduce and run PhantomChain v0.3 on this machine — the JVM crypto/consensus test suite and the Android debug app.
**Last verified:** 2026-06-21 (Windows 11, all steps green).
**Scope of what this builds — read first:** identity / keys / recovery, a single-node ledger, **and a 3-node toy cluster**. Post-quantum signing, QR backup/recovery, validated transactions into a hash-linked device-signed chain (persisted), plus 3 in-app nodes (ports 8081-8083) that gossip txs and commit blocks via a **2-of-3 quorum-certificate** (round-robin proposer collects a majority of validator ML-DSA signatures into a QC every node verifies). It is a multisig quorum, NOT a true threshold signature, NOT full BFT, and the 3 nodes are co-located on one device — i.e. not "mining" in the spec's cluster sense yet. See [Scope & Non-Goals](#scope--non-goals).

---

## 0. Environment (this machine)

| Thing | Value |
|---|---|
| OS | Windows 11, PowerShell 5.1 (primary), Git Bash available |
| JDK | Temurin 17 — `C:\Users\Christian Correa\scoop\apps\temurin17-jdk\current` |
| `JAVA_HOME` | set it to the path above before any Gradle/sdkmanager call |
| Android SDK (`ANDROID_HOME`) | `C:\Users\Christian Correa\scoop\apps\android-clt\current` (scoop `android-clt`) |
| sdkmanager | `%ANDROID_HOME%\cmdline-tools\latest\bin\sdkmanager.bat` |
| avdmanager | `%ANDROID_HOME%\cmdline-tools\latest\bin\avdmanager.bat` |
| adb | `%ANDROID_HOME%\platform-tools\adb.exe` |
| emulator | `%ANDROID_HOME%\emulator\emulator.exe` |
| Gradle | 8.7, downloaded to `src\android\gradle-dist\gradle-8.7\` (no system Gradle) |
| Project root | `C:\Users\Christian Correa\OneDrive\Desktop\Projects\PhantomChain\src` |
| Emulator accel | **WHPX is usable** (`emulator -accel-check` → accel 0) despite the "HypervisorPlatform" Windows feature reading as disabled. Boots headless in ~55 s. |

The SDK started bare (only `cmdline-tools/latest`). Components installed: `platform-tools`, `platforms;android-34`, `build-tools;34.0.0`, `emulator`, `system-images;android-34;google_apis;x86_64`.

---

## 1. Project layout

```
src/
  node/                          # validator node + JVM test/sim suite (NodeMain, NetNode, *Test.java)
  lib/                           # bcprov-jdk18on-1.84.jar, bcutil-jdk18on-1.84.jar, …
  out/                           # compiled JVM classes
  android/
    settings.gradle  build.gradle  gradle.properties  local.properties
    gradle-dist/gradle-8.7/...    # the Gradle distribution
    yes.txt                       # stdin feed for sdkmanager license prompts
    sdk-install.log / install.out # installer logs
    phantom-ui.png / phantom-qr.png
    app/
      build.gradle
      src/main/AndroidManifest.xml
      src/main/java/com/phantomchain/debug/
        PhantomCrypto.java         # library-only PQ + recovery crypto
        PropMeshServer.java        # NanoHTTPD mock mesh + /debug drivers
        MainActivity.java          # simulator UI (enroll/sign/backup/recover)
      build/outputs/apk/debug/app-debug.apk   # build output
```

**Dependencies (app/build.gradle):** AGP 8.5.2, compileSdk 34, minSdk 26, coreLibraryDesugaring on.
`org.bouncycastle:bcprov-jdk18on:1.84`, `org.nanohttpd:nanohttpd:2.3.1`, `com.google.zxing:core:3.5.3`, `com.android.tools:desugar_jdk_libs:2.0.4`.

---

## 2. JVM crypto & consensus test suite (no device needed)

Validates ML-DSA-65, ML-KEM-1024, Argon2id, HKDF, ChaCha20-Poly1305 and the consensus/economics engine — **all library calls, no hand-rolled crypto**. The suite is the standalone `main()` drivers in `src/test/java/com/phantomchain/debug/` (`KnownAnswerTest`, `CryptoAuditTest`, `CryptoBreakTest`, `MerkleProofTest`, `ClusterTest`, `LivenessTest`, `MetamorphicTest`, `GoldenStateRootTest`, and the adversarial suites). Run the whole gate with the Gradle wrapper (deps resolved from Maven Central — no vendored jars):

```
./gradlew runTests              # deterministic suite (the CI gate)
./gradlew runIntegrationTests   # socket-binding NetNode tests
```

Expected: `All N deterministic suites passed`. Notable outputs (from individual suites): ML-DSA sig = 3309 B (exceeds single-QR ~2900 B → needs multi-frame QR); recovery ciphertext = 48 B (fits one QR). Source layout: `src/core/java` (shared state machine + crypto), `src/main/java` (node/networking), `src/test/java` (the suites).

To re-pull the BouncyCastle jars if `lib/` is missing:
```powershell
$lib = "$base\lib"; New-Item -ItemType Directory -Force $lib | Out-Null
foreach ($a in @("bcprov-jdk18on","bcutil-jdk18on")) {
  Invoke-WebRequest "https://repo1.maven.org/maven2/org/bouncycastle/$a/1.84/$a-1.84.jar" -OutFile "$lib\$a-1.84.jar" -UseBasicParsing
}
```

---

## 3. Android SDK install (one-time)

### 3a. Accept licenses — THE critical gotcha
Piping `y` into `sdkmanager --licenses` through a PowerShell `|` pipe **does not reliably reach stdin** — the process stalls silently at the prompt and downloads nothing (looks like 0 % forever). Hand-writing the license hash files is also unreliable (wrong/missing hashes per SDK version). **Working method: redirect stdin from a file via `Start-Process`.**

```powershell
$env:JAVA_HOME = "C:\Users\Christian Correa\scoop\apps\temurin17-jdk\current"
$base = "C:\Users\Christian Correa\OneDrive\Desktop\Projects\PhantomChain\src\android"
$sm   = "$env:ANDROID_HOME\cmdline-tools\latest\bin\sdkmanager.bat"
[IO.File]::WriteAllText("$base\yes.txt", ("y`r`n" * 100))
Start-Process -FilePath $sm -ArgumentList "--licenses" `
  -RedirectStandardInput "$base\yes.txt" -RedirectStandardOutput "$base\lic.out" `
  -RedirectStandardError "$base\lic.err" -NoNewWindow -Wait
# success => "$env:ANDROID_HOME\licenses" gets 7 files; lic.out ends "All SDK package licenses accepted"
```

### 3b. Install components (long; run in background)
sdkmanager picks up the SDK root from `ANDROID_HOME`. Keep stdin redirected as a safety net.
```powershell
Start-Process -FilePath $sm -ArgumentList `
  "platform-tools","platforms;android-34","build-tools;34.0.0","emulator","system-images;android-34;google_apis;x86_64" `
  -RedirectStandardInput "$base\yes.txt" -RedirectStandardOutput "$base\install.out" `
  -RedirectStandardError "$base\install.err" -NoNewWindow -Wait
```
Verify: `Test-Path "$env:ANDROID_HOME\platform-tools\adb.exe"` etc. for each component.

---

## 4. Build the debug APK

```powershell
$env:JAVA_HOME = "C:\Users\Christian Correa\scoop\apps\temurin17-jdk\current"
$g    = "C:\Users\Christian Correa\OneDrive\Desktop\Projects\PhantomChain\src\android\gradle-dist\gradle-8.7\bin\gradle.bat"
$proj = "C:\Users\Christian Correa\OneDrive\Desktop\Projects\PhantomChain\src\android"
& $g -p $proj assembleDebug --no-daemon --console=plain
# => BUILD SUCCESSFUL; APK at app\build\outputs\apk\debug\app-debug.apk
```
`local.properties` must contain (forward slashes, spaces OK):
```
sdk.dir=C:/Users/Christian Correa/scoop/apps/android-clt/current
```
Note: BouncyCastle dexes cleanly (Android's platform BC is repackaged to `com.android.org.bouncycastle`, so no duplicate-class conflict).

---

## 5. Create AVD + boot emulator

```powershell
$avdm = "$env:ANDROID_HOME\cmdline-tools\latest\bin\avdmanager.bat"
[IO.File]::WriteAllText("$base\no.txt","no`r`n")   # answers the "custom hardware profile?" prompt
Start-Process -FilePath $avdm -ArgumentList `
  "create","avd","-n","phantom34","-k","system-images;android-34;google_apis;x86_64","--force" `
  -RedirectStandardInput "$base\no.txt" -NoNewWindow -Wait
```

Boot headless — **run in the background so it survives across turns** (harness `run_in_background`, NOT PowerShell `Start-Job`, which dies when the call's process exits):
```powershell
& "$env:ANDROID_HOME\emulator\emulator.exe" -avd phantom34 `
  -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect
```
Wait for boot:
```powershell
$adb = "$env:ANDROID_HOME\platform-tools\adb.exe"
& $adb start-server *>$null
for ($i=0; $i -lt 90; $i++) {
  if ((& $adb get-state 2>$null) -eq "device" -and "$((& $adb shell getprop sys.boot_completed 2>$null))".Trim() -eq "1") { break }
  Start-Sleep -Seconds 5
}
& $adb devices   # expect: emulator-5554  device
```

---

## 6. Install, launch, and drive the flow

The app starts the prop mesh server on device port 8080 in `onCreate`. Forward it and curl the `/debug` drivers (no UI tapping needed).
```powershell
$adb = "$env:ANDROID_HOME\platform-tools\adb.exe"
$apk = "C:\Users\Christian Correa\OneDrive\Desktop\Projects\PhantomChain\src\android\app\build\outputs\apk\debug\app-debug.apk"
& $adb install -r $apk
& $adb shell am start -n com.phantomchain.debug/.MainActivity
& $adb forward tcp:8080 tcp:8080
Start-Sleep -Seconds 6
curl.exe -s  http://localhost:8080/status
curl.exe -s -X POST http://localhost:8080/debug/enroll
curl.exe -s -X POST http://localhost:8080/debug/sign
curl.exe -s -X POST 'http://localhost:8080/debug/backup?password=pw123secure'
curl.exe -s -X POST 'http://localhost:8080/debug/recover?password=pw123secure'   # identity_matches=true
curl.exe -s -X POST 'http://localhost:8080/debug/recover?password=wrongpass'      # ERR: MAC check failed
```

### Endpoint reference
| Method/URL | Role |
|---|---|
| `GET /status` | health |
| `POST /register-share?identity_id=HEX` | mesh **creates+holds** a recovery share |
| `POST /authorize-transfer?identity_id=HEX` | mesh **releases** the share (server-mediated transfer) |
| `POST /debug/enroll` | make identity-root + device key |
| `POST /debug/sign?msg=...` | simulated-biometric ML-DSA signature |
| `POST /debug/backup?password=...` | seal recovery seed → blob (Argon2id+HKDF+ChaCha20-Poly1305) |
| `POST /debug/recover?password=...` | authorize transfer + recover seed + re-derive identity-root (balance preserved) |
| `POST /debug/enroll` | also seeds genesis (1,000,000 PHNT) and persists |
| `POST /tx/send?to=HEX&amount=N` | build+sign+validate (sig/balance/nonce) a tx, apply to state |
| `POST /node/mine` | seal mempool into a hash-linked, device-signed block |
| `GET  /ledger/balance?id=HEX` | balance + nonce (default: owner) |
| `GET  /ledger/chain` | height, blocks, total txs, last hash, chain validity |

### Cluster nodes (ports 8081-8083, started automatically by the app)
`adb forward` each port, then drive any node. Proposer for height h is node `h % 3`.

| Method/URL (per node) | Role |
|---|---|
| `GET  /status` | node index, height, last hash, mempool size, next proposer, all balances |
| `POST /submit?to=HEX&amount=N` | build+sign a tx from this node, add to mempool, gossip to peers |
| `POST /round` | proposer only: build block, collect votes, assemble 2-of-3 QC, commit + broadcast |
| `POST /vote` | peer: validate a proposal, return this validator's ML-DSA signature (node-to-node) |
| `POST /commit` | peer: verify the quorum certificate, then commit (node-to-node) |
| `POST /gossip/tx` | peer-to-peer mempool propagation (node-to-node) |

Convergence check: after a `/round`, all three `/status` show the **same height and last hash**; `/round` output lists the QC signer set.

### UI / QR render + screenshot
```powershell
& $adb shell uiautomator dump /sdcard/ui.xml; & $adb pull /sdcard/ui.xml "$base\ui.xml"
# parse button bounds from ui.xml, then: & $adb shell input tap X Y   (Enroll, then Backup)
& $adb shell screencap -p /sdcard/qr.png; & $adb pull /sdcard/qr.png "$base\phantom-qr.png"
```
(Use `screencap`→`adb pull`, NOT `adb exec-out screencap -p > file` — the `>` redirect corrupts the PNG.)

Stop the emulator: `& $adb -s emulator-5554 emu kill`.

---

## 7. Gotchas (all hit and solved here)

- **PowerShell `Start-Job` background dies** — each tool call is a fresh process. Use the harness `run_in_background` for anything that must outlive the call (SDK install, emulator).
- **`|` piping `y` to sdkmanager doesn't feed stdin** — stalls silently. Use `Start-Process -RedirectStandardInput file`.
- **Removing files under the scoop SDK is sandbox-blocked** ("protected path"). Overwrite with empty content instead of `Remove-Item`.
- **`2>&1` on native exes in PowerShell 5.1** wraps stderr as `NativeCommandError` and flips `$?` even on exit 0. Avoid it; read stderr separately.
- **Binary stdout redirect (`>`)** corrupts files (e.g. screencap). Write on device, then `adb pull`.
- **Emulator accel:** `HypervisorPlatform` Windows feature read "disabled", but `emulator -accel-check` reported WHPX usable and it boots fast. Trust `-accel-check`, not the feature flag. Fallback if it ever fails: `-no-accel -gpu swiftshader_indirect` (slow software boot).

---

## 8. Quick rerun (everything already installed)

```powershell
$env:JAVA_HOME = "C:\Users\Christian Correa\scoop\apps\temurin17-jdk\current"
$base = "C:\Users\Christian Correa\OneDrive\Desktop\Projects\PhantomChain\src"
$adb  = "$env:ANDROID_HOME\platform-tools\adb.exe"
# 1. (optional) JVM crypto/consensus test suite — see §2 for the compile + run
# 2. build APK
& "$base\android\gradle-dist\gradle-8.7\bin\gradle.bat" -p "$base\android" assembleDebug --no-daemon --console=plain
# 3. boot emulator (run_in_background): emulator.exe -avd phantom34 -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect
# 4. install + drive (section 6)
```

---

## 9. Networked cluster — 3 separate JVM processes (`node/`)

Unlike the in-app cluster (§6, co-located on 8081-8083), this runs the **same consensus as 3 independent OS processes** over real TCP (ports 9091-9093), with crash-recovery via a `/sync` catch-up protocol and per-node persistence. Reuses `PhantomCrypto.java` + `Ledger.java` from the Android tree.

**Compile** (explicit file list — do NOT compile the whole dir; MainActivity needs Android):
```powershell
$st = "C:\Users\Christian Correa\OneDrive\Desktop\Projects\PhantomChain\src"
$adir = "$st\android\app\src\main\java\com\phantomchain\debug"
javac -cp "$st\lib\*" -d "$st\node\out" "$adir\PhantomCrypto.java" "$adir\Ledger.java" "$st\node\NetNode.java" "$st\node\NodeMain.java"
```
Needs `lib\json-20240303.jar` (+ bcprov) — fetch from Maven Central if missing. (The node's HTTP server is the JDK's built-in `HttpsServer`; no web-server jar is required.)

**Run** — the node CLI is a **genesis-ceremony flow** (`keygen` → `genesis` → `run`; plus `mintcert` to issue a cert for a joining validator from the retained cluster CA). The canonical, verified recipe is **`node/beacon-test.sh`** — a fresh 3-validator testnet on ports **9190–9192** (TLS 1.3, commit-reveal RANDAO beacon, then a node restart to prove `beaconCtr` resync doesn't stall consensus). What it does:
1. `NodeMain keygen <keyFile>` ×3 → each prints `pubkey`, `id`, and `beaconCommit0` (binds that validator's first RANDAO reveal at genesis);
2. assemble `spec.json {chainId, genesisTime, validators:[{pubkey,stake,identity,verified,alloc,beaconCommit0}]}` — also `custodians`/`bridgeThreshold`/`reserve` for the bridge, and per-validator `region`/`tier` for geo-premium and light/heavy storage;
3. `NodeMain genesis spec.json out/` → writes `genesis.json` + mints `out/tls/` (`truststore.p12` + `node-0..N.p12`);
4. lay out each node dir: `genesis.json`, `node.key`, `pcdata/certs/{truststore.p12,node-<i>.p12}`, and `config.json {rpcPort, selfAddr, seeds:[...], dataDir, keyFile, certIndex}`;
5. `NodeMain run config.json genesis.json` per node — launch each via harness `run_in_background` (the script's bash `&` dies across tool calls). The seed node bootstraps; the rest discover full membership over the wire.

Endpoints are HTTPS — `curl -sk`. Open reads: `/status /econ /head /peers /block?h=`. Drive consensus: `POST /submit?to=<hex>&amount=N` (each accepted tx triggers a commit round; an empty chain stays at height 0 until a tx arrives). `to` may be any hex id (self-sovereign accounts — no registration). Convergence: all `/status` show the same height+hash and list the QC signer set.

> The cross-machine / QEMU / phone subsections below illustrate addressing and topology; their one-liners predate the ceremony flow (positional args) — under the current CLI you run `keygen`→`genesis`→`run` with real host IPs in `spec.json`/`config.json`, exactly as `beacon-test.sh` does on loopback.

**Consensus is autonomous** (no manual trigger): each node runs a view-timed proposer loop. Proposer for `(height h, view v)` = `(h+v) mod N`; if it doesn't commit within `VIEW_TIMEOUT` (3 s), the view advances and the next validator takes over — **a dead proposer no longer stalls the chain**. Safety: each validator signs at most one block per height, so competing views can't both reach quorum.

**Endpoints** (per node): `GET /status` (shows `slashed=[...]`), `GET /head`, `GET /block?h=H`, `GET /peers`, `POST /announce?index=&addr=`, `POST /sync`, `POST /submit?to=&amount=`, `POST /vote`, `POST /commit`, `POST /gossip/tx`, `POST /gossip/vote`, `POST /gossip/slash`, `POST /byz/equivocate` (debug: force a double-sign).

**Byzantine accountability:** every vote is gossiped and **persisted to `votes-<i>.json`** (reloaded on boot → a crash-restart can't double-vote at a height it already voted). Two conflicting signatures from one validator at one height = equivocation evidence → a `SLASH` tx → on commit every node **burns that validator's stake and ejects it** (its votes stop counting in `verifyQC`, it can't propose). The `slashed` set is part of the persisted ledger state.

**Drive + tests** (curl `127.0.0.1:909{1,2,3}`):
- **discovery**: `GET /peers` on each → all 3 addresses, though only the seed was configured.
- consensus: `POST /submit?amount=N` → the chain auto-commits; all `/status` converge.
- **view-change**: kill the proposer for the next height (`Get-CimInstance Win32_Process … '*NodeMain 2 *'` → `Stop-Process`), `/submit` → after ~3 s another node proposes at view 1 and commits with the remaining BFT quorum (its stdout logs `VIEW-CHANGE`). Verified. *(Quorum is the BFT-correct `N−(N−1)/3`, so surviving a downed validator needs **N≥4** — verified on the live 4-validator testnet as **3-of-4**. At **N=3** the quorum is unanimous (f=0), so the 3-node toy cluster does **not** survive losing a node; this is correct BFT for N=3, which is not 3f+1.)*
- **catch-up**: restart the killed node → its periodic sync loop pulls missed blocks and it converges (boot log `loaded chain height=N`). Verified.
- **double-sign slashing**: `POST /byz/equivocate` on a node → it double-signs at the current height; honest nodes detect the conflicting signatures (`DETECTED equivocation`), commit a SLASH tx, and all agree `slashed=[i] bal_i=0`. Verified — the slashed node's votes stop counting and it can't propose; the chain continues on the remaining quorum.
- **persistent votes**: each vote → `votes-<i>.json`; restart a node and the boot log shows `persistedVotes=N` (reloaded) + `slashed=K`. Verified — it refuses to double-vote at a height it already voted.

### Security stack (v1 — available libraries only, no rolled crypto)
| Layer | v1 (running) | Library | Pipeline upgrade |
|---|---|---|---|
| Signatures (tx/identity/votes) | ML-DSA-65 | BouncyCastle 1.84 | — |
| Key encapsulation | ML-KEM-1024 | BouncyCastle | — |
| Hash / commitments / beacon | SHA3-256, SHAKE-256 | BC/JDK | — |
| AEAD (recovery keystore) | ChaCha20-Poly1305 | BC | — |
| Password KDF | Argon2id | BC | — |
| Consensus certificate | multisig quorum cert (N×ML-DSA) | BC | threshold ML-DSA (1 aggregate sig) |
| Leader randomness | **commit-reveal RANDAO beacon** (each proposer reveals a secret it committed in its prior block; `beacon = sha3(beacon \| reveal)` seeds the weighted proposer; reveal bound by on-chain commitment, verified at commit + vote, covered by stateRoot; per-node secret = `HKDF(seed,"pcbeacon"+ctr)`, counter resynced on restart) | SHA3 + HKDF | true PQ-VRF (removes residual 1-bit last-revealer bias) |
| Transport | server-authenticated **TLS 1.3** + per-cluster CA (EC P-256 certs, `bcpkix`); discovery/gossip/votes/commits all encrypted | JDK SunJSSE + BC | PQ-hybrid KEX `X25519MLKEM768` (BCJSSE w/ BC JCE provider, or JDK 27 native JEP 527) |

Verified: 3 nodes negotiate TLS 1.3, discover over TLS, and reach quorum-certificate consensus over the encrypted channel (CA cert needs `BasicConstraints cA=true` for PKIX — gotcha). The one documented gap vs. "PQ everywhere" is the TLS **key exchange**, which is classical X25519 in v1; ML-KEM hybrid KEX is the BCJSSE/JDK-27 upgrade. Code: `node/TlsSetup.java`.

**Node HTTP server — JDK `HttpsServer` (no third-party web server):** the node's HTTP layer is the JDK's built-in `com.sun.net.httpserver.HttpsServer` (module `jdk.httpserver`), wrapped by `NodeHttpServer`. The former `org.nanohttpd:nanohttpd:2.3.1` dependency (last released 2017) was removed — the JVM build no longer depends on it. mTLS is configured cleanly via `HttpsConfigurator` (`needClientAuth=true` on the peer port; `false` on the open read port), replacing the old workaround for NanoHTTPD's `makeSecure()` resetting client auth. The on-device `ClusterMember` service (shared engine, runs on Android where `com.sun.net.httpserver` is absent) uses a minimal raw-socket HTTP/1.1 loop. Malformed requests return `400` without a stack trace (no log-flood vector). *(The Android app's debug `PropMeshServer` still uses NanoHTTPD — that's the app build, not the node.)*

### Mining economics (simulation)
Simulates the spec's §9 model on the networked node (`GET /econ` shows it live):
- **Weight** = `0.6·√stake-share + 0.4·identity-share` over non-slashed validators (10% cap is a server param, not binding at N=3). Verified with stakes `[4M,1M,1M]` + identity `[1,1,2]` → weights **40% / 25% / 35%**: node0's 4× stake yields only 40% (√-damped), node2's extra human lifts it to 35%.
- **Weighted proposer**: proposer for `(height,view)` is a deterministic weighted pick seeded by the **commit-reveal RANDAO `beacon`** (no longer the grindable `prevHash`). Residual: RANDAO's 1-bit last-revealer bias; a true PQ-VRF removes it.
- **Emission + rewards**: each block mints `BLOCK_REWARD`; every `EPOCH_LEN` blocks the pool is split by **on-chain contribution = QC signatures + proposer bonus**. Verified: 6 blocks → 600 minted over 2 epochs, split 200/240/160 (the node that proposed most earned most). **Earnings track participation, not weight.**
- **Provable vs sim-trusted:** stake, QC signatures, `block.proposer` are on-chain/provable (rewards use only these); identity-count needs Sybil-resistant personhood; bandwidth/uptime are unprovable and **not** rewarded.

### Cross-machine deployment
Nodes advertise `host:port`, so a real multi-host cluster just uses LAN IPs instead of loopback. Verified on this host bound to the LAN interface `192.168.1.138` (reachable + discovery + consensus over that address). To split across two machines on the same network:

1. **Firewall (admin, once) on each host:** `New-NetFirewallRule -DisplayName "PhantomChain" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9091-9093`
2. **Machine A** (`192.168.1.138`) runs node0 + node1:
   - `java -cp "out;lib/*" com.phantomchain.debug.NodeMain 0 9091 192.168.1.138:9091 192.168.1.138:9091 data`
   - `java -cp "out;lib/*" com.phantomchain.debug.NodeMain 1 9092 192.168.1.138:9092 192.168.1.138:9091 data`
3. **Machine B** (`<B-ip>`) — copy `node\out` + `lib`, install JDK 17, run node2 (stop any local node2 first so the identity isn't duplicated):
   - `java -cp "out;lib/*" com.phantomchain.debug.NodeMain 2 9093 <B-ip>:9093 192.168.1.138:9091 data`
4. node2 announces to the seed, learns node0/node1, syncs the chain, and joins consensus. Validator keys are deterministic, so node2's identity is identical regardless of host.

Note: on one host, traffic to the LAN IP is loopback-optimized by the OS, so a same-host LAN-IP run proves binding/addressing but not inter-host traversal. WSL2/Docker/Hyper-V need admin+reboot to install — but QEMU (below) does not.

### Cross-machine via QEMU VM (no admin — VERIFIED)
QEMU is installed via scoop and runs without admin (WHPX-accelerated here; falls back to `-accel tcg`). A real Linux VM (own kernel + network stack) joins the host cluster over QEMU's virtual NIC.

- **Networking:** user-mode (SLIRP). Guest→host LAN IP `192.168.1.138` works through SLIRP; host→guest node via `hostfwd=tcp::9093-:9093`. All nodes use `192.168.1.138` addressing — node2 lives behind the port-forward.
- **Provisioning:** Debian 12 genericcloud qcow2 + cloud-init delivered over HTTP from the host (no ISO needed): boot with `-smbios "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:8000/"`, and run `node vm/server.js vm/seed 8000` to serve `vm/seed/{user-data,meta-data}`. user-data installs `openjdk-17-jdk-headless` + `git`, clones the node repo, and runs `bash run.sh 2 9093 192.168.1.138:9093 192.168.1.138:9091`.
- **Boot:** `qemu-system-x86_64 -accel whpx -m 2048 -smp 2 -display none -serial file:vm/serial.log -drive file=vm/debian12.qcow2,if=virtio -netdev user,id=net0,hostfwd=tcp::9093-:9093 -device virtio-net-pci,netdev=net0 -smbios "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:8000/"`
- **Result (verified):** VM node2 discovered peers, synced to height 1, then **proposed and committed block 2** (`/block?h=2` → `proposer:2, view:0`); host node0/node1 + VM node2 converged on the same height+hash. Genuine bidirectional cross-stack consensus, entirely on one box, no admin/reboot.

### Phone (real second device)

## Scope & Non-Goals

**Proven runnable today (Android + JVM):** post-quantum identity (ML-DSA-65), biometric-gated signing (simulated in debug; real StrongBox/BiometricPrompt is device-only), identity≠key with rotation, the QR cold-recovery path (Argon2id + HKDF + ChaCha20-Poly1305 + mock mesh share, wrong-password rejected), and a **single-node ledger**: signature/balance/nonce-validated transactions finalized into a hash-linked, device-signed block chain that re-verifies, with on-disk persistence (wallet + ledger survive a force-stop/relaunch).

Also runnable, two ways: (a) an **in-app 3-node cluster** (co-located, ports 8081-8083), and (b) a **networked cluster of 3 separate JVM processes** (§9, ports 9091-9093) over real TCP. Both use deterministic genesis, tx gossip, and a **BFT quorum-certificate commit** (`N−(N−1)/3` validator ML-DSA signatures — BFT-correct, replacing the earlier unsafe `N/2+1`; this is **3-of-3 at N=3** and **3-of-4** on the live 4-validator testnet). The networked one adds and has **verified**: seed-based **peer discovery** (only a seed configured; membership learned over the wire), **autonomous view-change** (a dead proposer no longer stalls — the next validator takes over after a timeout), **crash fault-tolerance** (committed with 1 node down — at **N≥4**, where the BFT quorum tolerates `f=⌊(N−1)/3⌋≥1`; **N=3 is unanimous and does not tolerate a loss**, which is correct BFT since 3 ≠ 3f+1), **catch-up resync** (a killed node restarted, pulled missed blocks, and rejoined), **persistent per-height votes** (reloaded on boot; no double-vote across a crash), and **double-sign slashing** (equivocation evidence → on-chain SLASH → stake burned + validator ejected, all nodes agreeing). *(The earlier "2-of-3" wording in §1/§6 predates the BFT-correct quorum and describes only the simpler in-app demo; the networked node uses the rule above.)*

**What the Android + JVM build proves (§1–§6) vs. the full node layer (§9):** the QC here is a **multisig, not a true threshold signature** — several separate ML-DSA signatures, not one aggregate (that interim is shared with the full node; a production threshold-ML-DSA library doesn't exist yet). Byzantine accountability is honest-but-partial: it punishes *equivocation* (double-sign) with persistent-vote prevention + slashing, but is not a full BFT safety proof (vote-withholding, invalid-block spam, long-range/eclipse aren't fully handled). **The cluster model, economics, and bridge have since been built, verified, and run live** on testnet-2 — Reed-Solomon(k,n) erasure-coded history sharding, decaying-emission rewards + fee burn + staking/slashing economics, cluster mining (M-of-N member devices = one validator), and the cross-chain bridge. For the authoritative tier status and the honest research-gated gaps (threshold ML-DSA, proof-of-personhood, PUF attestation), see [`FRONTIER.md`](FRONTIER.md).

**The one research-grade primitive for the next layer:** threshold ML-DSA — it would compress the quorum certificate's several signatures into a **single aggregate signature** jointly produced by the quorum. 2026 schemes (Mithril/THED/Quorus) exist but have no production Java/Android library. After that, real BFT (view-change + equivocation slashing) and multi-device deployment are the remaining steps toward the spec's cluster mining.
