# FirewallXNdisFilter

FirewallXNdisFilter is an experimental Windows network filter written in Rust, with a C++ monitor and client APIs. It uses an **NDIS Lightweight Filter (LWF)** on compatible host Ethernet adapters, both physical and virtual.

Only traffic traversing an attached NDIS module can be inspected. Some adapters cannot accept an ordinary LWF; for example, Wintun/WireGuard adapters declaring `LowerRange=nolower` are not supported. Internal VM-to-VM traffic that never passes through an attached host adapter is also outside the filter's scope. The package and device API version is **0.3.3.0**; use a matching driver and client.

> **Warning:** This is experimental kernel software. Mixed local/transit IP NBLs are split: local packets bypass policy, while transit packets receive independent verdicts or fallback decisions. The driver attempts to queue one warning while a controller is connected. Policy is temporarily bypassed when the local-address inventory is unavailable. Address-only exemptions allow packets with spoofed local IPs and are not an anti-spoofing boundary. With no controller connected, the default fail-closed policy otherwise drops eligible transit IP traffic on attached adapters. Use a test machine with local recovery access; offline tests and enabled bindings do not prove correct live filtering.

## Build

Requirements:

- Windows x64 build **25341 or newer**, with compatible Ethernet adapters for NDIS traffic filtering.
- Visual Studio C++ x64 tools, CMake and Ninja; Rust 1.91+ with the `x86_64-pc-windows-msvc` target.
- Windows SDK and WDK **10.0.28000.0**, and LLVM with libclang. Set `LIBCLANG_PATH` if libclang is not in `%ProgramFiles%\LLVM\bin`.
- A signing certificate and root certificate. The [windows_kext_mod certificate instructions](https://github.com/GerardoKermitToy/windows_kext_mod#1-create-the-local-certificates) explain how to create the local keys used in the example below. Keep private keys out of source control.

From Git Bash at the repository root, build a signed Release package and run the offline tests:

```bash
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/Build.ps1 -Test -PfxPath 'C:\portmaster_v3\windows_kext\localhost-km.pfx' -RootCertificate 'C:\portmaster_v3\windows_kext\localhost-root-ca.der'
```

Adjust the certificate paths for your machine. Set `FIREWALLXNDISFILTER_PFX_PASSWORD` or pass `-PfxPassword` when needed. The build requests an RFC 3161 timestamp from `http://timestamp.digicert.com` by default; use `-TimestampUrl` for another service. Only the timestamp hash is sent; the private key stays local. Signing does not by itself guarantee that Windows will accept the driver: review the target system's signing and security requirements independently. The build does not install the driver or change certificate stores or security settings.

The package in `dist/` contains `FirewallXNdisFilter.sys`, its INF and CAT, `FirewallXNdisFilterNotify.dll`, `ndis_monitor.exe`, `Install.exe`, `Uninstall.exe`, and matching full PDBs. Keep these files together and do not mix package versions. If `dist/` contains artifacts from another product or monitor name, the build refuses to mix them; preserve and move the incompatible package before rebuilding.

## Install

Use an elevated Administrator/SYSTEM console, stop any monitor, and keep local recovery access available. Windows may reconfigure networking during installation. If the filter is already installed, remove it first with its matching uninstaller; the installer does not replace a live driver or overwrite a notify registration belonging to another product.

```bash
./dist/Install.exe
```

The installer uses the package beside the EXE and enables the eligible binding paths exposed by NetCfg for this filter, including compatible physical Ethernet adapters and host vNICs. An adapter with no compatible binding path is not covered. New adapters are not guaranteed to be enabled automatically; verify their binding and running module before relying on coverage. Use `--what-if` for read-only preflight or `--yes` to skip confirmation. Conflicting staged packages can cause installation to fail; use the matching uninstaller rather than overwriting package files.

If installation returns **3010**, reboot and then resume enabling the compatible NetCfg paths available at that time:

```bash
./dist/Install.exe --enable
```

## Monitor

Start with the default PermanentAccept policy:

```bash
./dist/ndis_monitor.exe --duration 15 --timestamps --memory-stats --out allow.log
```

Omit `--duration` to run until **Ctrl+C**. To apply a blocking verdict only to a test remote endpoint:

```bash
./dist/ndis_monitor.exe --duration 10 --match 192.0.2.10:9000 --verdict permanent-block --out block.log
```

`--match` selects the remote endpoint reported by the driver in both directions; unmatched events receive PermanentAccept. `--filter-ip` only hides output and does not limit verdicts. A blocking verdict without `--match` applies to every event and can disrupt connectivity. Run `./dist/ndis_monitor.exe --help` for the remaining options.

The monitor opens the existing control device; it does not install, load, bind, or start a temporary driver. Install and start the NDIS LWF before running it. `--duration` bounds monitoring, not driver installation or startup.

At startup, the monitor prints an attached-adapter snapshot and the count of running NDIS modules; the count is refreshed at `--poll` intervals. These are NDIS diagnostics, not proof that traffic is being intercepted. An unavailable query produces a warning rather than a fabricated empty result.

## Remove

Stop the monitor, then run from an elevated console:

```bash
./dist/Uninstall.exe
```

The uninstaller disarms and removes this filter and its identified driver packages without requiring the target adapters to remain present. `--what-if` lists the affected packages without changing system state. If removal returns **3010**, reboot and run `Uninstall.exe` again before reinstalling.

## API

The reusable clients are [PortmasterKext.h](monitor/include/PortmasterKext.h) (`pmkext`, with [DriverProtocol.h](monitor/include/DriverProtocol.h) for the codec) and the independent C++20 [FirewallXNdisFilter.hpp](monitor/include/FirewallXNdisFilter.hpp) (`firewallxndisfilter::Client`). The driver-side wire definitions are in [protocol/src/lib.rs](protocol/src/lib.rs); adapter snapshots use [adapter_info.rs](driver/src/adapter_info.rs).

For a complete header-only example, see [callback_client.cpp](monitor/examples/callback_client.cpp). It connects to an existing device, allows connection events, and runs for ten seconds after startup. The header-only client does not install or load the driver; its `Open()` can wait indefinitely for driver startup, as described below.

### Semantics

- **ConnectionIpv4/ConnectionIpv6 have no `process_id` field.** The `interface_index:u32` after `id` identifies the host adapter at the interception point (`BaseMiniportIfIndex`), not an interface inside a guest. It is retained with each pending packet and bandwidth group, so interleaved traffic from different interfaces keeps its own index. There is no compartment/sub-interface ID, TID, switch/port/GUID/LUID field, and no host-process or individual-VM ownership is inferred. Interface indices can change or be reused after adapter recreation; they are not permanent identities. The `ConnectionEnd` compatibility types have a PID field, but this driver does not emit these events.
- `direction=0` describes host NDIS receive, and `direction=1` host NDIS send. On a guest-facing host vNIC these normally correspond to guest outbound and inbound respectively; on other adapters they must not be interpreted as proof of guest ownership. `local_*` is the observed IP source for receive and destination for send; `remote_*` is the opposite endpoint. The console uses the same direction, endpoints and bandwidth counters as the raw API on every interface.
- One connection event and its `id` represent **one pending NBL**, not a socket or a connection lifetime. A homogeneous multi-NB NBL has one verdict and the complete IP packet from its first NB, not a concatenation of all NBs. A mixed local/transit NBL is instead split into one owned child NBL per NB; transit children receive independent policy decisions, with separate events when a verdict is required. Multi-NB transit-only batches processed by policy are accepted only for TCP/UDP packets whose non-fragmented flow keys are fully identified and match; incompatible transit-only flows, malformed batches, fragments, incomplete flow keys, and batches containing other IP protocols are dropped. Single-NB packets of other IP protocols still follow normal policy.
- `payload_layer=3`. `payload` contains the **complete observed IP packet**, including IP/transport headers, without Ethernet/VLAN headers or Ethernet padding. `payload_size` is its full byte count. Endpoint normalization does not rewrite packet bytes. For LSO/RSC, this is the logical packet observed at NDIS, not necessarily one frame on the wire.
- Normally, only packets whose observed source **and** destination are absent from the machine-wide local IPv4/IPv6 unicast and anycast inventory are selected for policy. A packet with either address in the inventory bypasses verdict events, cache and bandwidth accounting, including when no controller is connected. Addresses are compared globally across adapters; the adapter carrying the address need not be attached to this filter. When the inventory is unavailable or being rebuilt, policy is temporarily bypassed rather than treating unknown addresses as transit. NETIO unicast notifications are asynchronous; anycast is polled at a nominal five-second interval, so address changes are not instantaneous.
- **Mixed local/transit NBLs:** after every NB passes the bounded parser, the driver attempts one warning with the interface index and splits the NBL into independently owned children. Local packets bypass policy; each transit packet follows the normal verdict/fallback and bandwidth paths without using or populating the permanent cache. The original NBL is returned only after all children complete, without changing its NB chain. Normal send/receive children use cloned NB/MDL descriptors that reference the original packet data without an extra split copy; a receive indicated with `RESOURCES` is first deep-copied. Connection events still copy their packet payload. Local and transit children can complete in a different order. Invalid packets, IP/non-IP mixtures, unsupported metadata or NBL flags and paused attachments remain drop paths.
- Non-IP traffic such as ARP does not produce connection events and is passed when its ownership/profile is supported. Cache hits are handled in the kernel without a new verdict event.
- Redirect verdicts, UpdateV4/V6, PID suspension, and a thread-ID IOCTL are **unsupported**. Some enum names remain in the C++ header only for source compatibility.
- NDIS has no socket/ALE teardown notification. **Connection-END events are never generated**, including on cache expiry, timeout, or disconnect.
- A single packet traversing more than one attached adapter can produce separate verdicts and bandwidth counts at each observation point. A successful verdict write is not delivery confirmation.
- NDIS supports UDP receive coalescing and recognizes UDP segmentation offload; these logical packets are not cacheable.

Connection payloads are bounded at **1 MiB (1048576 bytes)**, covering ordinary IPv4/IPv6 packets and supported larger offload packets. Larger logical packets are dropped rather than reported with truncated payloads. Apart from the LogLine limit below, packet records, metadata, queues, NBL contexts and private receive copies have no driver-defined aggregate byte budget or item quota. Exhaustion of the driver's nonpaged pool can bugcheck the machine; clients must retrieve records promptly. While a controller is online, malformed or unsupported packets, copy/resource failures, failed sends and paused interfaces produce warning LogLine records when the log can be queued; verdict timeouts and normal blocking verdicts do not. Up to **1000 queued LogLine records**, of any severity and including a partially read record, are retained; each new LogLine replaces the oldest completely unread LogLine when the limit is reached. A partially read record is always completed to preserve stream framing. Connection events and bandwidth reports are not subject to this limit. LogLine records are not retained while no controller is connected, and queue/allocation failure can prevent a log record. `--filter-pid` is unsupported.

This is experimental kernel code. Offline tests and an enabled binding do not prove correct live filtering.

### Device session and IOCTLs

Open **`\\.\FirewallXNdisFilter`** as Administrator/SYSTEM with `GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, and exclusive sharing. The C++ client uses `FILE_FLAG_OVERLAPPED`; nonzero buffered reads wait for event bytes and are cancellable. Only **one controller** may hold the device.

Opening the device activates a policy session and resets its event queue, permanent cache, and bandwidth buckets. The client must verify the device version before relying on the protocol. `Driver::Open` only opens the session; the monitor separately checks the version.

All supported IOCTLs use `CTL_CODE(40000, function, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)` and take no input buffer:

| IOCTL | Function / numeric code | Output and effect |
|---|---|---|
| `IOCTL_VERSION` | `0x800` / `0x9C40E000` | Exactly four bytes: `00 03 03 00`. The output buffer must have at least four bytes. |
| `IOCTL_SHUTDOWN` | `0x801` / `0x9C40E004` | No output. Deactivates the policy session, discards queued events/cache/bandwidth, and resolves pending packets through the configured fallback. Does not unload, unbind, or uninstall the LWF. |
| `IOCTL_FILTERED_DEVICE_COUNT` | `0x802` / `0x9C40E008` | Exactly four bytes: an unsigned 32-bit little-endian count of running NDIS filter modules. The output buffer must have at least four bytes; input must be empty. No policy or binding side effects. |
| `IOCTL_ADAPTER_INFO` | `0x803` / `0x9C40E00C` | Versioned snapshot of every attached module, including not-running modules, with host adapter identity, names, MAC, link and general NDIS attributes. Empty input; variable-size output with a 16-byte sizing header on `STATUS_BUFFER_OVERFLOW`. Both clients grow their buffer as needed. No policy, OID or binding side effects. |

The count includes only modules admitted by the kernel gate that successfully restarted and have not begun pausing. Merely configured, rejected, attached-but-paused, failed-restart and detached modules do not count. Pause removes a module immediately, even while outstanding NBLs are draining; a later successful restart adds it again. The snapshot is independent of the controller's policy-session state, so shutdown does not reset it. It describes active interception on adapters, not packet delivery, link connectivity or proof that traffic was observed. Polling can miss brief transitions.

All other IOCTLs are unsupported. After shutdown, close and reopen the handle to activate a new session. Closing the active handle also disconnects the controller and drains pending decisions. Shutdown does not itself close the handle or stop a custom application's read loop.

Reads return an event byte stream, with no driver-defined size limit beyond the native Windows **DWORD/u32** request length. A read can complete with more than 65536 bytes and coalesce multiple records; it may return fewer bytes than requested. A nonzero read remains pending until bytes exist and never succeeds empty merely because the queue is empty. Zero-length requests still complete with zero bytes. Waiting reads have no fixed count or byte-budget admission quota; Windows must still allocate their buffered-I/O resources. Shutdown, cleanup and unload cancel waiting reads; new reads after session shutdown fail until close/reopen. `CancelIoEx` cancels a waiting read, but cancellation can race a successful completion. Always reap an outstanding OVERLAPPED operation before freeing its buffer/event. Reads can split a record; retain incomplete bytes between reads. No read-polling delay is needed.

### Adapter information snapshot

`IOCTL_ADAPTER_INFO` is an additive diagnostic: event/command wire version is **0.3.3.0**. Do not infer snapshot availability from the event version alone; treat an unsupported/failed query as **unavailable**, never as an empty adapter list. At startup, after checking the device version, the monitor prints this snapshot once, respecting `--out` and `--timestamps`. It warns and continues monitoring if the query fails. The separate running-device count still updates at `--poll` intervals; the two queries can observe different instants.

The snapshot lists only modules accepted by the armed schema-4 Ethernet attach gate, not all Windows adapters or configured bindings. A module remains listed while attached but initially paused, pausing, or after a failed restart; flag `Running` means its admission gate is open. Detached modules disappear. `module_id` is an ephemeral internal module identifier, distinct from every Windows interface index/LUID. Interface identities describe the **host NDIS stack**, not guest adapters, switch ports or VM ownership. GUIDs/LUIDs are diagnostic only and do not broaden binding authorization.

The driver copies names and current MAC at attach, captures general attributes supplied during successful restart, and updates link state/speeds from valid `NDIS_STATUS_LINK_STATE` indications. Fields describe the **last NDIS-supplied values**, not a fresh hardware/OID interrogation. A new restart clears optional general attributes first; if none are supplied, those values are zero and `GeneralAttributesValid` is unset. The base connector flag is available only with attach revision 4. `LinkStateValid` indicates that auto-negotiation flags were supplied by a link-state indication; initial connection/duplex/speeds already come from attach. Speeds are bits/s; `UINT64_MAX` means unknown under the NDIS convention. `PauseValid` reports the last observed pause reason/flags, even after restarting. Pointer-bearing capabilities, kernel handles/addresses, IP configuration, routes, process/guest identities and arbitrary OID data are not exported.

The reply is **not an event record**. Its explicit byte codec is [adapter_info.rs](driver/src/adapter_info.rs); do not serialize native structures. All integers and UTF-16 code units are little-endian. The first 16 bytes are four `u32` values:

| Offset | Field | Value |
|---:|---|---|
| 0 | Schema version | `1`, independent of the device/event version. |
| 4 | Entry size | `1760` bytes. |
| 8 | Attached module count | `u32`; no fixed adapter-count quota. The complete reply must fit the 32-bit IOCTL byte-length field. |
| 12 | Running module count | Number of entries with flag `Running`; `0..count`. |

Exactly `count` entries follow on success. Successful output length is **`16 + count * 1760`**; zero modules is a successful 16-byte reply. Count/length calculations are checked against `UINT32_MAX`, not a configured adapter ceiling. Nonempty input fails with `STATUS_INVALID_PARAMETER`. A buffer smaller than 16 bytes fails with `STATUS_BUFFER_TOO_SMALL`. A buffer that holds the header but not the **complete current snapshot** receives exactly the 16-byte header and `STATUS_BUFFER_OVERFLOW` (Win32 `ERROR_MORE_DATA`), never a partial adapter list. Compute the required length from that header, allocate a larger buffer, and retry; attach/detach may change the required size again. Only a successful complete reply is a snapshot. Both clients start with a modest 56336-byte buffer, then grow fallibly with bounded retries on topology churn; they never allocate the arithmetic maximum upfront. Complete queries can fail with `STATUS_RETRY` if repeated attachment churn prevents a consistent capture; this does not mean an empty list. The existing exclusive Administrator/SYSTEM device access requirement applies, including after policy shutdown while the handle remains open.

Entry offsets are relative to each 1760-byte entry. C++ `AdapterInfo` has the following fields; header-only `Client::AdapterInfo` exposes the same data. These are owning decoded types, **not** native wire-layout views:

| Offset | C++ field(s) | Wire format / source |
|---:|---|---|
| 0 | `module_id` | `u64`, driver module identity. |
| 8, 12, 16 | `interface_index`, `filter_interface_index`, `lower_interface_index` | Three `u32`: base miniport (matches connection events), filter, and lower interface indices. |
| 20 | `flags` | `u32`, validity/state/truncation bits below. |
| 24, 32, 40 | `interface_luid`, `filter_interface_luid`, `lower_interface_luid` | Three `u64`, corresponding NET_LUID values. |
| 48 | `interface_guid` | 16 bytes: Windows GUID field order (`Data1:u32 LE`, `Data2:u16 LE`, `Data3:u16 LE`, `Data4[8]`). C++ uses `std::array<uint8_t,16>`. |
| 64, 68 | `media_type`, `physical_medium` | Two `u32`, NDIS medium / physical-medium enum values. |
| 72, 76 | `media_connect_state`, `media_duplex_state` | Two `u32`: connect unknown/connected/disconnected=`0/1/2`; duplex unknown/half/full=`0/1/2`. |
| 80, 88 | `xmit_link_speed`, `rcv_link_speed` | Two `u64`, last known TX/RX link speeds in bits/s. |
| 96, 100, 104, 108 | `mtu`, `mac_options`, `supported_packet_filters`, `max_multicast_list_size` | Four `u32`, general restart attributes; MTU in bytes, option/filter values are bitmasks. |
| 112, 120 | `max_xmit_link_speed`, `max_rcv_link_speed` | Two `u64`, general maximum TX/RX speeds in bits/s. |
| 128, 132, 136, 140 | `lookahead_size`, `access_type`, `connection_type`, `supported_statistics` | Four `u32`, general restart attributes: bytes, NET_IF access/connection enums, statistics bitmask. |
| 144, 148, 152, 156 | `data_backfill_size`, `context_backfill_size`, `restart_flags`, `attach_flags` | Four `u32`: backfill byte counts, general restart flags, attach flags. |
| 160, 164 | `connector_present`, `mac_address_length` | Two `u32`: `0/1` (only meaningful with connector-valid flag), MAC length `0..32`. |
| 168 | `mac_address` | 32 bytes, zero-padded; C++ `std::array<uint8_t,32>`, first `mac_address_length` bytes are meaningful. |
| 200, 204, 208 | `instance_name_length`, `base_name_length`, `filter_module_name_length` | Three `u32` UTF-16 **code-unit** counts `0..255`, excluding the terminator. Equal to the corresponding decoded string lengths. |
| 212, 216, 220 | `auto_negotiation_flags`, `pause_reason`, `pause_flags` | Three `u32`, meaningful with link-state / pause validity flags. |
| 224, 736, 1248 | `instance_name`, `base_name`, `filter_module_name` | Three 256-code-unit UTF-16LE arrays: `BaseMiniportInstanceName`, `BaseMiniportName`, `FilterModuleGuidName`. Each has a NUL at its counted length and zero-filled tail; C++ decodes to `std::wstring`. Empty means unavailable/empty. |

| Flag | Bit | C++ `AdapterInfo::` constant |
|---|---:|---|
| Admission open | `0x01` | `Running` |
| General restart fields available | `0x02` | `GeneralAttributesValid` |
| Connector-present field available | `0x04` | `ConnectorPresentValid` |
| Instance/base/filter-module name truncated | `0x08` / `0x10` / `0x20` | `InstanceNameTruncated` / `BaseNameTruncated` / `FilterModuleNameTruncated` |
| Link-state indication received | `0x40` | `LinkStateValid` |
| Pause reason/flags available | `0x80` | `PauseValid` |

Names longer than 255 UTF-16 code units are bounded explicitly, with the corresponding truncation bit; truncation never splits a surrogate pair. Unknown numeric NDIS enum values are preserved. Clients validate schema/entry sizes, exact total length, counts, flags, MAC length and counted-string bounds/terminators before publishing any result. On failure the caller's snapshot is unchanged. `AdapterSnapshot` contains `uint32_t running_count` and `std::vector<AdapterInfo> adapters`; an empty vector is meaningful only after a successful query. Monitor names are UTF-8 with control bytes escaped, and unavailable general/connector/auto-negotiation fields are labelled unknown rather than reported as real zeros.

### Driver-start notification

`Global\FirewallXNdisFilter.DriverReady` (kernel name `\BaseNamedObjects\FirewallXNdisFilter.DriverReady`) is a named manual-reset event, separate from the device byte stream and IOCTLs. New objects allow access only to Administrator/SYSTEM. At startup, after initializing the control device and timer, the driver creates/opens the event, signals it, and keeps its handle until unload; unload clears the event and closes the handle. The driver supplies this notification independently of the monitor. Event creation is best-effort if the global object directory is not yet available during early system boot; device initialization does not depend on notification success.

The header-only client uses reset-before-retry startup waiting on this event, without device polling. A signal is only a retry hint, not proof of NDIS attachment, device authorization or version compatibility. The console monitor opens an already available device; it does not wait on the readiness event, load a temporary driver or reconnect after an established session ends.

### C++ client methods

Construct `Driver(std::wstring service_name = L"FirewallXNdisFilter")`; the argument selects the device basename, not a service to create. The class is non-copyable. Boolean methods report failures through `std::string& error`; sending a request does not imply a synchronous event response or confirmation that a verdict was applied.

| Method | Contract |
|---|---|
| `bool Open(std::string& error)` | Opens the existing device, preserving the Win32 failure code in `GetLastError()`. Fails if this client session is already open. Does not install, bind, load or negotiate the version. |
| `bool GetVersion(uint8_t out[4], std::string& error)` | Reads the four-byte version; integrations should require `0.3.3.0`. |
| `bool GetFilteredDeviceCount(uint32_t& out, std::string& error)` | Synchronously reads the running-module snapshot through `IOCTL_FILTERED_DEVICE_COUNT`. Requires exactly four response bytes. On failure returns false and leaves `out` unchanged; an unsupported request means unavailable, not zero. |
| `bool GetAdapterInfo(AdapterSnapshot& out, std::string& error)` | Synchronously reads and validates the complete variable-size attached-module snapshot described above, growing the query buffer as needed. Includes not-running modules; owning strings/arrays remain valid after return. Leaves `out` unchanged on failure, including malformed output or allocation failure. |
| `void Run(const Handlers& handlers, unsigned poll_interval_ms = 1000)` | Starts a reader thread and blocks until stopped or the reader exits. Dispatches complete records and invokes `on_poll` on the calling thread. It does not automatically request logs/statistics or send verdicts. |
| `bool SendVerdict(uint64_t id, Verdict verdict, std::string& error)` | Sends one verdict for a pending event ID. Only verdict values 2–7 are accepted. |
| `bool RequestLogs(std::string& error)` | Sends `GetLogs`; existing log events are already queued for reading. |
| `bool RequestBandwidthStats(std::string& error)` | Requests asynchronous bandwidth records for active buckets. No active buckets means no bandwidth records. |
| `bool RequestMemoryStats(std::string& error)` | Requests a diagnostic `LogLine` with policy storage/counter statistics. |
| `bool RequestClearCache(std::string& error)` | Invalidates all permanent verdict entries. Does not answer pending NBLs. |
| `bool RequestShutdown(std::string& error)` | Issues `IOCTL_SHUTDOWN`; does not signal the `Run` stop event or close the handle. |
| `void Stop()` | Signals `Run` and requests shutdown once. Safe to call from callbacks or another thread while `Run` is active. |
| `void Cleanup()` | Calls `Stop`, closes session handles, and resets the record parser. Join/return from `Run` before calling it or destroying the object. The destructor also calls `Cleanup`. |
| `bool Install(const std::wstring& sys_path, std::string& error, bool inbound_udp_pid_fallback = true)` | Compatibility stub: always returns an unsupported-operation error. Use the native installer instead. Neither argument enables a driver-loading or PID-fallback path. |

A typical integration opens the device, checks its version, installs handlers, answers `on_connection` events, and uses `on_poll` for periodic requests and a positive runtime deadline. Call `Stop`, wait for `Run` to finish, then call `Cleanup`. Keep callbacks short enough to answer before the pending timeout.

### Lightweight header-only client

[FirewallXNdisFilter.hpp](monitor/include/FirewallXNdisFilter.hpp) provides the separate **`firewallxndisfilter::Client`** namespace/API. Include just that file in a Windows x64 **C++20** application; no `pmkext` sources, codec, or client library are needed. It uses Kernel32 and Advapi32 (MSVC links Advapi32 through the header's pragma; other toolchains must link it explicitly). A compiled example is [callback_client.cpp](monitor/examples/callback_client.cpp), built as `build/monitor/callback_client.exe`. The example opens a real device if explicitly run; offline tests never run it.

`Run` uses one caller-owned thread: it blocks on overlapped read completion, Stop, or an optional runtime deadline. There is no automatic statistics timer or verdict. The receive buffer grows fallibly for large bandwidth groups. Connection headers, payloads, bandwidth arrays and log-message views borrow that buffer and expire when the callback returns; copy data that must outlive the callback. Bandwidth callbacks run once per nonempty group record, not once per tuple.

| Method | Contract (`DWORD`: 0 is success, otherwise a Win32 error) |
|---|---|
| `Open()` | Consumes a pending Stop with `ERROR_OPERATION_ABORTED` before device access; otherwise tries the existing exclusive Administrator/SYSTEM device. An exclusive-device `ERROR_SHARING_VIOLATION` is returned immediately on any attempt; the caller may retry after the other controller releases its handle. After any other open failure, creates/opens the protected `Global\FirewallXNdisFilter.DriverReady` event, resets it before retrying, then waits **indefinitely**, without device polling or a startup timeout. A signal only requests a retry. `Stop()` cancels this wait with `ERROR_OPERATION_ABORTED`. Never installs/loads the driver. Requires version `{0,3,3,0}` after opening; version/I/O errors are returned rather than treated as startup signals. |
| `Run(const Callbacks&, DWORD duration_ms = INFINITE)` | Blocking callback dispatch on the calling thread. A positive duration limits monitoring only, **not Open's unlimited startup wait**; zero is invalid. Stop/runtime expiry returns success after cancelling/reaping the outstanding read. Unexpected zero-byte reads are an error, not a retry loop. Callback exceptions propagate after pending I/O is reaped. |
| `Stop()` | Thread-safe local stop, usable during Open/Run; wakes the wait. A stop requested while closed cancels the next Open once with `ERROR_OPERATION_ABORTED` before touching the device; a successful Close clears a pending stop. Does not itself shut down policy, close handles or unload the LWF. |
| `Close()` | Returns `ERROR_BUSY` during Run. Otherwise closes handles; device cleanup disconnects policy and releases pending packets through fallback. Join Run and all other callers before Close/destruction. |
| `GetVersion(std::array<uint8_t,4>&)` / `GetFilteredDeviceCount(uint32_t&)` | Synchronous IOCTL queries; exact four-byte replies. Outputs are unchanged on failure. |
| `GetAdapterInfo(AdapterSnapshot&)` | Synchronous variable-size attached-module query with automatic buffer growth, including not-running modules. Owning `Client::AdapterSnapshot` / `Client::AdapterInfo` types have the fields and validity flags documented above. Leaves output unchanged on failure; malformed replies return `ERROR_INVALID_DATA`, allocation failure returns `ERROR_NOT_ENOUGH_MEMORY`. |
| `SendVerdict(uint64_t id, Verdict)` | Sends the fixed ten-byte verdict; values 2..7 only. No verdict-application acknowledgement. |
| `Send(Command)` | Single-byte ClearCache=4, GetLogs=5, GetBandwidthStats=6 or PrintMemoryStats=7. No automatic statistics requests. |
| `Shutdown()` | Calls Stop and issues the policy shutdown IOCTL. Does not close, unload or unbind. |

`Callbacks` contains optional function pointers and their shared `context`:

| Callback | Arguments after `void* context` |
|---|---|
| `on_connection_v4` | `const ConnectionV4* header, const uint8_t* payload, uint32_t payload_size` |
| `on_connection_v6` | `const ConnectionV6* header, const uint8_t* payload, uint32_t payload_size` |
| `on_log` | `uint8_t severity, std::string_view message` |
| `on_bandwidth_v4` | `uint8_t protocol, uint32_t interface_index, const BandwidthV4* entries, uint32_t count` |
| `on_bandwidth_v6` | `uint8_t protocol, uint32_t interface_index, const BandwidthV6* entries, uint32_t count` |

Every header/array/payload pointer refers directly to the validated input buffer and expires when the callback returns. The callback table/context must remain alive throughout Run. Callbacks may send commands/verdicts or call Stop; do not close/destroy the client from a callback. Open/Close are not concurrent operations; only Stop is supported during startup, and commands may run concurrently once Open has succeeded. Slow callbacks still delay verdicts and shutdown.

| Packed type (`Client::`) | Size / fields in wire order |
|---|---|
| `ConnectionV4` / `ConnectionV6` | 27 / 51 bytes: `id:u64`, `interface_index:u32`, `direction:u8`, `protocol:u8`, `local_ip[4/16]`, `remote_ip[4/16]`, `local_port:u16`, `remote_port:u16`, `payload_layer:u8=3`. The following four-byte payload length is validated and passed separately with the complete-IP payload pointer. |
| `BandwidthV4` / `BandwidthV6` | 28 / 52 bytes per entry: `local_ip[4/16]`, `local_port:u16`, `remote_ip[4/16]`, `remote_port:u16`, `transmitted_bytes:u64`, `received_bytes:u64`. The group `interface_index:u32` is in the record header and is passed separately to the callback; one callback receives the entire contiguous array. |

These fixed, trivially-copyable wire views use scoped `#pragma pack(push, 1)` / `pop`, with compile-time size, alignment and offset checks. All numbers are little-endian (native on supported Windows x64); addresses remain network-order bytes. Read packed scalar fields by value; do not pass a field's address/reference to an API expecting naturally aligned integers. IPv4/IPv6 is selected by the callback type, not an added `ipv6` field; no PID/thread ID is present. Direction and policy/fallback semantics are described above. `Verdict` contains Accept=2, PermanentAccept=3, Block=4, PermanentBlock=5, Drop=6 and PermanentDrop=7.

For offline adapter replies, `Client::DecodeAdapterInfo(Bytes, AdapterSnapshot&)` performs the same owning validation/decoding as `GetAdapterInfo`, without device access. Its layout constants are `AdapterInfoVersion=1`, `AdapterInfoHeaderSize=16`, `AdapterInfoEntrySize=1760`, `AdapterNameCapacity=256`, and `AdapterMacCapacity=32`. `MaxAdapters=(UINT32_MAX-16)/1760` and `MaxAdapterInfoSize=16+MaxAdapters*1760` are arithmetic overflow bounds, not allocation targets or configured item quotas; `InitialAdapterInfoSize=56336` is only the initial query capacity. The `Client::Adapter*` flag constants correspond to the `AdapterInfo::` aliases above, with `AdapterKnownFlags=0xff`.

For offline/custom transports, `Client::DispatchRecord(Bytes, callbacks)` validates one complete record before exposing any packed views. The optional `Client::Stream` helper exposes a writable `Buffer()` (at most 65536 bytes), `Commit(written, callbacks)`, `PendingBytes()` and `Reset()`; an invalid stream stays failed until Reset. Fill the latest Buffer and Commit it before asking for another; Buffer may compact storage, so do not retain its pointer across calls. `MaxRecordSize=1048636` is the connection-frame bound and `MaxPayloadSize=1048576` the connection payload bound; bandwidth storage grows fallibly to the full group size, `ReadSize=65536` is the client's streaming chunk size, not a driver read-size limit. The driver never generates connection-END events, and this client does not expose them.

### Callbacks and data types

All `Handlers` members are optional:

| Callback | Argument / execution context |
|---|---|
| `on_connection` | `const Connection&`, on the reader thread. Use `id` when sending a verdict. |
| `on_connection_end` | `const ConnectionEnd&`, compatibility decoder callback on the reader thread; this driver never emits the corresponding records. |
| `on_log` | `const LogLine&`, on the reader thread. |
| `on_bandwidth` | `const BandwidthStats&`, on the reader thread. |
| `on_warning` | `const std::string&`, client-side I/O/protocol diagnostics; may run on the reader or `Run` thread. Not a driver log record. |
| `on_poll` | No arguments, on the thread calling `Run`, once per poll iteration. |

Callback arguments are temporary; copy data needed after the callback returns. Synchronize state shared between reader callbacks and `on_poll`.

| Type | Public fields |
|---|---|
| `Connection` | `bool ipv6`; `uint64_t id`; `uint32_t interface_index`; `uint8_t direction, protocol`; `uint8_t local_ip[16], remote_ip[16]`; `uint16_t local_port, remote_port`; `uint8_t payload_layer`; `uint32_t payload_size`; `std::vector<uint8_t> payload`. |
| `ConnectionEnd` | `bool ipv6`; `uint64_t process_id`; `uint8_t direction, protocol`; `uint8_t local_ip[16], remote_ip[16]`; `uint16_t local_port, remote_port`. No verdict ID or payload. |
| `LogLine` | `Severity severity`; `std::string message`. |
| `BandwidthEntry` | `bool ipv6`; `uint8_t local_ip[16]`; `uint16_t local_port`; `uint8_t remote_ip[16]`; `uint16_t remote_port`; `uint64_t transmitted_bytes, received_bytes`. |
| `BandwidthStats` | `uint8_t protocol`; `uint32_t interface_index`; `std::vector<BandwidthEntry> entries`. The index applies to every entry in this group. |

IP arrays contain network-order address bytes. IPv4 uses the first four bytes; the C++ decoder leaves the remaining bytes zero. `ipv6` is derived from the record type, not a separate wire field. `protocol` is the IP protocol number, for example 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6. Transport ports are zero where unavailable/not applicable. IPv6 extension parsing is bounded to eight headers and the first 320 bytes of the observed NDIS frame. For a single-NB packet whose extension chain exceeds either bound, `protocol` identifies the first unparsed extension and ports remain zero; its captured IP payload is still complete, but an unrecognized TCP/UDP transport cannot contribute to TCP/UDP bandwidth groups or permanent caching.

`Connection`, `ConnectionEnd`, and `BandwidthEntry` provide `LocalIpString()` and `RemoteIpString()`. `Connection::PayloadHexString()` produces lowercase hexadecimal without separators. Additional helpers are `FormatIpv4`, `FormatIpv6`, `NormalizeIpAddress`, `ProtocolToString`, `DirectionToString`, `PayloadLayerToString`, and `ToString` overloads for `Verdict`, `Severity`, and `InfoType`.

### Verdicts, timeout, and caching

| `Verdict` | Byte | Effect |
|---|---:|---|
| `Accept` | 2 | Allow this NBL. |
| `PermanentAccept` | 3 | Allow and cache the TCP/UDP tuple decision when cacheable; matching cache hits refresh its idle TTL. |
| `Block` | 4 | Silently discard this NBL. |
| `PermanentBlock` | 5 | Discard and cache the TCP/UDP tuple decision when cacheable. |
| `Drop` | 6 | Silently discard this NBL; same data-path action as Block. |
| `PermanentDrop` | 7 | Discard and cache the TCP/UDP tuple decision when cacheable. |

No TCP RST or ICMP rejection is generated. `Undecided=0`, `Undeterminable=1`, `RedirectNameServer=8`, `RedirectTunnel=9`, `Failed=10`, and `RedirectSplitTunnel=11` are not accepted as verdicts.

Pending decisions have a **8000 ms default deadline**, measured from classification, not from when an application reads the event. The driver checks timeouts every **1 second only while pending NBLs exist**, so fallback may run up to roughly one additional check interval after the deadline, plus DPC scheduling delay. Verdicts are still checked against the actual deadline and applied immediately when valid; they do not wait for the timer. The default fallback is **fail-closed (drop)** on missing controller, disconnect/shutdown, timeout, or policy/queue limits. Without a controller, eligible transit IP packets are dropped immediately; with a controller online, an uncached packet waits for a userspace verdict until its deadline and is dropped if unanswered. Local-address exemptions and unavailable-inventory bypass are applied before policy. A valid cached PermanentAccept is still an explicit userspace decision and may admit matching traffic while that session remains online. Disconnect/shutdown clears those cached decisions. Non-IP control-frame bypass is unchanged. Pause/invalidated attachments, malformed packets, unsupported copy metadata, and unsafe copy cases always drop, even if fail-open is explicitly configured.

A permanent decision is a **TTL cache entry for TCP/UDP only**, not lifetime socket permission. **Every host `interface_index` has four independent, dynamically growing hash tables: TCP/IPv4, UDP/IPv4, TCP/IPv6, and UDP/IPv6.** There is no configured maximum entry count and no capacity-driven eviction of live decisions. Other IP protocols (including ICMP/ICMPv6) never create or use permanent entries: a permanent verdict applies only to that NBL, and the next packet still needs a decision.

Within each table, the key is the full normalized `local_ip, local_port, remote_ip, remote_port` tuple. Both directions and different VLANs share a decision when the tuples match **within the same interface, protocol, and IP family**. NDIS path/direction, VLAN, module ID, epoch and Ethernet MAC addresses do not distinguish entries. TCP and UDP, different interface indices, and different IP families have separate caches.

Expired entries stop matching immediately. While caches are nonempty, the driver automatically requests a full expiry sweep every 10 seconds; the monitor does not need to request cleanup.

Except for the 1000 queued-LogLine limit described above, pending decisions, event queues, bandwidth storage, and receive-copy data have no fixed item-count or aggregate byte quota. Nonpaged-pool exhaustion can bugcheck the machine. Bandwidth counters use saturating 64-bit arithmetic.

`PrintMemoryStats` queues an Info `LogLine` containing only counts of elements in the policy engine's collections:

| Field | Count |
|---|---|
| `pending` | Pending NBLs not yet claimed for completion, including expired or invalidated requests awaiting drain. |
| `pending_nodes` | Allocated pending nodes, including a claimed decision retained by a partially read event. |
| `events` | Queued events before the statistics `LogLine` itself is queued, including partially read events. |
| `interfaces` | Interface contexts, including detached contexts awaiting cache reclamation. |
| `bandwidth` | Entries in the active and retry bandwidth stores; an in-flight detached report is not included, and retry stores can contain duplicate keys. |
| `cached_tcp_v4`, `cached_udp_v4`, `cached_tcp_v6`, `cached_udp_v6` | Entries in each protocol/family cache, summed across interface contexts and current/previous tables. Entries awaiting expiry or invalidation cleanup are included until reclaimed. |

These are collection counts, not byte sizes, capacities, traffic counters, or a complete accounting of detached and retired storage. If a cache entry cannot be inserted, the current packet still receives its requested verdict, but later traffic requires another decision.

The default TTL is **60000 ms**. `PermanentAccept` uses a **sliding idle timeout**: the initial deadline is set when the verdict is applied, and each cacheable TCP/UDP packet actually admitted by that still-valid entry resets the deadline to its classification time plus `CacheTtlMs`. Either direction refreshes the matching tuple in that protocol-specific table; TCP traffic cannot refresh a UDP entry or vice versa. Preliminary cache checks and uncacheable packets do not refresh it. At or after the deadline, a packet needs a new decision rather than reviving the expired entry. `PermanentBlock` and `PermanentDrop` retain a **fixed TTL from verdict application**; matching traffic does not extend them.

Fragments, offloaded/incomplete transport headers, and multi-NB batches cannot seed or refresh permanent entries. Clear-cache and a new/disconnected controller session reset all four tables on every interface. NDIS pause, attachment invalidation or detach also invalidates that interface's pending IDs and caches; other interfaces retain their entries.

Optional service `Parameters` values, all `REG_DWORD`, are read when the SYS loads: `DecisionTimeoutMs=8000` (clamped to 100–60000), `CacheTtlMs=60000` (1000–300000), and `FailClosed=1` (the default; an explicit `0` opts into fail-open for controller/timeout/queue fallback). These are driver configuration, not protocol commands.

Late, duplicate, unknown, cancelled, or already-completed IDs are harmless no-ops: a successful verdict write is **not an acknowledgement that the NBL still existed**. Such writes do not create cache entries. There is no per-verdict response record.

### Event framing and layouts

Events use explicit byte encoding, never native C++/Rust structure layout:

```text
[type:u8][body_size:u32 LE][body:body_size bytes]
```

The header is five bytes. `body_size` excludes the header. A complete **connection** record is at most **1048636 bytes** (`1 MiB + 60`, the IPv6 prefix); the IPv4 prefix is 36 bytes. Log records retain their separate 512-byte bound. Bandwidth records have no configured frame-size or entry-count cap: their lengths/counts must fit the explicit `u32` fields and allocation must succeed. All numeric fields, **including ports**, are little-endian. IP address bytes are in network order. There is no padding or implicit string terminator. In layouts below, `A=4` for IPv4 and `A=16` for IPv6.

| `InfoType` | Byte | Body layout / availability |
|---|---:|---|
| `LogLine` | 0 | `[severity:u8][message:remaining bytes]`. |
| `ConnectionIpv4` | 1 | Connection layout below, `A=4`. |
| `ConnectionIpv6` | 2 | Connection layout below, `A=16`. |
| `ConnectionEndEventV4` | 3 | Compatibility-only END layout, `A=4`; never emitted. |
| `ConnectionEndEventV6` | 4 | Compatibility-only END layout, `A=16`; never emitted. |
| `BandwidthStatsV4` | 5 | Bandwidth layout below, `A=4`. |
| `BandwidthStatsV6` | 6 | Bandwidth layout below, `A=16`. |

**Connection body**, in order:

| Field | Encoding / meaning |
|---|---|
| `id` | `u64`, pending NBL verdict ID. |
| `interface_index` | `u32`, host adapter index (`BaseMiniportIfIndex`), not a guest interface index. |
| `direction` | `u8`: host receive=0 / host send=1. |
| `protocol` | `u8`, IP protocol number. |
| `local_ip` | `A` raw bytes, observed source on host receive or destination on host send. |
| `remote_ip` | `A` raw bytes, observed destination on host receive or source on host send. |
| `local_port` | `u16`. |
| `remote_port` | `u16`. |
| `payload_layer` | `u8`, always 3. |
| `payload_size` | `u32`, complete observed IP packet length, at most 1048576. |
| `payload` | Exactly `payload_size` bytes, starting with the original IP header; never a shortened capture. |

Body size is `31 + payload_size` for IPv4 or `55 + payload_size` for IPv6; total frame size is respectively `36 + payload_size` or `60 + payload_size`. No process-ID bytes or alignment padding are present.

**END compatibility body**, understood by the client but not produced by the LWF:

```text
[process_id:u64=0][direction:u8][protocol:u8]
[local_ip:A bytes][remote_ip:A bytes][local_port:u16][remote_port:u16]
```

Its body size is 22 bytes for IPv4 or 46 for IPv6. No ID, payload, or timestamp is present.

**Log body:** severity is `Trace=1`, `Debug=2`, `Info=3`, `Warning=4`, `Error=5`, `Critical=6`, or `Disabled=7`. The rest is the message, without a trailing NUL; driver-generated messages are UTF-8. The maximum message length is 506 bytes. Memory statistics are ordinary Info-level `LogLine` records, not a separate event type.

**Bandwidth body:**

```text
[protocol:u8][interface_index:u32][count:u32]
repeat count times:
  [local_ip:A bytes][local_port:u16]
  [remote_ip:A bytes][remote_port:u16]
  [transmitted_bytes:u64][received_bytes:u64]
```

Each entry is 28 bytes for IPv4 or 52 for IPv6; body size is `9 + count * entry_size` (37 bytes for one IPv4 entry, 61 bytes for one IPv6 entry). The driver emits **all entries for one host interface, protocol and IP family in a single record**, without an artificial count cap, a 1 MiB bandwidth-frame limit, or splitting the group. The shared `interface_index` is the host adapter index at the interception point; it keeps identical normalized tuples on different host adapters separate and is not repeated per entry. Body size and count must fit their `u32` fields. Unlike connection records, each address is immediately followed by its port.

Bandwidth counts **admitted TCP/UDP IP bytes** while the controller is online, grouped by host `interface_index` and normalized tuple. `transmitted_bytes` corresponds to host receive and `received_bytes` to host send; these are guest-relative only on an appropriate guest-facing adapter. Disconnection discards accumulated data, and collection starts fresh when a controller reconnects. These are deltas since the bucket was created or last successfully queued by `GetBandwidthStats`, not cumulative per-socket totals. If a complete group cannot be queued, all of its unreported counters are retained for a later request. The number of distinct buckets has no fixed ceiling; byte counters are 64-bit, records contain no PID, and the counters do not prove delivery to the destination.

### Commands and write validation

Commands are **unframed**, unlike events. One write can concatenate complete commands, with a nonzero total size fitting the native Windows **DWORD/u32** I/O length; there is no driver-defined 64 KiB limit. The whole batch is validated before any command is applied; a malformed/unsupported suffix prevents earlier commands in that batch from taking effect. This is syntactic validation, not a transactional acknowledgement of live event IDs.

| `CommandType` | Byte | Wire size | Effect |
|---|---:|---:|---|
| `Shutdown` | 0 | 1 | Same policy-session effect as `IOCTL_SHUTDOWN`. |
| `Verdict` | 1 | 10 | `[1:u8][id:u64 LE][verdict:u8]`. |
| `UpdateV4` | 2 | Unsupported | Rejected; no update layout is implemented. |
| `UpdateV6` | 3 | Unsupported | Rejected; no update layout is implemented. |
| `ClearCache` | 4 | 1 | Invalidates all permanent-cache entries. |
| `GetLogs` | 5 | 1 | Compatibility no-op; log records are already queued. |
| `GetBandwidthStats` | 6 | 1 | Queues bandwidth deltas for active buckets. |
| `PrintMemoryStats` | 7 | 1 | Queues an Info `LogLine` containing policy collection element counts. |
| `CleanEndedConnections` | 8 | Unsupported | Rejected; expiry cleanup is automatic. |

Single-byte commands contain only their command byte. Command byte 8 is unsupported, including when it follows otherwise valid commands; the entire batch is rejected before any command takes effect. Request results are read asynchronously from the same event stream; there is no correlation ID or separate acknowledgement. Diagnostic/statistics records need not be queued when no data is available or a size limit is exceeded.

Empty/truncated writes are rejected with `STATUS_INVALID_PARAMETER`; unsupported command/verdict values and unknown IOCTLs use `STATUS_NOT_SUPPORTED`. A second controller is rejected with `STATUS_SHARING_VIOLATION`. Version and filtered-device-count queries with an undersized output buffer use `STATUS_BUFFER_TOO_SMALL`. The filtered-device-count query rejects nonempty input with `STATUS_INVALID_PARAMETER`. The C++ client validates commands locally before writing and reports Windows I/O failures through `error`.

### Device-independent codec helpers

`pmkext::wire` exposes `IsCompatibleVersion`, `DecodeFilteredDeviceCount`, `DecodeAdapterInfoHeader`, `DecodeAdapterInfo`, `IsSupportedVerdict`, `ValidateCommands`, `EncodeVerdict`, and `DispatchRecord`. `DecodeAdapterInfoHeader(bytes, length, uint32_t& required_size, error)` validates a header prefix of at least 16 bytes, checks schema/count/running-count arithmetic, and computes the complete reply size without allocating; it leaves `required_size` unchanged on failure and does not validate the following entries. `DecodeAdapterInfo(bytes, length, AdapterSnapshot&, error)` validates and decodes exactly one complete adapter snapshot, leaving output unchanged on failure. Its constants are `kIoctlAdapterInfo=0x9C40E00C`, `kAdapterInfoVersion=1`, `kAdapterInfoHeaderSize=16`, `kAdapterInfoEntrySize=1760`, `kAdapterNameCapacity=256`, `kMaxAdapters=(UINT32_MAX-16)/1760`, and `kMaxAdapterInfoSize=16+kMaxAdapters*1760`; the last two are checked-length arithmetic bounds, not preallocation sizes or item quotas. `kInitialAdapterInfoSize=56336` is only the initial query capacity. `IsCompatibleVersion` accepts exactly `kRequiredDeviceVersion={0,3,3,0}`; `Open` itself does not perform this check. `DecodeFilteredDeviceCount` requires a non-null, exactly four-byte little-endian reply and leaves its output unchanged on failure. `EncodeVerdict` fills a fixed ten-byte array; `DispatchRecord` validates exactly one complete frame before invoking its handler.

`RecordStream::Feed(bytes, length, callback, error)` accepts arbitrary read boundaries and invokes the callback for each complete frame. `PendingBytes()` reports buffered incomplete bytes; `Reset()` discards buffered state. A malformed header or an oversized connection/log record invalidates the stream until reset; it does not guess a new boundary. The stream assembles one record across arbitrary driver reads, growing heap storage fallibly for bandwidth groups beyond the connection-frame bound. Constants are `kRecordHeaderSize=5`, `kConnectionIpv4PrefixSize=36`, `kConnectionIpv6PrefixSize=60`, `kMaxPayloadSize=1048576`, `kMaxRecordSize=1048636` (connection frames only), `kMaxLogRecordSize=512`, `kMaxCommandBatchSize=UINT32_MAX`, and `kVerdictCommandSize=10`.

## License

Copyright (c) 2026 FirewallXNdisFilter contributors. Licensed under **GNU General Public License version 3 only** (`GPL-3.0-only`); see [LICENSE](LICENSE). The adapted monitor retains its original GPLv3 license and source-provenance notices; see [monitor/README.md](monitor/README.md) and [monitor/LICENSE](monitor/LICENSE).
