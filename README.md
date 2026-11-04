# HyperVXNdisFilter

Experimental Rust-based **NDIS 6.89 Lightweight Filter (LWF)** with additional **WFP IPFORWARD IPv4/IPv6 callouts** and a C++ monitor with a `kext_monitor`-style API. The NDIS path targets **all Hyper-V management-OS Ethernet host adapters associated with HNS networks of type `ICS`**, regardless of network, switch or adapter names. WFP independently filters **all traffic presented at `FWPM_LAYER_IPFORWARD_V4/V6`**, including forwarding through physical and VPN interfaces. This includes Default Switch and WSL (Hyper-V firewall) when their HNS networks are ICS. It is not a Hyper-V switch extension; WFP does not replace the LWF.

Driver package and device API: **0.3.3.0**. Connection records add the host adapter `interface_index:u32` immediately after `id:u64`, and bandwidth group headers now carry the same index. This breaks compatibility with 0.3.2.0 and earlier event layouts; nonzero reads still wait for event data and support cancellation. Use a matching SYS and monitor; the monitor rejects older device versions.

Coverage consists of the restricted host-vNIC NDIS path and unrestricted routed IP traffic at WFP IPFORWARD. Host-local traffic and packets switched without reaching those layers are not covered by WFP IPFORWARD. VM-to-VM traffic is not guaranteed to be visible. The installer and kernel check the exact adapter GUID/NET_LUID, not its display name. The complete eligible ICS adapter set is captured during installation. Adding/removing an ICS target, changing network type or recreating an adapter requires explicit uninstall/reinstall; setup does not silently expand or retarget the stored set.

## Build

Requires Windows x64 **build 25341+**, Hyper-V with at least one HNS ICS network, Visual Studio C++ x64 tools with CMake/Ninja, Rust 1.91+ with the `x86_64-pc-windows-msvc` target, WDK/SDK **10.0.28000.0**, and LLVM with **libclang**. Kernel builds are **release-only**. `LIBCLANG_PATH` may select the LLVM `bin` directory; otherwise the generator uses `%ProgramFiles%\LLVM\bin`.

The LWF builds against `NDIS689=1` and selects the highest supported runtime version with `NdisGetVersion`: **6.40, 6.50, 6.51, 6.60, 6.70, and 6.80 through 6.89**. Registration uses revision 2 below 6.80 and revision 3 from 6.80; direct and synchronous OIDs bypass it. Resource-copy metadata scans use the corresponding runtime OOB bounds, not a newer structure size on older runtimes. The existing package OS minimum is unchanged; runtime compatibility is not a claim that the current notify-object package installs on older Windows releases. **UDP Receive Segment Coalescing Offload (URO)** is supported on the NDIS receive path: original NBLs retain their packet/OOB state, and private `RESOURCES` copies preserve the inline `SegCount`/`SegSize` metadata and receive-checksum information. The complete logical UDP packet is exposed in one event without rewriting checksum fields, and coalesced/segmented packets never use, seed or refresh permanent verdict caches. UDP segmentation offload (USO) is recognized on sends. Unknown pointer-bearing OOB metadata is still rejected for private receive copies. See Microsoft's [NDIS 6.89 requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/introduction-to-ndis-6-89) and [URO specification](https://github.com/microsoft/net-offloads/blob/main/udp-rsc-offload.md).

WFP is unchanged and does not opt into `FWP_CALLOUT_FLAG_ALLOW_URO`; this NDIS support does not claim WFP URO clone/reinjection support. Windows may suppress URO for incompatible components at URO-sensitive layers. The device/wire API remains **0.3.3.0**.

The intermediate-version contracts are handled as follows ([version overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/overview-of-ndis-versions)):

| NDIS versions | LWF behavior |
| --- | --- |
| 6.40, 6.50, 6.51, 6.60 | Revision 2 registration; version-appropriate OOB bounds. Optional dynamic MAC/MTU capabilities are not advertised. |
| 6.70 | Ordinary LWF callbacks remain valid with NetAdapterCx miniports; no dependency on deprecated TCP Chimney/IPsec offload. |
| 6.80, 6.81, 6.82 | Revision 3 registration; synchronous OID/RSSv2 requests bypass the LWF rather than being pended or cloned as regular OIDs. |
| 6.83, 6.84 | USO and UDP receive-coalescing scalar metadata are recognized without treating logical packets as cacheable datagrams. |
| 6.85 | Miniport Poll Mode needs no new LWF callback; original USO NBLs retain encapsulation/offload OOB without copying borrowed pointers. |
| 6.86, 6.87, 6.88 | Existing callback, ownership and bounded packet rules continue to apply; unknown receive-copy OOB remains fail-closed. |
| 6.89 | NDIS URO is accepted with checksum/segment metadata retained; no URO opt-out flag is set. |

These are compatibility rules for this Ethernet LWF, not an implementation of every optional miniport, RDMA, wireless or switch-extension feature. Registration selection and structure/OOB boundaries are covered offline; successful installation and live validation on each Windows runtime are separate requirements.

The kernel is Rust, including its native WDK ABI: [NDIS callbacks and ownership](driver/src/native_ndis.rs), [NBL/NB/MDL operations](driver/src/native_packet.rs), [IRP/CSQ and device lifetime](driver/src/native_device.rs), [registry and readiness](driver/src/native_registry.rs), and [native WFP calls](driver/src/native_wfp.rs). [The build-time generator](driver/build.rs) uses `windows-drivers-rs`'s `wdk-build` configuration and `bindgen` against installed WDK headers; NDIS/WFP/NETIO bindings and evaluated SDK size constants are generated into `OUT_DIR`, not manually copied into source. Neither build tooling nor `windows-sys` is linked into the kernel. Allocation remains fallible and ownership/IRQL/error checks are preserved; branch hints favor successful allocation, never an allow verdict.

Portable control/diagnostic logic is also Rust: [device control](driver/src/device_control.rs) validates IOCTLs and encodes small replies, [adapter information](driver/src/adapter_info.rs) owns the schema-1 encoder/size planner and bounded UTF-16 handling, and [target admission](driver/src/target_config.rs) validates the kernel allowlist. The [adapter storage declarations](driver/shim/adapter_info.h) remain only for user-mode fixture interoperability, with checked C/Rust offsets; storage is never copied as a wire reply. Native offline tests execute the production Rust modules on actual generated WDK layouts with fake OS calls. C++ remains in the user-mode installer, notify DLL and clients, not in the SYS. The wire/API and filtering behavior are unchanged.

Commands below use Git Bash at the repository root:

```bash
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts/Build.ps1 -Test
```

This builds the package and runs offline tests without installing, loading, or binding the driver. Output goes to `dist/`: **`HyperVXNdisFilter.sys`**, `HyperVXNdisFilter.inf`, `HyperVXNdisFilter.cat`, `HyperVXNdisFilterNotify.dll`, `hyperv_monitor.exe`, `Install.exe`, and `Uninstall.exe`, together with a matching full `.pdb` for every SYS/DLL/EXE. Keep package files together; do not mix versions.

Rust and MSVC targets, including Release examples and tests, retain full debug information (`debuginfo=2`, `/Zi`, `/DEBUG:FULL`). `/PDBALTPATH:%_PDB%` embeds only the PDB filename, not the local build path. Release optimizations remain enabled. The build rejects SYS imports outside the kernel-module allowlist before signing. The SYS also embeds the [driver version resource](driver/version.rc): file/product version **0.3.3.0**, network-driver type, and product/filename metadata matching the package.

All product identities use the new name: service `HyperVXNdisFilter`, device `\\.\HyperVXNdisFilter`, startup event `Global\HyperVXNdisFilter.DriverReady`, NetCfg component `hyperv_xndis_filter`, and header-only client `HyperVXNdisFilter.hpp` / `hypervxndisfilter::Client`. The rename preserved the IOCTLs and product GUIDs; the current 0.3.3.0 Connection and Bandwidth API exposes the host adapter index; old header/namespace/device aliases are not provided. Use a clean `dist/` when rebuilding after the rename and deploy the entire new package, not individually renamed binaries. An existing installation under a previous name must first be removed with **its matching old `Uninstall.exe`**. The new installer rejects another component with the same filter GUID; it does not migrate, replace or remove it automatically.

The default build is unsigned. For signing, pass `-PfxPath` and `-RootCertificate` to the build script. Every signature requests an RFC 3161 SHA-256 timestamp from `http://timestamp.digicert.com`; `-TimestampUrl` selects another TSA. Signing therefore requires access to that service, which receives a hash, not the binary or private key. The local test-PFX password defaults to `1`; a nonempty process environment variable `HYPERVXNDISFILTER_PFX_PASSWORD` overrides that default, and an explicit `-PfxPassword` overrides both (including an explicitly empty password). The script does not import certificates or change security policy. Installation requires trusted package signatures.

The separate [offline cache lookup benchmark](policy/examples/README.md) compares the actual driver cache with standard Rust `HashMap`/`BTreeMap` variants on generated IPv4/IPv6 TCP tuples within one protocol scope. Its signed user-mode runner does not build/install/open the driver or change the production cache.

## Install

Use an **elevated Administrator/SYSTEM console**, stop the monitor, and have local recovery access: network reconfiguration may interrupt connectivity. **The running filter is fail-closed by default: all IPFORWARD traffic, including shared Internet access, and target-interface NDIS IP traffic are dropped while no userspace controller is connected.** If already installed, use `Uninstall.exe` first; the installer does not replace a live driver.

```bash
./dist/Install.exe
```

The native installer reads the package beside its EXE and enables HyperVXNdisFilter on every eligible HNS ICS host vNIC present during installation. It never starts WSL or creates/changes HNS networks. Default Switch and WSL are examples, not a name allowlist or a mandatory pair. Non-ICS networks are excluded even if their names match those examples. No eligible ICS network, or malformed/ambiguous ICS topology, aborts installation rather than choosing a fallback. `--what-if` performs read-only preflight; `--yes` skips confirmation only.

Before activation, setup also checks every existing HyperVXNdisFilter Driver Store candidate and the actual package returned by staging. Its INF, SYS, notify DLL and catalog must match the validated source **byte for byte**; matching INF/version/signatures alone is insufficient. A conflicting old staged package aborts installation before NetCfg `Install`/`Apply`, even when no service or binding remains. Explicitly run the matching `Uninstall.exe` first; installation never overwrites or silently purges old packages. Verified source/store files remain read-locked through activation.

The [native HNS discovery](install/console/Hns.cpp) selects records by `Type=ICS` and obtains their `SwitchGuid`. Network IDs must be valid and unique; they need not equal switch GUIDs. Setup follows each switch through Hyper-V management-OS port associations to all of its exact host interface GUIDs and verifies their NET_LUIDs through NETIO. Shared switch references are deduplicated. The notify DLL and kernel independently enforce the resulting NDIS GUID/LUID allowlist; physical, non-Ethernet and unrelated virtual adapters remain forbidden as LWF bindings. This does not restrict the independent global WFP forwarding path.

Target configuration uses **`ConfigVersion=3`** and an atomic `TargetAdapters` REG_BINARY allowlist: `[count:u32 LE]` followed by `count` entries of `[Windows GUID:16 bytes][NET_LUID:u64 LE]`. There is no two-adapter/fixed-capacity limit: count is positive and checked against the native `u32` value length; allocation is fallible. Zero/duplicate identities, length overflow and malformed records are rejected by the [shared codec](driver/shim/target_config.h). Writers use stable GUID ordering; comparisons do not depend on enumeration or stored entry order. Readers size the actual value and retry boundedly if it grows. This setup schema is independent of the unchanged **0.3.3.0** event/API version. Older schema-2 configurations require explicit uninstall/reinstall; `--enable` never changes a stored target set. Use a coherent SYS/notify DLL/setup package, not older limited-list binaries, and never replace an installed SYS or edit configuration manually.

If installation returns **3010**, reboot, then resume explicitly:

```bash
./dist/Install.exe --enable
```

### Controller-managed binding recovery

`HKLM\SOFTWARE\HyperVXNdisFilter\Lwf` separates current attach admission (`AllowBindings`) from permission for runtime repair (`AutoRepairAllowed`). Setup durably writes `AutoRepairAllowed=0` before installation, resume or removal and publishes `1` only after the exact target paths have enabled successfully. A failed setup or a requested reboot remains installer-controlled; complete the reboot and explicit resume instead of overriding these flags.

A compatible controller may use `AutoRepairAllowed=1` to retry a transient runtime failure only for the existing schema-3 target set. It must understand the complete allowlist, revalidate every identity through HNS/Hyper-V/NETIO, hold the NetCfg write lock, refuse enabled foreign paths, and disarm/disable only the exact target paths before re-enabling them. It must not add newly discovered ICS targets, rewrite a recreated adapter identity, or treat old single-target recovery support as schema-3 compatibility. Such changes require explicit uninstall/reinstall. A NetCfg reboot request blocks further automatic repair. NetCfg enabled state alone is not proof of a running NDIS module.

### Forwarded IPv4/IPv6

The same SYS registers callouts at `FWPM_LAYER_IPFORWARD_V4` and `FWPM_LAYER_IPFORWARD_V6`. No separate WFP installer, service, controller or protocol is needed. [WFP registration](driver/src/wfp.rs) creates **two unconditional dynamic filters**, one per family, in the shared private sublayer requesting **weight `0x7100`**, below **`FWPM_SUBLAYER_UNIVERSAL` (`0x8000`)**. BFE may assign a nearby available weight if the requested value is already occupied. They do not depend on HNS discovery, NDIS bindings, an adapter allowlist, or an attached LWF module. A route between two NDIS targets is not rejected merely for that reason.

[Rust WFP code](driver/src/wfp.rs) owns registration/retry/teardown, classification and packet-ownership decisions, reinjection routing and failure reporting. [Checksum restoration](driver/src/wfp_checksum.rs) handles split MDLs without linearizing packets or allocating payload buffers. The [native Rust WDK boundary](driver/src/native_wfp.rs) owns callbacks, WDK structure construction, synchronization storage and NB/NBL/MDL access; kernel WFP calls link through `fwpkclnt.lib`. Offline WFP tests execute both production Rust layers using generated WDK layouts and fake native APIs; no duplicate C++ implementation is retained.

Both sources use **one policy engine and the same pending/event, cache and bandwidth structures**. The public verdict ID identifies the one pending record holding the actual NBL. There is no separate opaque packet token, token hash table, policy generation or source-specific flow mirror. The NBL itself carries only the ownership/completion context required by NDIS or WFP. Forwarding interfaces join the existing per-interface cache state when observed; WFP does not enumerate NETIO interfaces or schedule extra cache resets/work on interface connect/disconnect. Existing NDIS pause/detach invalidation remains in place.

The existing verdicts apply unchanged. An uncached forwarded packet is retained with WFP clone/reassembly ownership and the original is blocked/absorbed. Accept normally reinjects it through the original destination interface and available routing compartment; weak-host inbound/outbound pass-through uses the corresponding network-receive/network-send injection API. Before pending reinjection, complete datagrams receive software IPv4-header and TCP/UDP/ICMPv4/ICMPv6 checksums, including IPv6 pseudo-header lengths after extension headers; this does not depend on receive-checksum success or checksum metadata surviving cloning. Software-completed packets have their checksum-offload request cleared. Non-atomic fragments retain their transport checksum, and logical LSO/RSC buffers retain their existing offload profile rather than being treated as wire datagrams. Block/Drop discard without RST/ICMP. Synchronous allows, including cache hits, soft-permit the original instead of reinjecting. Once a pending record is published, the classifier never dereferences its NBL again; even an early verdict uses the normal injection/free path. WFP fragment groups are reassembled before inspection and never use or seed permanent caches. Malformed or unsupported packet ownership/metadata is rejected.

Injection submission/completion failures produce Warning `LogLine` records with the NTSTATUS, injection route and destination interface. Repeated failures are reported at counts 1, 2, 4, 8, ... per controller session to limit diagnostic pressure. A successful verdict write is not an injection or delivery acknowledgement.

IPFORWARD has no intrinsic guest side. Each WFP event is **source-interface-relative**: `interface_index=SOURCE_INTERFACE_INDEX`, `direction=0`, `local_*` is the observed IP source and `remote_*` the destination. A reply is another source-relative observation, normally under another ingress index; it is not reconstructed as guest-inbound traffic. WFP admitted bytes contribute TX for that source-relative tuple. NDIS keeps its guest-relative direction and TX/RX semantics. NAT can change the addresses observed at either point.

IPFORWARD requires the Windows **Base Filtering Engine (BFE)**. Dynamic objects are recreated after a BFE restart. Registration failures are logged and retried without changing NDIS attachments or network configuration. WFP cannot enforce policy while BFE or its filters are unavailable, even with `FailClosed=1`. Running-module counts and adapter snapshots describe NDIS only; an IPFORWARD event can name an interface absent from that snapshot.

Both paths share the same exclusive device session, ID namespace and per-interface TCP/UDP caches. They are independent observation points, not a packet-deduplication facility: a temporary Accept may be needed at each point, and admitted bytes can be counted twice if a packet traverses both. Only matching normalized tuples within the same interface/protocol/family share permanent decisions. Events add no source tag, PID or VM identity; wire/API version remains **0.3.3.0**.

## Monitor

Start with the default PermanentAccept policy:

```bash
./dist/hyperv_monitor.exe --duration 15 --timestamps --memory-stats --out allow.log
```

Block only a test remote endpoint:

```bash
./dist/hyperv_monitor.exe --duration 10 --match 192.0.2.10:9000 --verdict permanent-block --out block.log
```

For an interactive session, omit `--duration` and exit with **Ctrl+C**:

```bash
./dist/hyperv_monitor.exe
```

If `\\.\HyperVXNdisFilter` is absent, the monitor loads `HyperVXNdisFilter.sys` from its **EXE directory**, or from `--sys PATH`. It creates a temporary demand-start kernel service when none exists, setting its `Parameters\StandaloneWfp=1`: this loads **WFP IPFORWARD and the control device only**, without installing a NetCfg component or creating NDIS bindings. Loading requires elevation and a SYS accepted by Windows signing policy. An existing service is never reconfigured; an explicit conflicting SYS path is refused. Busy-device and access-denied errors do not trigger loading.

```bash
./dist/hyperv_monitor.exe --sys 'C:/drivers/HyperVXNdisFilter.sys' --duration 15
```

Without `--duration`, monitoring ends on Ctrl+C. A positive `--duration N` limits monitoring, not the synchronous SCM load. Startup failures return an error rather than waiting indefinitely. Zero, negative and malformed durations remain invalid.

The monitor prints `Filtered network devices: N (running NDIS modules)` after the version check and whenever the count changes, checking at the `--poll` interval (default 1000 ms). This is the driver's live attachment/running-state count, not the number of configured or enabled bindings. A loaded driver can report zero. Status lines honor `--out` and `--timestamps`. If the installed SYS lacks the new IOCTL or a query fails, the monitor warns that the count is unavailable rather than reporting zero; monitoring continues and later polls retry.

At startup it also prints `Attached network adapters: N` and one `[ADAPTER]` block per attached module: names, host indices/GUID/LUIDs, running state, MAC, media/link/duplex, speeds, MTU and available general NDIS attributes. Paused modules remain visible as not-running. Unknown fields and truncated names are labelled explicitly. This one-time diagnostic honors `--out`/`--timestamps`; an unavailable query warns without stopping monitoring. See the complete snapshot API below.

Each `[CONN v4]` / `[CONN v6]` header prints `interface_index=N` immediately after `id`, in both console output and `--out` files. This is the host adapter index from that event, not a guest interface index; traffic from different adapters retains its own value.

The console discovers enabled **public/upstream ICS interfaces** through read-only native sharing APIs and resolves their connection GUIDs to host indices through NETIO. For those indices only, it reverses CONN direction (`0`/`1`), swaps local/remote IP addresses and ports, and swaps bandwidth endpoints and TX/RX counters. Private/downstream and nonshared interfaces are unchanged. The list is refreshed at startup and each `--poll`; status changes honor `--out`/`--timestamps`. Discovery failures warn once per failure streak, clear stale roles, and use raw driver orientation until recovery. No ICS configuration is changed.

This is **console-only presentation**, applied before `--match` selects the presented remote peer. Packet bytes, IDs, interface indices, driver policy/caches and both reusable client APIs remain unchanged. NDIS and WFP records have no source tag, so the index-based rule applies to either path; it does not correlate NAT tuples or merge records from different interfaces.

`--match` selects the remote endpoint in both directions; unmatched events receive PermanentAccept. `--filter-ip` only filters output, not verdicts. A blocking verdict without `--match` applies to every event and can disconnect host-vNIC or routed traffic.

On exit, the monitor closes its device session before stopping a driver it started and deleting a service it created. A previously running driver is left running; a preexisting stopped service started by the monitor is stopped but not deleted. Cleanup also runs after startup/version errors; stop/delete failures are reported. Forced process termination cannot guarantee cleanup. A driver installed through NetCfg remains installed/bound; use `Uninstall.exe` to remove it. `--help` performs no device or SCM access.

## Remove

Stop the monitor, then run from an elevated console:

```bash
./dist/Uninstall.exe
```

Uninstall first disarms and removes the `hyperv_xndis_filter` NetCfg component, then removes **all identified HyperVXNdisFilter driver-package versions** from Driver Store, including old `HyperVXNdisFilter.sys` copies under `FileRepository`. Windows driver-installation APIs perform the deletion; the program never takes ownership of Driver Store folders or deletes them manually. Package ownership is checked from the original INF name, NetService class, every component model, filter instance GUID, and service/SYS identity, without requiring the current package version. Unrelated driver packages are not selected.

After the component and service are gone and package removal completes, setup also unregisters only this package's notify COM class before deleting the target configuration. Missing registration is harmless; cleanup errors remain failures, leaving configuration disarmed for a retry.

`--what-if` lists matching published OEM INFs without changing system state. Cleanup also works when the component is already absent and only old staged packages remain. Exit **0** requires a fresh inventory with no matching packages; partial failure is reported, not ignored. If component/package removal returns **3010**, reboot and run `Uninstall.exe` again before reinstalling. Busy packages are never forcibly deleted; no manual SCM service creation/deletion is needed.

## API

The public C++ interface is [PortmasterKext.h](monitor/include/PortmasterKext.h), namespace `pmkext`. The wire codec is [DriverProtocol.h](monitor/include/DriverProtocol.h); driver-side event/command encoding is defined in [protocol/src/lib.rs](protocol/src/lib.rs), with the separate adapter-snapshot codec in [adapter_info.rs](driver/src/adapter_info.rs).

### Semantics and compatibility

- **ConnectionIpv4/ConnectionIpv6 have no `process_id` field.** The `interface_index:u32` after `id` identifies the host adapter at the interception point (`BaseMiniportIfIndex` for NDIS, `SOURCE_INTERFACE_INDEX` for WFP), not an interface inside the guest. It is retained with each pending packet and bandwidth group, so interleaved traffic from different interfaces keeps its own index. There is no compartment/sub-interface ID, TID, switch/port/GUID/LUID field, and no host-process or individual-VM ownership is inferred. Interface indices can change or be reused after adapter recreation; they are not permanent identities. Existing exact-target binding restrictions are unchanged. Unused legacy END compatibility records retain their zero PID.
- NDIS: `direction=0` is **guest/Sandbox outbound** (host receive), `direction=1` is **guest/Sandbox inbound** (host send); `local_*` is the guest and `remote_*` the peer. WFP IPFORWARD: `direction=0` is source-interface-relative; `local_*` is the observed IP source and `remote_*` the destination. Reverse routed packets normally have another source index/tuple. No guest or connection-initiator inference is performed.
- One connection event and its `id` represent **one pending NBL**, not a socket or a connection lifetime. A homogeneous multi-NB NBL has one verdict and the complete IP packet from its first NB, not a concatenation of all NBs. Mixed-flow or malformed batches are dropped rather than represented as one flow.
- `payload_layer=3`. `payload` contains the **complete observed IP packet**, including IP/transport headers, without Ethernet/VLAN headers or Ethernet padding. `payload_size` is its full byte count. No 256-byte capture truncation remains. Endpoint normalization does not rewrite packet bytes. For LSO/RSC, this is the logical packet observed at NDIS, not necessarily one frame on the wire.
- Non-IP traffic such as ARP does not produce connection events and is passed when its ownership/profile is supported. Cache hits are handled in the kernel without a new verdict event.
- Redirect verdicts, UpdateV4/V6, PID suspension, and a thread-ID IOCTL are **unsupported**. Some enum names remain in the C++ header only for source compatibility.
- NDIS has no socket/ALE teardown notification. **Connection-END events are never generated**, including on cache expiry, timeout, or disconnect.

Connection payloads are bounded at **1 MiB (1048576 bytes)**, covering ordinary IPv4/IPv6 packets and supported larger offload packets. Larger logical packets are dropped rather than reported with truncated payloads. Packet records, metadata, queues, NBL contexts and private receive copies have no driver-defined aggregate byte budget or item quota; allocations are fallible nonpaged allocations. Allocation failure follows the configured policy fallback without publishing a shortened event. Failed NDIS buffer copies remain drop paths. Removing quotas does not make memory unlimited: a slow controller or many outstanding requests can exhaust system nonpaged pool. `--filter-pid` is no longer supported.

This is experimental kernel code. Offline tests and an enabled binding do not prove correct live filtering.

### Device session and IOCTLs

Open **`\\.\HyperVXNdisFilter`** as Administrator/SYSTEM with `GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, and exclusive sharing. The C++ client uses `FILE_FLAG_OVERLAPPED`; nonzero buffered reads wait for event bytes and are cancellable. Only **one controller** may hold the device. There is no named-pipe/winrpc transport.

Opening the device activates a policy session and resets its event queue, permanent cache, and bandwidth buckets. The client must verify the device version before relying on the protocol. `Driver::Open` only opens the session; the monitor separately checks the version.

All supported IOCTLs use `CTL_CODE(40000, function, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)` and take no input buffer:

| IOCTL | Function / numeric code | Output and effect |
|---|---|---|
| `IOCTL_VERSION` | `0x800` / `0x9C40E000` | Exactly four bytes: `00 03 03 00`. The output buffer must have at least four bytes. |
| `IOCTL_SHUTDOWN` | `0x801` / `0x9C40E004` | No output. Deactivates the policy session, discards queued events/cache/bandwidth, and resolves pending packets through the configured fallback. Does not unload, unbind, or uninstall the LWF. |
| `IOCTL_FILTERED_DEVICE_COUNT` | `0x802` / `0x9C40E008` | Exactly four bytes: an unsigned 32-bit little-endian count of running NDIS filter modules. The output buffer must have at least four bytes; input must be empty. No policy or binding side effects. |
| `IOCTL_ADAPTER_INFO` | `0x803` / `0x9C40E00C` | Versioned snapshot of every attached module, including not-running modules, with host adapter identity, names, MAC, link and general NDIS attributes. Empty input; variable-size output with a 16-byte sizing header on `STATUS_BUFFER_OVERFLOW`. Both clients grow their buffer as needed. No policy, OID or binding side effects. |

The count includes only modules admitted by the kernel target gate that successfully restarted and have not begun pausing. Merely configured, rejected, attached-but-paused, failed-restart and detached modules do not count. Pause removes a module immediately, even while outstanding NBLs are draining; a later successful restart adds it again. The snapshot is independent of the controller's policy-session state, so shutdown does not reset it. It describes active interception on adapters, not packet delivery, link connectivity or proof that traffic was observed. The count is not limited to two: it follows the running modules for the configured HNS ICS host-vNIC set. Missing, paused or rejected attachments reduce it; a nonzero count still does not prove that guest traffic actually traversed the filter. Polling can miss brief transitions.

All other IOCTLs are unsupported. After shutdown, close and reopen the handle to activate a new session. Closing the active handle also disconnects the controller and drains pending decisions. Shutdown does not itself close the handle or stop a custom application's read loop.

Reads return an event byte stream, with no driver-defined size limit beyond the native Windows **DWORD/u32** request length. A read can complete with more than 65536 bytes and coalesce multiple records; it may return fewer bytes than requested. A nonzero read remains pending until bytes exist and never succeeds empty merely because the queue is empty. Zero-length requests still complete with zero bytes. Waiting reads have no fixed count or byte-budget admission quota; Windows must still allocate their buffered-I/O resources. Shutdown, cleanup and unload cancel waiting reads; new reads after session shutdown fail until close/reopen. `CancelIoEx` cancels a waiting read, but cancellation can race a successful completion. Always reap an outstanding OVERLAPPED operation before freeing its buffer/event. Reads can split a record; retain incomplete bytes between reads. No read-polling delay is needed. A work item handles buffered I/O, releasing the policy lock between short copy chunks and completing requests outside policy/NDIS locks; the chunk size is not a completion-size limit. Stale-only queues leave the read pending instead of returning zero.

### Adapter information snapshot

`IOCTL_ADAPTER_INFO` is an additive diagnostic: event/command wire version remains **0.3.3.0**. Earlier SYS builds with that same event version may not support it; treat an unsupported/failed query as **unavailable**, never as an empty adapter list. At startup, after checking the device version, the monitor prints this snapshot once, respecting `--out` and `--timestamps`. It warns and continues monitoring if the query fails. The separate running-device count still updates at `--poll` intervals; the two queries can observe different instants.

The snapshot lists only modules accepted by the existing exact-target attach gate, not all Windows adapters or configured bindings. A module remains listed while attached but initially paused, pausing, or after a failed restart; flag `Running` means its admission gate is open. Detached modules disappear. `module_id` is an ephemeral internal module identifier, distinct from every Windows interface index/LUID. Interface identities describe the **host NDIS stack**, not guest adapters, switch ports or VM ownership. GUIDs/LUIDs are diagnostic only and do not broaden binding authorization.

The driver copies names and current MAC at attach, captures general attributes supplied during successful restart, and updates link state/speeds from valid `NDIS_STATUS_LINK_STATE` indications. Fields describe the **last NDIS-supplied values**, not a fresh hardware/OID interrogation. A new restart clears optional general attributes first; if none are supplied, those values are zero and `GeneralAttributesValid` is unset. The base connector flag is available only with attach revision 4. `LinkStateValid` indicates that auto-negotiation flags were supplied by a link-state indication; initial connection/duplex/speeds already come from attach. Speeds are bits/s; `UINT64_MAX` means unknown under the NDIS convention. `PauseValid` reports the last observed pause reason/flags, even after restarting. Pointer-bearing capabilities, kernel handles/addresses, IP configuration, routes, process/guest identities and arbitrary OID data are not exported.

The reply is **not an event record**. Its explicit byte codec is [adapter_info.rs](driver/src/adapter_info.rs); do not serialize native structures. All integers and UTF-16 code units are little-endian. The first 16 bytes are four `u32` values:

| Offset | Field | Value |
|---:|---|---|
| 0 | Schema version | `1`, independent of the device/event version. |
| 4 | Entry size | `1760` bytes. |
| 8 | Attached module count | `u32`; no fixed adapter-count quota. The complete reply must fit the 32-bit IOCTL byte-length field. |
| 12 | Running module count | Number of entries with flag `Running`; `0..count`. |

Exactly `count` entries follow on success. Successful output length is **`16 + count * 1760`**; zero modules is a successful 16-byte reply. Count/length calculations are checked against `UINT32_MAX`, not a configured adapter ceiling. The driver captures the whole list, entry state and running count under one diagnostic lock into fallibly allocated nonpaged staging storage. Allocation, wire encoding and frees run outside that lock; detach cannot invalidate the captured values. Nonempty input fails with `STATUS_INVALID_PARAMETER`. A buffer smaller than 16 bytes fails with `STATUS_BUFFER_TOO_SMALL`. A buffer that holds the header but not the **complete current snapshot** receives exactly the 16-byte header and `STATUS_BUFFER_OVERFLOW` (Win32 `ERROR_MORE_DATA`), never a partial adapter list. Compute the required length from that header, allocate a larger buffer, and retry; attach/detach may change the required size again. Only a successful complete reply is a snapshot. Both clients start with a modest 56336-byte buffer for compatibility with older schema-1 drivers, then grow fallibly with bounded retries on topology churn; they never allocate the arithmetic maximum upfront. A header-only sizing response needs no staging allocation. Complete queries can fail with insufficient resources or `STATUS_RETRY` if repeated attachment churn prevents a consistent capture; neither means an empty list. The existing exclusive Administrator/SYSTEM device access requirement applies, including after policy shutdown while the handle remains open.

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

`Global\HyperVXNdisFilter.DriverReady` (kernel name `\BaseNamedObjects\HyperVXNdisFilter.DriverReady`) is a named manual-reset event, separate from the device byte stream and IOCTLs. New objects allow access only to Administrator/SYSTEM. At startup, after initializing the control device and timer, the driver creates/opens the event, signals it, and keeps its handle until unload; unload clears the event and closes the handle. This requires the updated SYS, not just the monitor. Event creation is best-effort if the global object directory is not yet available during early system boot; device initialization does not depend on notification success.

The header-only client uses reset-before-retry startup waiting on this event, without device polling. A signal is only a retry hint, not proof of NDIS attachment, device authorization or version compatibility. The console monitor instead attempts temporary SCM loading when the device is absent; it does not wait on the readiness event or reconnect after an established session ends.

### C++ client methods

Construct `Driver(std::wstring service_name = L"HyperVXNdisFilter")`; the argument selects the device basename, not a service to create. The class is non-copyable. Boolean methods report failures through `std::string& error`; sending a request does not imply a synchronous event response or confirmation that a verdict was applied.

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
| `bool RequestCleanEndedConnections(std::string& error)` | Requests a full asynchronous expiry sweep, coalesced with driver-scheduled cleanup. Does not migrate tables, discover socket teardown or emit END events; successful write does not acknowledge sweep completion. |
| `bool RequestClearCache(std::string& error)` | Invalidates all permanent verdict entries. Does not answer pending NBLs. |
| `bool RequestShutdown(std::string& error)` | Issues `IOCTL_SHUTDOWN`; does not signal the `Run` stop event or close the handle. |
| `void Stop()` | Signals `Run` and requests shutdown once. Safe to call from callbacks or another thread while `Run` is active. |
| `void Cleanup()` | Calls `Stop`, closes session handles, and resets the record parser. Join/return from `Run` before calling it or destroying the object. The destructor also calls `Cleanup`. |
| `bool Install(const std::wstring& sys_path, std::string& error, bool inbound_udp_pid_fallback = true)` | Compatibility stub: always returns an unsupported-operation error. Use the native installer instead. Neither argument enables a driver-loading or PID-fallback path. |

A typical integration opens the device, checks its version, installs handlers, answers `on_connection` events, and uses `on_poll` for periodic requests and a positive runtime deadline. Call `Stop`, wait for `Run` to finish, then call `Cleanup`. Keep callbacks short enough to answer before the pending timeout.

### Lightweight header-only client

[HyperVXNdisFilter.hpp](monitor/include/HyperVXNdisFilter.hpp) provides the separate **`hypervxndisfilter::Client`** namespace/API. Include just that file in a Windows x64 **C++20** application; no `pmkext` sources, codec, or client library are needed. It uses Kernel32 and Advapi32 (MSVC links Advapi32 through the header's pragma; other toolchains must link it explicitly). A compiled example is [callback_client.cpp](monitor/examples/callback_client.cpp), built as `build/monitor/callback_client.exe`. The example opens a real device if explicitly run; offline tests never run it.

`Run` uses one caller-owned thread: it blocks on overlapped read completion, Stop, or an optional runtime deadline. There is no second reader/poll thread, idle read polling, automatic statistics timer, or automatic verdict. The receive buffer is allocated once per Run and grows fallibly when a bandwidth group exceeds its current capacity; reads go directly into it. Connection headers, payloads, bandwidth arrays and log-message views borrow that storage: dispatch does not reconstruct event structures or allocate/copy individual entries or payloads. Bandwidth dispatch calls once per nonempty group record, not once per tuple. A head/tail cursor retains partial frames in place; compaction happens only when the writable tail is short, not after every read. Callback function pointers plus a `void*` context avoid type-erasure/capture allocations. Copy the actual data (not just its pointer) if it must outlive the callback. This minimizes idle wakeups and hot-path work, not a measured guarantee of zero CPU usage.

| Method | Contract (`DWORD`: 0 is success, otherwise a Win32 error) |
|---|---|
| `Open()` | Tries the existing exclusive Administrator/SYSTEM device. An exclusive-device `ERROR_SHARING_VIOLATION` is returned immediately on any attempt; the caller may retry after the other controller releases its handle. After any other open failure, creates/opens the protected `Global\HyperVXNdisFilter.DriverReady` event, resets it before retrying, then waits **indefinitely**, without device polling or a startup timeout. A signal only requests a retry. `Stop()` cancels this wait with `ERROR_OPERATION_ABORTED`. Never installs/loads the driver. Requires version `{0,3,3,0}` after opening; version/I/O errors are returned rather than treated as startup signals. |
| `Run(const Callbacks&, DWORD duration_ms = INFINITE)` | Blocking callback dispatch on the calling thread. A positive duration limits monitoring only, **not Open's unlimited startup wait**; zero is invalid. Stop/runtime expiry returns success after cancelling/reaping the outstanding read. Unexpected zero-byte reads are an error, not a retry loop. Callback exceptions propagate after pending I/O is reaped. |
| `Stop()` | Thread-safe local stop, usable during Open/Run; wakes the wait. Does not itself shut down policy, close handles or unload the LWF. |
| `Close()` | Returns `ERROR_BUSY` during Run. Otherwise closes handles; device cleanup disconnects policy and releases pending packets through fallback. Join Run and all other callers before Close/destruction. |
| `GetVersion(std::array<uint8_t,4>&)` / `GetFilteredDeviceCount(uint32_t&)` | Synchronous IOCTL queries; exact four-byte replies. Outputs are unchanged on failure. |
| `GetAdapterInfo(AdapterSnapshot&)` | Synchronous variable-size attached-module query with automatic buffer growth, including not-running modules. Owning `Client::AdapterSnapshot` / `Client::AdapterInfo` types have the fields and validity flags documented above. Leaves output unchanged on failure; malformed replies return `ERROR_INVALID_DATA`, allocation failure returns `ERROR_NOT_ENOUGH_MEMORY`. |
| `SendVerdict(uint64_t id, Verdict)` | Sends the fixed ten-byte verdict; values 2..7 only. No verdict-application acknowledgement. |
| `Send(Command)` | Single-byte ClearCache=4, GetLogs=5, GetBandwidthStats=6, PrintMemoryStats=7 or CleanEndedConnections=8. No automatic scheduling. |
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

These fixed, trivially-copyable wire views use scoped `#pragma pack(push, 1)` / `pop`, with compile-time size, alignment and offset checks. All numbers are little-endian (native on supported Windows x64); addresses remain network-order bytes. Read packed scalar fields by value; do not pass a field's address/reference to an API expecting naturally aligned integers. IPv4/IPv6 is selected by the callback type, not an added `ipv6` field; no PID/thread ID is present. Guest direction and all policy/fallback semantics are unchanged. `Verdict` contains Accept=2, PermanentAccept=3, Block=4, PermanentBlock=5, Drop=6 and PermanentDrop=7.

**C++ source migration:** the former unified `on_connection(const Connection&)` and per-tuple `on_bandwidth(const Bandwidth&)` callbacks are replaced by the IPv4/IPv6 pointer callbacks above. Update consumers as in [callback_client.cpp](monitor/examples/callback_client.cpp); both clients now require wire version **0.3.3.0** and decode the host adapter index in connection and bandwidth records. Older SYS/client generations must not be mixed.

For offline adapter replies, `Client::DecodeAdapterInfo(Bytes, AdapterSnapshot&)` performs the same owning validation/decoding as `GetAdapterInfo`, without device access. Its layout constants are `AdapterInfoVersion=1`, `AdapterInfoHeaderSize=16`, `AdapterInfoEntrySize=1760`, `AdapterNameCapacity=256`, and `AdapterMacCapacity=32`. `MaxAdapters=(UINT32_MAX-16)/1760` and `MaxAdapterInfoSize=16+MaxAdapters*1760` are arithmetic overflow bounds, not allocation targets or configured item quotas; `InitialAdapterInfoSize=56336` is only the initial query capacity. The `Client::Adapter*` flag constants correspond to the `AdapterInfo::` aliases above, with `AdapterKnownFlags=0xff`.

For offline/custom transports, `Client::DispatchRecord(Bytes, callbacks)` validates one complete record before exposing any packed views. The optional `Client::Stream` helper exposes a writable `Buffer()` (at most 65536 bytes), `Commit(written, callbacks)`, `PendingBytes()` and `Reset()`; an invalid stream stays failed until Reset. Fill the latest Buffer and Commit it before asking for another; Buffer may compact storage, so do not retain its pointer across calls. `MaxRecordSize=1048636` is the connection-frame bound and `MaxPayloadSize=1048576` the connection payload bound; bandwidth storage grows fallibly to the full group size, `ReadSize=65536` is the client's streaming chunk size, not a driver read-size limit. Legacy connection-END types are not exposed by this client: the driver never generates them.

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

IP arrays contain network-order address bytes. IPv4 uses the first four bytes; the C++ decoder leaves the remaining bytes zero. `ipv6` is derived from the record type, not a separate wire field. `protocol` is the IP protocol number, for example 1=ICMP, 6=TCP, 17=UDP, 58=ICMPv6. Transport ports are zero where unavailable/not applicable.

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

Pending decisions have a **8000 ms default deadline**, measured from classification, not from when an application reads the event. The driver checks timeouts every **1 second only while pending NBLs exist**, so fallback may run up to roughly one additional check interval after the deadline, plus DPC scheduling delay. Verdicts are still checked against the actual deadline and applied immediately when valid; they do not wait for the timer. The default fallback is **fail-closed (drop)** on missing controller, disconnect/shutdown, timeout, or policy/event-allocation pressure. Without a controller, IP packets are dropped immediately; with a controller online, an uncached packet waits for a userspace verdict until its deadline and is dropped if unanswered. A valid cached PermanentAccept is still an explicit userspace decision and may admit matching traffic while that session remains online. Disconnect/shutdown clears those cached decisions. Non-IP control-frame bypass is unchanged. Pause/invalidated attachments, malformed packets, unsupported copy metadata, and unsafe ownership/copy-allocation cases always drop, even if fail-open is explicitly configured.

A permanent decision is a **TTL cache entry for TCP/UDP only**, not lifetime socket permission. **Every host `interface_index` has four independent, dynamically growing hash tables: TCP/IPv4, UDP/IPv4, TCP/IPv6, and UDP/IPv6.** There is no configured maximum entry count and no capacity-driven eviction of live decisions. Other IP protocols (including ICMP/ICMPv6) never create or use permanent entries: a permanent verdict applies only to that NBL, and the next packet still needs a decision.

Within each table, the 64-bit lookup hash and full entry identity depend **exclusively on normalized `local_ip, local_port, remote_ip, remote_port`**. IPv4 uses four address bytes and IPv6 all sixteen. Full-tuple comparison resolves hash collisions. `interface_index`, transport protocol, and IP family select the table and are **not** part of its hash or stored tuple. NDIS path/direction, VLAN, module ID, epoch, and Ethernet MAC addresses are **not additional key fields or equality guards**. Both directions and different VLANs share a decision when their normalized guest/peer tuples match **within the same interface, protocol, and IP family**. TCP and UDP never share entries, even with identical IP addresses and ports; different interface indices and IP families are also independent.

Tables use a `no_std` SwissTable-style lookup: separate control bytes, 16-byte SSE2 groups on x64 with seven-bit hash fingerprints, triangular group probing, and a fast rotate/XOR/multiply word hash. Fingerprints only select candidates; full tuples still determine equality. The deterministic hash is not keyed protection against adversarial collisions. No standard-library map, AVX, or x87 is used in the driver. Baseline integer SSE2 follows Windows x64 compiler/ABI state preservation; no explicit extended-state save/restore is needed.

Table storage uses a separate fallible nonpaged allocator with no driver-defined byte budget. Allocation/control-byte initialization and retired-table frees occur outside the policy spin lock. Growth/compaction is requested at 75% live/used load, preserving empty slots without evicting live entries. Migration advances only in the insertion path, at most 32 old-table slots per step, never from a background timer; ordinary insertion does not sweep expired entries. A cache hit performs one cache lookup on the normal driver path (also checking the old table while migration is active) and needs no event capture/allocation.

Every **10 seconds while nonempty cache banks exist**, the driver requests a **full expiry sweep of all four TCP/UDP IPv4/IPv6 caches of every candidate interface, including current and previous tables**. A system work item completes all ranges in the same cleanup run, not across later timer ticks. It releases the policy spin lock between ranges of at most 256 slots per table and frees retired buffers unlocked; control-group masks skip empty/deleted slots. One fixed expiry cutoff is taken at the start of the run. Concurrent refreshes and newly applied decisions remain valid, and growth cannot hide decisions already expired at that cutoff. Timer and explicit cleanup requests are coalesced so full scans do not overlap. Unload waits for queued/running cleanup work.

Expired entries stop matching immediately, independently of physical cleanup. The pending timer never services caches. Both timers are cancelled when their candidates disappear, are not reset on every packet/hit, and are not armed at idle startup; maintained pending counts/cache-bank counts avoid candidate scans in the packet path. Cache cleanup uses an interface-index cursor with an initial upper bound instead of a fixed-width adapter bitmask. The monitor does not schedule cache cleanup. `CleanEndedConnections` is an optional explicit asynchronous request for the same full sweep; a successful command write does not acknowledge sweep completion.

Pending decisions, queued events, bandwidth storage, attached interface contexts, and NBL ownership contexts have **no fixed item-count quota or aggregate byte budget**. Small metadata nodes are allocated fallibly without moving existing entries. Record captures, waiting reads and per-adapter receive-copy data also have no configured byte budget; actual system allocation failure and checked size arithmetic remain boundaries. Policy/event allocation failure uses the configured fallback; NBL-context and NDIS-copy allocation failures still drop. Bandwidth accounting remains best-effort, uses **64-bit counters including aggregate bytes across a multi-NB NBL**, and session-reset bulk destruction runs outside the policy lock. Cache tables retain their separate fallible allocator. `PrintMemoryStats` reports current metadata/event bytes and pending/event/bandwidth counts, not fictitious maximum values. There is no 64-NB-per-NBL ceiling, 256 KiB per-resource-copy ceiling, or 16 MiB global/per-queue/per-adapter budget. The **1 MiB connection IP payload** and 512-byte log limits remain unchanged; bandwidth groups are limited only by their checked native wire lengths and available memory.

Bandwidth aggregation uses [stable 128-entry pages and an open-addressing handle index](policy/src/bandwidth.rs), rather than per-flow list scans. Index growth is prepared at 75% load; only new-key insertion advances migration, scanning at most 32 old slots per step. Page/index allocation, index initialization and retired-buffer destruction occur outside the policy lock, and live counter entries never move. Both directions share a full normalized tuple within an interface/protocol/IP-family scope. Detached report encoding and consolidation of unqueued retry deltas also run outside the lock; only successfully queued groups reset their deltas, and controller-session reset rejects stale detached reports. Event types, complete-group encoding and the wire version are unchanged.

Memory is not infinite: if table allocation/growth fails, the current packet still receives its requested verdict, but no new cache entry is retained and later traffic requires another decision. Existing live entries remain intact; `PrintMemoryStats` reports aggregate `cached_v4`, `cached_v6`, `cache_bytes` and `cache_alloc_fail` across interfaces (the per-family counts sum TCP and UDP). The latter counts failed cache insertions, not just allocator calls.

The default TTL is **60000 ms**. `PermanentAccept` uses a **sliding idle timeout**: the initial deadline is set when the verdict is applied, and each cacheable TCP/UDP packet actually admitted by that still-valid entry resets the deadline to its classification time plus `CacheTtlMs`. Either direction refreshes the matching tuple in that protocol-specific table; TCP traffic cannot refresh a UDP entry or vice versa. Preliminary cache checks and uncacheable packets do not refresh it. At or after the deadline, a packet needs a new decision rather than reviving the expired entry. `PermanentBlock` and `PermanentDrop` retain a **fixed TTL from verdict application**; matching traffic does not extend them.

Fragments, offloaded/incomplete transport headers, and multi-NB batches cannot seed or refresh permanent entries. Clear-cache and a new/disconnected controller session reset all four tables on every interface. Pause/attachment invalidation or detach immediately disables and discards all four caches of the affected interface; table storage is freed outside the policy lock. Other interfaces retain their entries. WFP performs no extra connect/disconnect tracking; its cache state follows numeric interface index, TTL, explicit ClearCache and controller-session resets, not a persistent adapter identity.

Pending records hold the actual NBL address, interface index, deadline and parsed packet metadata. The public verdict ID is the only decision identifier; applying it claims that pending record directly. There is no opaque ownership token, epoch, generation, source/path map or mirrored connection record. NBL-local context describes only the required completion/free route. NDIS attached indices remain nonzero and unique; pause/detach invalidate their existing pending IDs and caches. An optional NDIS send cancellation ID is interface-scoped; receives and WFP packets have none. Diagnostic `module_id` remains snapshot-only. WFP network-interface connect/disconnect does not create extra invalidation work.

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
| `interface_index` | `u32`, host adapter index (`BaseMiniportIfIndex`) for this NBL, not the guest interface index. |
| `direction` | `u8`: NDIS guest outbound=0 / inbound=1; IPFORWARD source-interface-relative=0. |
| `protocol` | `u8`, IP protocol number. |
| `local_ip` | `A` raw bytes, guest endpoint. |
| `remote_ip` | `A` raw bytes, peer endpoint. |
| `local_port` | `u16`. |
| `remote_port` | `u16`. |
| `payload_layer` | `u8`, always 3. |
| `payload_size` | `u32`, complete observed IP packet length, at most 1048576. |
| `payload` | Exactly `payload_size` bytes, starting with the original IP header; never a shortened capture. |

Body size is `31 + payload_size` for IPv4 or `55 + payload_size` for IPv6; total frame size is respectively `36 + payload_size` or `60 + payload_size`. No process-ID bytes or alignment padding are present. These connection layouts are not wire-compatible with 0.3.1.0 or earlier; the bandwidth layout is described below and is new in 0.3.3.0.

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

Bandwidth counts **admitted TCP/UDP IP bytes** while the controller is online, grouped by host `interface_index` plus the normalized guest/peer tuple. `transmitted_bytes` means guest outbound; `received_bytes` means guest inbound. These are deltas since the bucket was created or last successfully queued by `GetBandwidthStats`, not cumulative per-socket totals. If the complete group cannot be allocated or queued, all of its unreported counters are retained for a later request. The number of distinct buckets has no fixed ceiling; allocation is fallible/best-effort, byte counters are 64-bit, records contain no PID, and the counters do not prove delivery to the destination.

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
| `PrintMemoryStats` | 7 | 1 | Queues an Info `LogLine` containing policy storage/counter statistics. |
| `CleanEndedConnections` | 8 | 1 | Requests a full asynchronous cache-expiry sweep; no migration or END events. |

Single-byte commands contain only their command byte. Request results are read asynchronously from the same event stream; there is no correlation ID or separate acknowledgement. Allocation failure can prevent diagnostic/statistics records from being queued.

Empty/truncated writes are rejected with `STATUS_INVALID_PARAMETER`; unsupported command/verdict values and unknown IOCTLs use `STATUS_NOT_SUPPORTED`. A second controller is rejected with `STATUS_SHARING_VIOLATION`. Version and filtered-device-count queries with an undersized output buffer use `STATUS_BUFFER_TOO_SMALL`. The filtered-device-count query rejects nonempty input with `STATUS_INVALID_PARAMETER`. The C++ client validates commands locally before writing and reports Windows I/O failures through `error`.

### Device-independent codec helpers

`pmkext::wire` exposes `IsCompatibleVersion`, `DecodeFilteredDeviceCount`, `DecodeAdapterInfoHeader`, `DecodeAdapterInfo`, `IsSupportedVerdict`, `ValidateCommands`, `EncodeVerdict`, and `DispatchRecord`. `DecodeAdapterInfoHeader(bytes, length, uint32_t& required_size, error)` validates a header prefix of at least 16 bytes, checks schema/count/running-count arithmetic, and computes the complete reply size without allocating; it leaves `required_size` unchanged on failure and does not validate the following entries. `DecodeAdapterInfo(bytes, length, AdapterSnapshot&, error)` validates and decodes exactly one complete adapter snapshot, leaving output unchanged on failure. Its constants are `kIoctlAdapterInfo=0x9C40E00C`, `kAdapterInfoVersion=1`, `kAdapterInfoHeaderSize=16`, `kAdapterInfoEntrySize=1760`, `kAdapterNameCapacity=256`, `kMaxAdapters=(UINT32_MAX-16)/1760`, and `kMaxAdapterInfoSize=16+kMaxAdapters*1760`; the last two are checked-length arithmetic bounds, not preallocation sizes or item quotas. `kInitialAdapterInfoSize=56336` is only the initial query capacity. `IsCompatibleVersion` accepts exactly `kRequiredDeviceVersion={0,3,3,0}`; `Open` itself does not perform this check. `DecodeFilteredDeviceCount` requires a non-null, exactly four-byte little-endian reply and leaves its output unchanged on failure. `EncodeVerdict` fills a fixed ten-byte array; `DispatchRecord` validates exactly one complete frame before invoking its handler.

`RecordStream::Feed(bytes, length, callback, error)` accepts arbitrary read boundaries and invokes the callback for each complete frame. `PendingBytes()` reports buffered incomplete bytes; `Reset()` discards buffered state. A malformed header or an oversized connection/log record invalidates the stream until reset; it does not guess a new boundary. The stream assembles one record across arbitrary driver reads, growing heap storage fallibly for bandwidth groups beyond the connection-frame bound. Constants are `kRecordHeaderSize=5`, `kConnectionIpv4PrefixSize=36`, `kConnectionIpv6PrefixSize=60`, `kMaxPayloadSize=1048576`, `kMaxRecordSize=1048636` (connection frames only), `kMaxLogRecordSize=512`, `kMaxCommandBatchSize=UINT32_MAX`, and `kVerdictCommandSize=10`.

## License

Copyright (c) 2026 HyperVXNdisFilter contributors. Licensed under **GNU General Public License version 3 only** (`GPL-3.0-only`); see [LICENSE](LICENSE). The adapted monitor retains its original GPLv3 license and source-provenance notices; see [monitor/README.md](monitor/README.md) and [monitor/LICENSE](monitor/LICENSE).
