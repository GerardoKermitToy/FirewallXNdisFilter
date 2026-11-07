#include "Management.h"
#include "../../driver/shim/target_config.h"

#include <algorithm>
#include <cwchar>
#include <string_view>

namespace hyperv_xndis_filter::setup {
namespace {

void RequireFresh(System& system) {
    if (system.HasService() || system.HasComponent()) {
        throw Error{L"HyperVXNdisFilter is already installed or removal is pending. Stop the monitor and run Uninstall.exe first; a live driver is never replaced."};
    }
}

void RevalidateTargets(System& system, const Targets& targets) {
    if (!SameTargets(targets, system.ResolveTargets())) {
        throw Error{L"The HNS ICS host vNIC set changed. No alternate adapter will be selected; uninstall and reinstall explicitly."};
    }
}

int NeedsReboot(System& system) {
    system.Print(L"A reboot is required. Target configuration remains disarmed. After reboot, run Install.exe --enable explicitly (or finish removal with Uninstall.exe).\n");
    return kRebootRequired;
}

int RemovalNeedsReboot(System& system) {
    system.Print(L"Removal requires a reboot. Configuration remains disarmed. After reboot, run Uninstall.exe again to remove all remaining HyperVXNdisFilter Driver Store packages.\n");
    return kRebootRequired;
}

Change RemovePackages(System& system) {
    bool reboot = false;
    std::wstring failures;
    for (const auto& package : system.ReadDriverPackages()) {
        try {
            if (system.RemoveDriverPackage(package) == Change::RebootRequired) {
                if (!reboot) {
                    system.Print(L"Package removal requires a reboot, even if later cleanup fails. After reboot, rerun Uninstall.exe.\n");
                }
                reboot = true;
            }
        } catch (const Error& error) {
            // РћС‚РєР°Р· РѕРґРЅРѕРіРѕ РїР°РєРµС‚Р° РЅРµ РґРѕР»Р¶РµРЅ РѕСЃС‚Р°РІР»СЏС‚СЊ РѕСЃС‚Р°Р»СЊРЅС‹Рµ СЃС‚Р°СЂС‹Рµ РІРµСЂСЃРёРё
            // Р±РµР· РїРѕРїС‹С‚РєРё СѓРґР°Р»РµРЅРёСЏ. РЈСЃРїРµС… РїСЂРё С‡Р°СЃС‚РёС‡РЅРѕР№ РѕС‡РёСЃС‚РєРµ РЅРµ РІРѕР·РІСЂР°С‰Р°РµРј.
            failures += package + L": " + error.message + L"\n";
            system.Print(L"WARNING: " + package + L": " + error.message + L"\n");
        }
    }
    const auto remaining = system.ReadDriverPackages();
    if (!failures.empty()) throw Error{L"Driver Store cleanup is incomplete; configuration remains disarmed.\n" + failures};
    if (reboot) return Change::RebootRequired;
    if (!remaining.empty()) {
        throw Error{L"HyperVXNdisFilter packages remain in Driver Store after removal. Configuration is retained; run Uninstall.exe again."};
    }
    return Change::Complete;
}

int Enable(System& system, const Targets& targets) {
    ValidateBindings(system.ReadBindings(), targets, false);
    RevalidateTargets(system, targets);
    system.VerifyConfiguration(targets);
    system.RequireMonitorStopped();
    system.DisarmIfPresent();
    if (system.DisableTargets(targets) == Change::RebootRequired) return NeedsReboot(system);
    ValidateBindings(system.ReadBindings(), targets, true);
    RevalidateTargets(system, targets);
    system.VerifyConfiguration(targets);
    system.AllowBindings();
    if (system.EnableTargets(targets) == Change::RebootRequired) {
        system.DisarmIfPresent();
        return NeedsReboot(system);
    }
    ValidateBindings(system.ReadBindings(), targets, false, true);
    RevalidateTargets(system, targets);
    system.VerifyConfiguration(targets);
    system.AllowRuntimeRecovery();
    system.Print(L"HyperVXNdisFilter is enabled only on the exact configured HNS ICS host vNICs.\n");
    return 0;
}

void Rollback(System& system, bool attempted_install) noexcept {
    try {
        system.DisarmIfPresent();
    } catch (const Error& error) {
        system.Print(L"WARNING: could not disarm configuration: " + error.message + L"\n");
    } catch (...) {
        system.Print(L"WARNING: could not disarm configuration.\n");
    }
    if (!attempted_install) return;
    system.Print(L"Installation failed; rolling back only this new HyperVXNdisFilter component.\n");
    try {
        if (system.RemoveComponent() == Change::RebootRequired) {
            system.Print(L"Rollback requires a reboot; configuration is retained disarmed.\n");
        } else if (system.HasComponent() || system.HasService()) {
            system.Print(L"WARNING: rollback is incomplete. Configuration is retained; use Uninstall.exe.\n");
        } else {
            system.DeleteConfiguration();
        }
    } catch (const Error& error) {
        system.Print(L"WARNING: rollback is incomplete: " + error.message + L". Use Uninstall.exe.\n");
    } catch (...) {
        system.Print(L"WARNING: rollback is incomplete. Use Uninstall.exe.\n");
    }
}

} // namespace

bool ParseOptions(Action executable, int argc, const wchar_t* const* argv,
                  Options& options, std::wstring& error) {
    options = {};
    options.action = executable;
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg(argv[i]);
        if (arg == L"--help" || arg == L"-h" || arg == L"/?") options.help = true;
        else if (arg == L"--yes") options.yes = true;
        else if (arg == L"--what-if") options.what_if = true;
        else if (arg == L"--enable" && executable == Action::Install) options.action = Action::Enable;
        else if (arg == L"--package" && executable == Action::Install) {
            if (!options.package.empty() || i + 1 >= argc || argv[i + 1][0] == L'\0' ||
                std::wstring_view(argv[i + 1]).starts_with(L"--")) {
                error = L"--package requires one nonempty directory path";
                return false;
            }
            options.package = argv[++i];
        } else {
            error = L"unknown option or positional argument: " + std::wstring(arg) + L"; use --help";
            return false;
        }
    }
    if (options.action == Action::Enable && !options.package.empty()) {
        error = L"--enable uses the installed component, not --package";
        return false;
    }
    error.clear();
    return true;
}

std::wstring Usage(Action executable) {
    const bool uninstall = executable == Action::Uninstall;
    std::wstring result = uninstall
        ? L"Usage: Uninstall.exe [--yes] [--what-if]\n       Uninstall.exe --help\n\n"
        : L"Usage: Install.exe [--package DIRECTORY] [--yes] [--what-if]\n       Install.exe --enable [--yes] [--what-if]\n       Install.exe --help\n\n";
    result += uninstall
        ? L"Disarms and removes only the hyperv_xndis_filter NetCfg component, then\nremoves ALL identified HyperVXNdisFilter package versions from Driver Store.\nPackages in use require reboot and another Uninstall.exe run; no forced file\ndeletion is performed. No Default Switch, VM, HNS, NAT or unrelated driver is changed.\n"
        : L"Installs the optional NDIS LWF on all Hyper-V management-OS Ethernet\nvNICs associated with HNS networks of type ICS, regardless of names.\nThe package directory defaults to the directory containing this EXE.\n--enable resumes an installed, disarmed component after a requested reboot;\nit never retargets a changed ICS adapter set or creates HNS networks.\n";
    result += L"\nRun from an elevated Administrator/SYSTEM console; stop hyperv_monitor first.\nConfirmation is required unless --yes is supplied. --what-if performs read-only\npreflight without a write lock, registry writes, package deletion or binding changes.\n--help and invalid arguments do not access WMI, NetCfg, registry or the driver.\n\nExit codes: 0 success/dry run, 1 failure, 2 invalid arguments,\n1223 cancelled, 3010 reboot required (configuration retained disarmed).\nThe programs never open the driver device or create an SCM service manually.\n";
    return result;
}

bool ParseGuid(const std::wstring& text, GUID& guid) {
    if (text.size() != 36 && text.size() != 38) return false;
    if (text.size() == 38 && (text.front() != L'{' || text.back() != L'}')) return false;
    const std::wstring braced = text.size() == 36 ? L"{" + text + L"}" : text;
    return SUCCEEDED(CLSIDFromString(braced.c_str(), &guid)) && guid != GUID_NULL;
}

GUID InternalPortGuid(const std::wstring& device_id) {
    constexpr std::wstring_view prefix = L"Microsoft:";
    GUID guid{};
    if (!std::wstring_view(device_id).starts_with(prefix) ||
        !ParseGuid(device_id.substr(prefix.size()), guid)) {
        throw Error{L"The management-OS internal Ethernet port has no valid interface GUID."};
    }
    return guid;
}

std::vector<GUID> SelectIcsSwitches(const std::vector<HnsNetwork>& networks) {
    std::vector<GUID> ids, switches;
    for (const auto& network : networks) {
        if (network.type != L"ICS") continue;
        if (network.id == GUID_NULL || network.switch_id == GUID_NULL ||
            std::find(ids.begin(), ids.end(), network.id) != ids.end()) {
            throw Error{L"An HNS ICS network identity is invalid or ambiguous. No fallback is allowed."};
        }
        ids.push_back(network.id);
        // Multiple HNS networks may reference one switch; select its host vNICs once.
        if (std::find(switches.begin(), switches.end(), network.switch_id) == switches.end()) {
            switches.push_back(network.switch_id);
        }
    }
    return switches;
}

void ValidateTargets(const Targets& targets) {
    unsigned int size = 0;
    if (targets.size() > MAXDWORD || !HvTargetsSize(static_cast<unsigned int>(targets.size()), &size)) {
        throw Error{L"Invalid target adapter count or registry byte-length overflow."};
    }
    for (size_t i = 0; i < targets.size(); ++i) {
        if (targets[i].guid == GUID_NULL || targets[i].luid == 0) throw Error{L"Invalid target GUID/NET_LUID."};
        for (size_t j = 0; j < i; ++j) {
            if (targets[i].guid == targets[j].guid || targets[i].luid == targets[j].luid) {
                throw Error{L"The HNS ICS target identities are ambiguous."};
            }
        }
    }
}

Targets SelectTargets(const std::vector<GUID>& switches, const std::vector<HostPort>& ports,
                      const std::vector<Adapter>& adapters, const std::vector<HnsNetwork>& networks) {
    const auto selected = SelectIcsSwitches(networks);
    Targets targets;
    for (const auto& switch_id : selected) {
        if (std::count(switches.begin(), switches.end(), switch_id) != 1) {
            throw Error{L"An HNS ICS Hyper-V switch is missing or ambiguous. No name-based fallback is allowed."};
        }
        for (const auto& port : ports) {
            if (std::find(port.switches.begin(), port.switches.end(), switch_id) == port.switches.end()) continue;
            if (port.switches.size() != 1) throw Error{L"An HNS ICS management-OS port has ambiguous switch associations."};
            const GUID guid = InternalPortGuid(port.device_id);
            const Adapter* target = nullptr;
            for (const auto& adapter : adapters) {
                if (adapter.guid != guid) continue;
                if (target) throw Error{L"The exact host adapter is ambiguous."};
                target = &adapter;
            }
            if (!target) throw Error{L"The exact host adapter was not found. No alternate adapter will be selected."};
            if (!target->is_virtual || target->hardware || target->interface_type != 6 || !target->luid) {
                throw Error{L"The target is not an Ethernet host vNIC with a valid NET_LUID."};
            }
            targets.push_back(*target);
        }
    }
    ValidateTargets(targets);
    // Match PowerShell's canonical GUID text ordering, independent of HNS/WMI enumeration order.
    std::sort(targets.begin(), targets.end(), [](const Adapter& left, const Adapter& right) {
        const auto& a = left.guid;
        const auto& b = right.guid;
        if (a.Data1 != b.Data1) return a.Data1 < b.Data1;
        if (a.Data2 != b.Data2) return a.Data2 < b.Data2;
        if (a.Data3 != b.Data3) return a.Data3 < b.Data3;
        return std::lexicographical_compare(a.Data4, a.Data4 + 8, b.Data4, b.Data4 + 8);
    });
    return targets;
}

bool SameTarget(const Adapter& first, const Adapter& second) {
    return first.guid == second.guid && first.luid == second.luid;
}

bool SameTargets(const Targets& first, const Targets& second) {
    return first.size() == second.size() && std::is_permutation(first.begin(), first.end(), second.begin(), SameTarget);
}

void ValidateBindings(const std::vector<Binding>& bindings, const Targets& targets,
                      bool all_disabled, bool require_enabled) {
    ValidateTargets(targets);
    for (const auto& binding : bindings) {
        if (binding.adapter == GUID_NULL) throw Error{L"An ambiguous HyperVXNdisFilter binding path was found."};
        const bool target = std::any_of(targets.begin(), targets.end(), [&](const Adapter& adapter) {
            return binding.adapter == adapter.guid;
        });
        if (binding.enabled && (all_disabled || !target)) {
            throw Error{L"HyperVXNdisFilter has an unexpectedly enabled binding. No foreign adapter will be edited."};
        }
        if (target && require_enabled && !binding.enabled) {
            throw Error{L"An exact target binding did not enable. No other binding will be tried."};
        }
    }
    // Several paths may terminate at one adapter; every configured adapter must
    // have a path, and every one of its paths must reach the requested state.
    for (const auto& target : targets) {
        if (std::none_of(bindings.begin(), bindings.end(), [&](const Binding& binding) { return binding.adapter == target.guid; })) {
            throw Error{L"No HyperVXNdisFilter binding exists on an exact configured host adapter."};
        }
    }
}

int Execute(const Options& options, System& system) {
    system.RequireAdministrator();
    if (options.action != Action::Uninstall) system.RequireSupportedOS();
    system.RequireMonitorStopped();
    Targets targets;
    if (options.action != Action::Uninstall) {
        targets = system.ResolveTargets();
        ValidateTargets(targets);
        if (options.action == Action::Install) {
            RequireFresh(system);
            system.ValidatePackage(options.package);
        } else {
            if (!system.HasComponent()) throw Error{L"HyperVXNdisFilter is not installed. Run Install.exe without --enable first."};
            system.VerifyConfiguration(targets);
            ValidateBindings(system.ReadBindings(), targets, false);
        }
        if (targets.empty()) {
            system.Print(L"No HNS ICS host vNIC targets were discovered. Setup will continue without NDIS bindings.\n");
        }
        for (const auto& target : targets) {
            system.Print(L"Exact target: " + target.name + L", NET_LUID=" + std::to_wstring(target.luid) + L"\n");
        }
        system.Print(L"WARNING: this is the host-vNIC path, not all VM-to-VM traffic. Blocking verdicts can disconnect it.\n");
    }
    if (options.action == Action::Uninstall) {
        const auto packages = system.ReadDriverPackages();
        system.Print(L"HyperVXNdisFilter Driver Store packages (all versions): " + std::to_wstring(packages.size()) + L"\n");
        for (const auto& package : packages) system.Print(L"  " + package + L"\n");
    }
    if (options.what_if) {
        system.Print(L"What-if: preflight completed. No system state was changed.\n");
        return 0;
    }
    const std::wstring operation = options.action == Action::Uninstall
        ? L"Disarm and uninstall ONLY HyperVXNdisFilter, including ALL its Driver Store package versions"
        : options.action == Action::Enable ? L"Enable ONLY the configured HNS ICS host bindings"
                                          : L"Install HyperVXNdisFilter and enable ONLY the discovered HNS ICS host bindings";
    if (!options.yes && !system.Confirm(operation)) {
        system.Print(L"Cancelled. No system state was changed.\n");
        return ERROR_CANCELLED;
    }
    system.LockNetwork();
    system.RequireMonitorStopped();
    if (options.action == Action::Uninstall) {
        system.DisarmIfPresent();
        if (system.RemoveComponent() == Change::RebootRequired) return RemovalNeedsReboot(system);
        if (system.HasComponent() || system.HasService()) {
            throw Error{L"HyperVXNdisFilter removal is incomplete. Configuration remains disarmed; reboot if requested and run Uninstall.exe again."};
        }
        if (RemovePackages(system) == Change::RebootRequired) return RemovalNeedsReboot(system);
        system.DeleteConfiguration();
        system.Print(L"HyperVXNdisFilter and all its Driver Store package versions removed. No other component, switch, VM, HNS or NAT setting was changed.\n");
        return 0;
    }
    RevalidateTargets(system, targets);
    if (options.action == Action::Enable) {
        if (!system.HasComponent()) throw Error{L"The installed HyperVXNdisFilter component disappeared."};
        try {
            return Enable(system, targets);
        } catch (...) {
            Rollback(system, false);
            throw;
        }
    }
    RequireFresh(system);
    bool attempted_install = false;
    try {
        system.WriteDisarmedConfiguration(targets);
        attempted_install = true;
        if (system.InstallComponent(options.package) == Change::RebootRequired) return NeedsReboot(system);
        ValidateBindings(system.ReadBindings(), targets, false);
        return Enable(system, targets);
    } catch (...) {
        Rollback(system, attempted_install);
        throw;
    }
}

} // namespace hyperv_xndis_filter::setup
