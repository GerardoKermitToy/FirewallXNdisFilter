#include "WindowsSupport.h"

#include <algorithm>
#include <cstdio>
#include <cwchar>
#include <functional>
#include <stdexcept>
#include <utility>

using namespace firewallx_ndis_filter::setup;
namespace {

void Require(bool value, const char* message = "assertion failed") {
    if (!value) throw std::runtime_error(message);
}

template<typename F>
void Throws(F&& action, const wchar_t* text) {
    try { action(); }
    catch (const Error& error) {
        Require(error.message.find(text) != std::wstring::npos, "unexpected error message");
        return;
    }
    throw std::runtime_error("expected failure");
}

GUID Guid(const wchar_t* text) {
    GUID result{};
    Require(SUCCEEDED(CLSIDFromString(text, &result)) && result != GUID_NULL);
    return result;
}

const GUID target_guid = Guid(L"{9EB6CA05-3905-4420-A34F-4FA09DCC6A2D}");
const GUID foreign_guid = Guid(L"{00000001-0002-0003-0405-060708090A0B}");
const GUID wsl_guid = Guid(L"{00000011-0002-0003-0405-060708090A0B}");
const GUID wsl_switch = Guid(L"{00000022-0002-0003-0405-060708090A0B}");

Adapter Target() { return {target_guid, 1689399750295552ull, L"Ethernet adapter"}; }
Adapter WslTarget() { return {wsl_guid, 0x1122334455667788ull, L"Virtual adapter"}; }

class FakeSystem final : public System {
public:
    Adapter target = Target();
    Targets extra_targets;
    Targets configured{target};
    std::vector<Binding> bindings;
    std::vector<std::wstring> packages, removed_packages;
    std::wstring package_failure;
    bool package_remove_effect = true, package_after_confirmation = false;
    Change package_remove_result = Change::Complete;
    std::vector<std::string> calls;
    std::vector<std::wstring> messages;
    std::string fail;
    size_t fail_on_occurrence = 1;
    bool appear_after_confirm = false, remove_fails = false;
    bool service = false, component = false, config = false, allowed = false, recovery = false;
    bool invalid_config = false;
    bool consent = true, foreign_enabled = false, target_enabled_on_install = false;
    bool change_luid_after_install = false, change_target_after_confirm = false, change_target_on_disable = false;
    bool include_target = true, add_target_after_confirm = false, add_target_after_install = false;
    bool change_wsl_after_confirm = false, change_wsl_luid_after_install = false, skip_wsl_enable = false;
    bool enable_has_effect = true, disable_has_effect = true, leave_service = false;
    Change install_result = Change::Complete, remove_result = Change::Complete, service_remove_result = Change::Complete;
    Change enable_result = Change::Complete, disable_result = Change::Complete;

    void Step(const char* name) {
        calls.emplace_back(name);
        if (fail == name && static_cast<size_t>(std::count(calls.begin(), calls.end(), name)) == fail_on_occurrence) {
            throw Error{L"injected failure"};
        }
    }
    void RequireAdministrator() override { Step("admin"); }
    void RequireSupportedOS() override { Step("os"); }
    void RequireMonitorStopped() override { Step("monitor"); }
    Targets CurrentTargets() const {
        Targets result;
        if (include_target) result.push_back(target);
        result.insert(result.end(), extra_targets.begin(), extra_targets.end());
        return result;
    }
    Targets ResolveTargets() override {
        Step("resolve");
        Require(component, "paths cannot be inspected before component installation");
        return CurrentTargets();
    }
    bool HasService() override { Step("service"); return service; }
    bool HasComponent() override { Step("component"); return component; }
    void ValidatePackage(const std::filesystem::path&) override { Step("package"); }
    void VerifyConfiguration(const Targets& adapters) override {
        Step("verify-config");
        ValidateTargets(adapters);
        if (!config || invalid_config) throw Error{L"stale configuration"};
    }
    bool Confirm(const std::wstring&) override {
        Step("confirm");
        if (change_target_after_confirm) target.guid = foreign_guid;
        if (add_target_after_confirm) include_target = true;
        if (change_wsl_after_confirm) extra_targets.front().guid = foreign_guid;
        if (appear_after_confirm) service = component = true;
        if (package_after_confirmation) packages.push_back(L"oem999.inf");
        return consent;
    }
    void Print(const std::wstring& text) override { messages.push_back(text); }
    void LockNetwork() override { Step("lock"); }
    void WriteDisarmedConfiguration(const Targets& adapters) override {
        config = true;
        allowed = recovery = false;
        configured = adapters;
        Step("write-disarmed");
    }
    void DisarmIfPresent() override { Step("disarm"); if (config) allowed = recovery = false; }
    void AllowBindings() override { allowed = true; Step("arm"); }
    void AllowRuntimeRecovery() override {
        Require(config && allowed, "recovery requires completed armed configuration");
        ValidateBindings(bindings, configured, false, true);
        recovery = true; Step("ready");
    }
    Change InstallComponent(const std::filesystem::path&) override {
        Require(config && !allowed, "NetCfg must never install armed");
        component = service = true;
        bindings = {{target.guid, target_enabled_on_install}, {foreign_guid, foreign_enabled}};
        for (const auto& adapter : extra_targets) bindings.push_back({adapter.guid, target_enabled_on_install});
        if (change_luid_after_install) ++target.luid;
        if (add_target_after_install) include_target = true;
        if (change_wsl_luid_after_install) ++extra_targets.front().luid;
        Step("install");
        return install_result;
    }
    Change RemoveComponent() override {
        Require(!allowed, "removal must follow disarm");
        Step("remove");
        if (remove_fails) throw Error{L"rollback removal failure"};
        if (remove_result == Change::Complete && component) {
            component = false;
            service = leave_service;
            bindings.clear();
        }
        return remove_result;
    }
    Change RemoveOrphanedService() override {
        Require(!component && !allowed, "service removal must follow component removal and disarm");
        Step("remove-service");
        if (service_remove_result == Change::Complete) service = false;
        return service_remove_result;
    }
    std::vector<std::wstring> ReadDriverPackages() override { Step("packages"); return packages; }
    Change RemoveDriverPackage(const std::wstring& published_inf) override {
        Require(!component && !service && !allowed && !recovery, "package removal must follow complete component removal and disarm");
        removed_packages.push_back(published_inf);
        Step("purge");
        if (package_failure == published_inf) throw Error{L"injected package removal failure"};
        if (package_remove_effect) std::erase(packages, published_inf);
        return package_remove_result;
    }
    std::vector<Binding> ReadBindings() override { Step("bindings"); return bindings; }
    Change DisableTargets(const Targets& adapters) override {
        Require(config && !allowed, "disable must follow configuration validation and disarm");
        configured = adapters;
        Step("disable");
        if (change_target_on_disable) ++target.luid;
        if (disable_has_effect) {
            for (auto& binding : bindings) {
                for (const auto& adapter : adapters) if (binding.adapter == adapter.guid) binding.enabled = false;
            }
        }
        return disable_result;
    }
    Change EnableTargets(const Targets& adapters) override {
        Require(allowed && config && SameTargets(configured, adapters), "enable must follow disarm, stable snapshot and arming");
        Step("enable");
        if (enable_has_effect) {
            for (auto& binding : bindings) {
                for (const auto& adapter : adapters) {
                    if (binding.adapter == adapter.guid && !(skip_wsl_enable && adapter.guid == wsl_guid)) binding.enabled = true;
                }
            }
        }
        return enable_result;
    }
    void DeleteConfiguration() override { Step("delete-config"); config = allowed = recovery = false; }

    bool Called(const char* name) const { return std::find(calls.begin(), calls.end(), name) != calls.end(); }
    size_t At(const char* name) const {
        const auto found = std::find(calls.begin(), calls.end(), name);
        Require(found != calls.end(), "missing expected operation");
        return static_cast<size_t>(found - calls.begin());
    }
    void RequireNoMutation() const {
        for (const auto name : {"lock", "write-disarmed", "disarm", "arm", "ready", "install", "disable", "enable", "remove", "remove-service", "purge", "delete-config"}) {
            Require(!Called(name), "unexpected mutation in read-only path");
        }
    }
    void Installed() {
        service = component = config = true;
        configured = CurrentTargets();
        bindings = {{target.guid, false}, {foreign_guid, false}};
        for (const auto& adapter : extra_targets) bindings.push_back({adapter.guid, false});
    }
};

Options Install() { Options options; options.package = L"offline-package"; return options; }
Options Uninstall() { Options options; options.action = Action::Uninstall; return options; }
Options Enable() { Options options; options.action = Action::Enable; return options; }

struct Case { const char* name; std::function<void()> test; };

} // namespace

int main() {
    const std::vector<Case> cases = {
        {"CLI help/defaults and explicit modes", [] {
            Options options;
            std::wstring error;
            const wchar_t* help[] = {L"Install.exe", L"--help"};
            Require(ParseOptions(Action::Install, 2, help, options, error) && options.help);
            Require(Usage(Action::Install).find(L"--what-if") != std::wstring::npos);
            const wchar_t* args[] = {L"Install.exe", L"--enable", L"--yes", L"--what-if"};
            Require(ParseOptions(Action::Install, 4, args, options, error));
            Require(options.action == Action::Enable && options.yes && options.what_if);
            const wchar_t* package[] = {L"Install.exe", L"--package", L"C:\\package with spaces"};
            Require(ParseOptions(Action::Install, 3, package, options, error));
            Require(options.package == package[2]);
            Require(ParseOptions(Action::Uninstall, 1, package, options, error) && options.action == Action::Uninstall);
        }},
        {"CLI rejects unsupported, missing and conflicting arguments", [] {
            for (const auto arg : {L"--unknown", L"--sys", L"x.sys", L"--package"}) {
                const wchar_t* args[] = {L"Install.exe", arg}; Options opt; std::wstring error;
                Require(!ParseOptions(Action::Install, 2, args, opt, error));
            }
            for (const auto arg : {L"--enable", L"--package", L"x.sys"}) {
                const wchar_t* args[] = {L"Uninstall.exe", arg}; Options opt; std::wstring error;
                Require(!ParseOptions(Action::Uninstall, 2, args, opt, error));
            }
            const wchar_t* conflict[] = {L"Install.exe", L"--package", L"directory", L"--enable"};
            Options opt; std::wstring error;
            Require(!ParseOptions(Action::Install, 4, conflict, opt, error));
            const wchar_t* empty[] = {L"Install.exe", L"--package", L""};
            Require(!ParseOptions(Action::Install, 3, empty, opt, error));
            const wchar_t* dup[] = {L"Install.exe", L"--package", L"a", L"--package", L"b"};
            Require(!ParseOptions(Action::Install, 5, dup, opt, error));
        }},
        {"all exact target paths are required; foreign enabled paths are rejected", [] {
            const auto target = Target();
            ValidateBindings({{target.guid, false}, {target.guid, false}, {foreign_guid, false}}, {target}, true);
            ValidateBindings({{target.guid, true}, {target.guid, true}, {foreign_guid, false}}, {target}, false, true);
            Throws([&] { ValidateBindings({{target.guid, true}}, {target}, true); }, L"unexpectedly enabled");
            Throws([&] { ValidateBindings({{target.guid, true}, {foreign_guid, true}}, {target}, false); }, L"unexpectedly enabled");
            Throws([&] { ValidateBindings({{target.guid, true}, {target.guid, false}}, {target}, false, true); }, L"did not enable");
            Throws([&] { ValidateBindings({{foreign_guid, false}}, {target}, false); }, L"No FirewallXNdisFilter binding");
            Throws([&] { ValidateBindings({{GUID_NULL, false}}, {target}, false); }, L"ambiguous");
        }},
        {"binding snapshot rejects duplicate identities but has no two-adapter quota", [] {
            ValidateTargets({Target(), WslTarget(), {wsl_switch, 777, L"third"}});
            ValidateTargets({});
            Throws([&] { ValidateTargets({Target(), WslTarget(), WslTarget()}); }, L"ambiguous");
            auto wsl = WslTarget(); wsl.guid = target_guid;
            Throws([&] { ValidateTargets({Target(), wsl}); }, L"ambiguous");
            wsl = WslTarget(); wsl.luid = Target().luid;
            Throws([&] { ValidateTargets({Target(), wsl}); }, L"ambiguous");
        }},
        {"empty target set installs, resumes and never enables unrelated bindings", [] {
            FakeSystem system; system.include_target = false;
            Require(Execute(Install(), system) == 0);
            Require(system.component && system.service && system.config && system.allowed && system.recovery);
            Require(system.configured.empty() && system.bindings.size() == 2);
            Require(std::none_of(system.bindings.begin(), system.bindings.end(), [](const Binding& binding) { return binding.enabled; }));
            Require(system.At("write-disarmed") < system.At("install") && system.At("install") < system.At("arm"));
            Require(std::any_of(system.messages.begin(), system.messages.end(), [](const auto& text) { return text.find(L"No compatible Ethernet binding paths") != std::wstring::npos; }));
            Require(Execute(Enable(), system) == 0);
            Require(system.configured.empty() && !system.bindings[0].enabled && !system.bindings[1].enabled);
            system.include_target = true;
            Require(Execute(Enable(), system) == 0);
            Require(system.bindings[0].enabled && !system.bindings[1].enabled);
        }},
        {"new paths after installation are part of the first snapshot", [] {
            for (const bool during_install : {false, true}) {
                FakeSystem system; system.include_target = false;
                system.add_target_after_confirm = !during_install;
                system.add_target_after_install = during_install;
                Require(Execute(Install(), system) == 0);
                Require(system.allowed && system.bindings[0].enabled);
                Require(system.At("install") < system.At("resolve"));
            }
        }},
        {"empty target set rejects every enabled binding and rolls back", [] {
            FakeSystem system; system.include_target = false; system.foreign_enabled = true;
            Throws([&] { Execute(Install(), system); }, L"unexpectedly enabled");
            Require(system.Called("remove") && !system.Called("arm") && !system.Called("enable"));
            ValidateBindings({{target_guid, false}, {foreign_guid, false}}, {}, false, true);
            Throws([&] { ValidateBindings({{target_guid, true}}, {}, false); }, L"unexpectedly enabled");
        }},
        {"empty target install reboot retains disarmed configuration for resume", [] {
            FakeSystem system; system.include_target = false; system.install_result = Change::RebootRequired;
            Require(Execute(Install(), system) == kRebootRequired);
            Require(system.configured.empty() && system.component && !system.allowed && !system.recovery);
            system.install_result = Change::Complete;
            Require(Execute(Enable(), system) == 0);
            Require(system.allowed && system.recovery && system.configured.empty());
        }},
        {"setup enables more than two exact targets without editing a foreign path", [] {
            FakeSystem system;
            system.extra_targets = {WslTarget(), {wsl_switch, 777, L"third"}};
            Require(Execute(Install(), system) == 0);
            Require(system.configured.size() == 3 && system.bindings.size() == 4);
            Require(system.bindings[0].enabled && !system.bindings[1].enabled && system.bindings[2].enabled && system.bindings[3].enabled);
        }},
        {"both exact adapters are enabled but every foreign binding stays disabled", [] {
            FakeSystem system; system.extra_targets = {WslTarget()}; system.target_enabled_on_install = true;
            Require(Execute(Install(), system) == 0);
            Require(SameTargets(system.configured, {Target(), WslTarget()}));
            Require(system.bindings[0].enabled && !system.bindings[1].enabled && system.bindings[2].enabled);
            Require(system.At("disable") < system.At("arm") && system.At("arm") < system.At("enable"));
        }},
        {"adapter changes before post-install enumeration are included", [] {
            FakeSystem system; system.extra_targets = {WslTarget()};
            system.change_wsl_luid_after_install = true;
            Require(Execute(Install(), system) == 0);
            Require(system.allowed && system.bindings[0].enabled && system.bindings[2].enabled);
            Require(system.configured[1].luid == WslTarget().luid + 1);
        }},
        {"partial two-adapter enable is failure, not single-adapter success", [] {
            FakeSystem system; system.extra_targets = {WslTarget()}; system.skip_wsl_enable = true;
            Throws([&] { Execute(Install(), system); }, L"did not enable");
            Require(system.Called("remove") && !system.allowed && !system.recovery);
        }},
        {"resume uses current paths instead of an old stored adapter list", [] {
            FakeSystem system; system.Installed();
            system.extra_targets = {WslTarget()};
            system.bindings.push_back({wsl_guid, false});
            Require(Execute(Enable(), system) == 0);
            Require(system.bindings[0].enabled && system.bindings.back().enabled);
            Require(system.configured.size() == 2);
        }},
        {"both adapters require paths and reject an enabled foreign path", [] {
            const Targets targets{Target(), WslTarget()};
            ValidateBindings({{target_guid, true}, {wsl_guid, true}, {foreign_guid, false}}, targets, false, true);
            Throws([&] { ValidateBindings({{target_guid, false}}, targets, false); }, L"No FirewallXNdisFilter binding");
            Throws([&] { ValidateBindings({{target_guid, true}, {wsl_guid, false}}, targets, false, true); }, L"did not enable");
            Throws([&] { ValidateBindings({{target_guid, true}, {wsl_guid, true}, {foreign_guid, true}}, targets, false); }, L"unexpectedly enabled");
        }},
        {"fresh install orders validation, disarm, NetCfg, arm and exact enable", [] {
            FakeSystem system;
            Require(Execute(Install(), system) == 0);
            Require(system.At("package") < system.At("confirm"));
            Require(system.At("confirm") < system.At("lock"));
            Require(system.At("write-disarmed") < system.At("install"));
            Require(system.At("install") < system.At("verify-config"));
            Require(system.At("verify-config") < system.At("arm"));
            Require(system.At("arm") < system.At("enable"));
            Require(system.At("enable") < system.At("ready"));
            Require(system.component && system.service && system.config && system.allowed && system.recovery);
            Require(system.bindings[0].enabled && !system.bindings[1].enabled);
            Require(!system.Called("remove"));
        }},
        {"existing service or component cannot be replaced", [] {
            for (const bool service : {false, true}) {
                FakeSystem system; system.service = service; system.component = !service;
                Throws([&] { Execute(Install(), system); }, L"already installed");
                system.RequireNoMutation();
            }
        }},
        {"preflight failures never reach mutation or installation", [] {
            for (const auto stage : {"admin", "os", "monitor", "package"}) {
                FakeSystem system; system.fail = stage;
                Throws([&] { Execute(Install(), system); }, L"injected");
                system.RequireNoMutation();
            }
        }},
        {"declined confirmation changes nothing", [] {
            FakeSystem system; system.consent = false;
            Require(Execute(Install(), system) == ERROR_CANCELLED);
            system.RequireNoMutation();
        }},
        {"what-if is read-only for install, resume and removal", [] {
            for (const auto action : {Action::Install, Action::Enable, Action::Uninstall}) {
                FakeSystem system;
                Options options = Install(); options.action = action; options.what_if = true;
                if (action == Action::Enable) system.Installed();
                Require(Execute(options, system) == 0);
                Require(!system.Called("confirm"));
                system.RequireNoMutation();
                if (action == Action::Uninstall) Require(!system.Called("resolve") && !system.Called("os"));
            }
        }},
        {"--yes skips only confirmation, not safety checks", [] {
            FakeSystem system; auto options = Install(); options.yes = true;
            Require(Execute(options, system) == 0);
            Require(!system.Called("confirm") && system.Called("admin") && system.Called("package") && system.Called("lock"));
        }},
        {"fresh install snapshots paths only after installation", [] {
            FakeSystem system; system.change_target_after_confirm = true;
            Require(Execute(Install(), system) == 0);
            Require(system.At("install") < system.At("resolve"));
            Require(system.configured.front().guid == foreign_guid);
        }},
        {"path enumeration failure rolls back a new disarmed component", [] {
            FakeSystem system; system.fail = "resolve";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.Called("remove") && !system.allowed);
        }},
        {"write failure is disarmed but never removes a preexisting component", [] {
            FakeSystem system; system.fail = "write-disarmed";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.Called("disarm") && !system.allowed && !system.Called("remove"));
        }},
        {"partially failed installation rolls back only the new component", [] {
            FakeSystem system; system.fail = "install";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.At("disarm") < system.At("remove"));
            Require(system.At("remove") < system.At("delete-config"));
            Require(!system.component && !system.service && !system.config);
        }},
        {"automatic non-PnP target path is disabled while disarmed before enable", [] {
            FakeSystem system; system.target_enabled_on_install = true;
            Require(Execute(Install(), system) == 0);
            Require(system.At("disarm") < system.At("disable") && system.At("disable") < system.At("arm"));
            Require(system.allowed && system.bindings[0].enabled && !system.bindings[1].enabled);
            Require(!system.Called("remove"));
        }},
        {"unexpected foreign enabled path causes rollback without editing it", [] {
            FakeSystem system; system.foreign_enabled = true;
            Throws([&] { Execute(Install(), system); }, L"unexpectedly enabled");
            Require(system.Called("remove") && !system.Called("disable") && !system.Called("arm"));
        }},
        {"identity churn after enumeration aborts before arming", [] {
            FakeSystem system; system.change_target_on_disable = true;
            Throws([&] { Execute(Install(), system); }, L"changed");
            Require(system.Called("remove") && !system.Called("arm") && !system.allowed);
        }},
        {"target disable failure cannot arm a fresh installation", [] {
            FakeSystem system; system.target_enabled_on_install = true; system.fail = "disable";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.Called("remove") && !system.Called("arm") && !system.allowed);
        }},
        {"target disable without effect cannot arm the component", [] {
            FakeSystem system; system.target_enabled_on_install = true; system.disable_has_effect = false;
            Throws([&] { Execute(Install(), system); }, L"unexpectedly enabled");
            Require(system.Called("remove") && !system.Called("arm") && !system.allowed);
        }},
        {"target disable reboot preserves disarmed component", [] {
            FakeSystem system; system.target_enabled_on_install = true; system.disable_result = Change::RebootRequired;
            Require(Execute(Install(), system) == kRebootRequired);
            Require(system.component && system.config && !system.allowed && !system.Called("arm") && !system.Called("remove"));
        }},
        {"resume reattaches an already enabled non-PnP target", [] {
            FakeSystem system; system.Installed(); system.bindings[0].enabled = true;
            Require(Execute(Enable(), system) == 0);
            Require(system.At("disable") < system.At("arm") && system.At("arm") < system.At("enable"));
            Require(system.allowed && system.bindings[0].enabled && !system.Called("install"));
        }},
        {"post-install identity snapshot uses the current LUID", [] {
            FakeSystem system; system.change_luid_after_install = true;
            Require(Execute(Install(), system) == 0);
            Require(system.configured.front().luid == Target().luid + 1);
        }},
        {"arming and enable errors disarm and roll back fresh installs", [] {
            for (const auto stage : {"arm", "enable", "ready"}) {
                FakeSystem system; system.fail = stage;
                Throws([&] { Execute(Install(), system); }, L"injected");
                Require(system.Called("disarm") && system.Called("remove") && !system.allowed && !system.recovery);
            }
        }},
        {"a binding that did not enable is never silently accepted", [] {
            FakeSystem system; system.enable_has_effect = false;
            Throws([&] { Execute(Install(), system); }, L"did not enable");
            Require(system.Called("remove") && !system.allowed);
        }},
        {"install reboot preserves disarmed config without enabling", [] {
            FakeSystem system; system.install_result = Change::RebootRequired;
            Require(Execute(Install(), system) == kRebootRequired);
            Require(system.component && system.config && !system.allowed);
            Require(!system.Called("arm") && !system.Called("enable") && !system.Called("remove"));
        }},
        {"enable reboot disarms and preserves the installed component", [] {
            FakeSystem system; system.enable_result = Change::RebootRequired;
            Require(Execute(Install(), system) == kRebootRequired);
            Require(system.component && system.config && !system.allowed && !system.Called("remove"));
        }},
        {"rollback reboot retains the exact target configuration disarmed", [] {
            FakeSystem system; system.fail = "enable"; system.remove_result = Change::RebootRequired;
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.config && !system.allowed && !system.Called("delete-config"));
        }},
        {"resume requires installed matching configuration", [] {
            FakeSystem missing;
            Throws([&] { Execute(Enable(), missing); }, L"not installed");
            missing.RequireNoMutation();
            FakeSystem stale; stale.Installed(); stale.invalid_config = true;
            Throws([&] { Execute(Enable(), stale); }, L"stale");
            stale.RequireNoMutation();
        }},
        {"resume enables only existing target without reinstalling", [] {
            FakeSystem system; system.Installed();
            Require(Execute(Enable(), system) == 0);
            Require(system.allowed && system.recovery && system.bindings[0].enabled && !system.bindings[1].enabled);
            Require(system.At("enable") < system.At("ready"));
            Require(!system.Called("write-disarmed") && !system.Called("package") && !system.Called("install"));
        }},
        {"failed resume disarms but never removes an existing installation", [] {
            FakeSystem system; system.Installed(); system.fail = "enable";
            Throws([&] { Execute(Enable(), system); }, L"injected");
            Require(system.component && system.config && !system.allowed && !system.Called("remove"));
        }},
        {"resume failures and reboot block previously permitted runtime recovery", [] {
            for (const bool reboot : {false, true}) {
                FakeSystem system; system.Installed(); system.allowed = system.recovery = true;
                if (reboot) system.enable_result = Change::RebootRequired;
                else system.fail = "ready";
                if (reboot) Require(Execute(Enable(), system) == kRebootRequired);
                else Throws([&] { Execute(Enable(), system); }, L"injected");
                Require(system.component && system.config && !system.allowed && !system.recovery && !system.Called("remove"));
                if (reboot) Require(!system.Called("ready"));
            }
        }},
        {"removal requiring reboot blocks runtime recovery before removing", [] {
            FakeSystem system; system.Installed(); system.allowed = system.recovery = true;
            system.remove_result = Change::RebootRequired;
            Require(Execute(Uninstall(), system) == kRebootRequired);
            Require(!system.allowed && !system.recovery && system.config && !system.Called("ready"));
            Require(system.At("disarm") < system.At("remove"));
        }},
        {"uninstall disarms then removes own component and configuration", [] {
            FakeSystem system; system.Installed(); system.allowed = true;
            Require(Execute(Uninstall(), system) == 0);
            Require(system.At("disarm") < system.At("remove") && system.At("remove") < system.At("delete-config"));
            Require(!system.component && !system.service && !system.config);
            Require(!system.Called("resolve") && !system.Called("os") && !system.Called("enable") && !system.Called("package"));
        }},
        {"uninstall removes all package versions before deleting configuration", [] {
            FakeSystem system; system.Installed(); system.allowed = system.recovery = true;
            system.packages = {L"oem7.inf", L"oem42.inf", L"oem108.inf"};
            const auto expected = system.packages;
            Require(Execute(Uninstall(), system) == 0);
            Require(system.packages.empty() && system.removed_packages == expected && !system.config);
            Require(system.At("remove") < system.At("purge") && system.At("purge") < system.At("delete-config"));
        }},
        {"staged old packages are removed even when component is already absent", [] {
            FakeSystem system; system.packages = {L"oem1.inf", L"oem12.inf"};
            Require(Execute(Uninstall(), system) == 0);
            Require(system.packages.empty() && system.removed_packages.size() == 2);
            Require(!system.Called("resolve") && !system.Called("os") && !system.Called("package"));
        }},
        {"package preflight and declined confirmation are read-only", [] {
            FakeSystem system; system.packages = {L"oem3.inf"}; system.consent = false;
            Require(Execute(Uninstall(), system) == ERROR_CANCELLED);
            system.RequireNoMutation();
            Require(system.packages.size() == 1 && system.removed_packages.empty());
            Require(std::any_of(system.messages.begin(), system.messages.end(), [](const auto& text) { return text.find(L"oem3.inf") != std::wstring::npos; }));
        }},
        {"what-if reports package versions without deleting them", [] {
            FakeSystem system; system.packages = {L"oem3.inf", L"oem4.inf"};
            auto options = Uninstall(); options.what_if = true;
            Require(Execute(options, system) == 0);
            system.RequireNoMutation();
            Require(system.packages.size() == 2 && !system.Called("confirm"));
        }},
        {"package inventory is refreshed after confirmation", [] {
            FakeSystem system; system.packages = {L"oem3.inf"}; system.package_after_confirmation = true;
            Require(Execute(Uninstall(), system) == 0);
            Require(system.packages.empty() && system.removed_packages.size() == 2);
        }},
        {"component reboot postpones all package removal", [] {
            FakeSystem system; system.Installed(); system.packages = {L"oem3.inf"};
            system.remove_result = Change::RebootRequired;
            Require(Execute(Uninstall(), system) == kRebootRequired);
            Require(!system.Called("purge") && system.packages.size() == 1 && system.config && !system.recovery);
        }},
        {"orphaned service is removed before package cleanup", [] {
            FakeSystem system; system.service = system.config = true; system.packages = {L"oem3.inf"};
            Require(Execute(Uninstall(), system) == 0);
            Require(!system.service && !system.config && system.packages.empty());
            Require(system.At("remove") < system.At("remove-service") && system.At("remove-service") < system.At("purge"));
        }},
        {"service left by component removal is removed", [] {
            FakeSystem system; system.Installed(); system.leave_service = true; system.packages = {L"oem3.inf"};
            Require(Execute(Uninstall(), system) == 0);
            Require(!system.service && !system.config && system.packages.empty());
        }},
        {"service pending deletion postpones package cleanup", [] {
            FakeSystem system; system.service = system.config = true; system.packages = {L"oem3.inf"};
            system.service_remove_result = Change::RebootRequired;
            Require(Execute(Uninstall(), system) == kRebootRequired);
            Require(!system.Called("purge") && system.packages.size() == 1 && system.config);
            system.service_remove_result = Change::Complete;
            Require(Execute(Uninstall(), system) == 0 && system.packages.empty() && !system.config);
        }},
        {"service deletion failure keeps configuration and packages", [] {
            FakeSystem system; system.service = system.config = true; system.packages = {L"oem3.inf"};
            system.fail = "remove-service";
            Throws([&] { Execute(Uninstall(), system); }, L"injected");
            Require(!system.Called("purge") && system.packages.size() == 1 && system.config);
        }},
        {"uninstall does not block on a monitor process name", [] {
            FakeSystem system; system.fail = "monitor"; system.packages = {L"oem3.inf"};
            Require(Execute(Uninstall(), system) == 0);
            Require(!system.Called("monitor") && system.packages.empty());
        }},
        {"one package failure does not skip the other old versions", [] {
            FakeSystem system; system.Installed();
            system.packages = {L"oem3.inf", L"oem4.inf", L"oem5.inf"}; system.package_failure = L"oem3.inf";
            Throws([&] { Execute(Uninstall(), system); }, L"cleanup is incomplete");
            Require(system.removed_packages.size() == 3 && system.packages == std::vector<std::wstring>{L"oem3.inf"});
            Require(system.config && !system.allowed && !system.recovery && !system.Called("delete-config"));
        }},
        {"remaining packages are not silently accepted", [] {
            FakeSystem system; system.Installed(); system.packages = {L"oem3.inf"}; system.package_remove_effect = false;
            Throws([&] { Execute(Uninstall(), system); }, L"packages remain");
            Require(system.config && !system.Called("delete-config") && !system.allowed);
        }},
        {"package reboot retains disarmed configuration and later cleanup can finish", [] {
            FakeSystem system; system.Installed(); system.allowed = system.recovery = true;
            system.packages = {L"oem3.inf", L"oem4.inf"};
            system.package_remove_result = Change::RebootRequired; system.package_remove_effect = false;
            Require(Execute(Uninstall(), system) == kRebootRequired);
            Require(system.removed_packages.size() == 2 && system.config && !system.allowed && !system.recovery);
            Require(!system.Called("delete-config"));
            system.package_remove_result = Change::Complete; system.package_remove_effect = true;
            Require(Execute(Uninstall(), system) == 0 && system.packages.empty() && !system.config);
        }},
        {"post-removal inventory errors retain configuration", [] {
            FakeSystem system; system.Installed(); system.packages = {L"oem3.inf"};
            system.fail = "packages"; system.fail_on_occurrence = 3;
            Throws([&] { Execute(Uninstall(), system); }, L"injected");
            Require(system.packages.empty() && system.config && !system.Called("delete-config"));
        }},
        {"package reboot instruction survives a later package failure", [] {
            FakeSystem system; system.Installed(); system.packages = {L"oem3.inf", L"oem4.inf"};
            system.package_remove_result = Change::RebootRequired; system.package_failure = L"oem4.inf";
            Throws([&] { Execute(Uninstall(), system); }, L"cleanup is incomplete");
            Require(system.config && !system.allowed && !system.recovery);
            Require(std::any_of(system.messages.begin(), system.messages.end(), [](const auto& text) {
                return text.find(L"reboot") != std::wstring::npos && text.find(L"Uninstall.exe") != std::wstring::npos;
            }), "lost reboot instruction after a later package failure");
        }},
        {"package reboot instruction survives final inventory failure", [] {
            FakeSystem system; system.Installed(); system.packages = {L"oem3.inf"};
            system.package_remove_result = Change::RebootRequired;
            system.fail = "packages"; system.fail_on_occurrence = 3;
            Throws([&] { Execute(Uninstall(), system); }, L"injected");
            Require(system.config && !system.allowed && !system.recovery);
            Require(std::any_of(system.messages.begin(), system.messages.end(), [](const auto& text) {
                return text.find(L"reboot") != std::wstring::npos && text.find(L"Uninstall.exe") != std::wstring::npos;
            }), "lost reboot instruction after final inventory failure");
        }},
        {"failed fresh install never purges preexisting driver store packages", [] {
            FakeSystem system; system.packages = {L"oem3.inf"}; system.fail = "enable";
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(!system.Called("purge") && !system.Called("packages") && system.packages.size() == 1);
        }},
        {"already absent component removal is safe", [] {
            FakeSystem system;
            Require(Execute(Uninstall(), system) == 0);
            Require(!system.config && !system.allowed);
        }},
        {"uninstall reboot and failure retain disarmed configuration", [] {
            FakeSystem reboot; reboot.Installed(); reboot.allowed = true; reboot.remove_result = Change::RebootRequired;
            Require(Execute(Uninstall(), reboot) == kRebootRequired);
            Require(reboot.config && !reboot.allowed && !reboot.Called("delete-config"));
            FakeSystem failure; failure.Installed(); failure.allowed = true; failure.fail = "remove";
            Throws([&] { Execute(Uninstall(), failure); }, L"injected");
            Require(failure.config && !failure.allowed && !failure.Called("delete-config"));
        }},
        {"monitor restart is checked after confirmation and before arming", [] {
            for (const size_t occurrence : {size_t{2}, size_t{3}}) {
                FakeSystem system; system.fail = "monitor"; system.fail_on_occurrence = occurrence;
                Throws([&] { Execute(Install(), system); }, L"injected");
                Require(!system.Called("arm") && !system.Called("enable"));
                if (occurrence == 2) Require(!system.Called("write-disarmed") && !system.Called("remove"));
                else Require(system.Called("remove") && !system.allowed);
            }
        }},
        {"component appearing during confirmation is never overwritten or removed", [] {
            FakeSystem system; system.appear_after_confirm = true;
            Throws([&] { Execute(Install(), system); }, L"already installed");
            Require(system.component && system.service && !system.Called("install") && !system.Called("remove") && !system.Called("write-disarmed"));
        }},
        {"rollback failure preserves original error and disarmed recovery state", [] {
            FakeSystem system; system.fail = "enable"; system.remove_fails = true;
            Throws([&] { Execute(Install(), system); }, L"injected");
            Require(system.Called("remove") && system.component && system.config && !system.allowed && !system.Called("delete-config"));
        }},
        {"uninstall disarm failure cannot proceed to removal", [] {
            FakeSystem system; system.Installed(); system.allowed = true; system.fail = "disarm";
            Throws([&] { Execute(Uninstall(), system); }, L"injected");
            Require(!system.Called("remove") && !system.Called("delete-config") && system.component);
        }},
        {"uninstall cancellation leaves existing state untouched", [] {
            FakeSystem system; system.Installed(); system.allowed = true; system.consent = false;
            Require(Execute(Uninstall(), system) == ERROR_CANCELLED);
            system.RequireNoMutation();
            Require(system.component && system.config && system.allowed);
        }},
        {"residual service is removed before configuration", [] {
            FakeSystem system; system.Installed(); system.allowed = true; system.leave_service = true;
            Require(Execute(Uninstall(), system) == 0);
            Require(!system.service && !system.config && system.At("remove-service") < system.At("delete-config"));
        }}
    };
    for (const auto& test : cases) {
        try { test.test(); }
        catch (...) { std::fprintf(stderr, "FAIL: %s\n", test.name); return 1; }
        std::printf("PASS: %s\n", test.name);
    }
    std::printf("%zu console management tests passed; fake system only.\n", cases.size());
    return 0;
}
