#pragma once
#include <windows.h>
#include <objbase.h>
#include <cguid.h>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace firewallx_ndis_filter::setup {

inline constexpr int kRebootRequired = ERROR_SUCCESS_REBOOT_REQUIRED;
// Coherent driver-store package for the PID-free, full-packet, blocking-read 0.3.3.0 API.
inline constexpr wchar_t kPackageVersion[] = L"0.3.3.0";
inline constexpr wchar_t kDriverFileName[] = L"FirewallXNdisFilter.sys";
inline constexpr wchar_t kServiceName[] = L"FirewallXNdisFilter";

enum class Action { Install, Enable, Uninstall };
enum class Change { Complete, RebootRequired };

struct Error {
    std::wstring message;
};

struct Options {
    Action action = Action::Install;
    bool help = false;
    bool yes = false;
    bool what_if = false;
    std::filesystem::path package;
};

struct Adapter {
    GUID guid{};
    uint64_t luid = 0;
    std::wstring name;
};

struct Binding {
    GUID adapter{};
    bool enabled = false;
};

using Targets = std::vector<Adapter>;

bool ParseOptions(Action executable, int argc, const wchar_t* const* argv,
                  Options& options, std::wstring& error);
std::wstring Usage(Action executable);
void ValidateTargets(const Targets& targets);
bool SameTarget(const Adapter& first, const Adapter& second);
bool SameTargets(const Targets& first, const Targets& second);
void ValidateBindings(const std::vector<Binding>& bindings, const Targets& targets,
                      bool all_disabled, bool require_enabled = false);

// The workflow is shared by the EXEs and a fake implementation in offline tests.
// Only the Windows implementation may touch NetCfg, files or registry state.
class System {
public:
    virtual ~System() = default;
    virtual void RequireAdministrator() = 0;
    virtual void RequireSupportedOS() = 0;
    virtual void RequireMonitorStopped() = 0;
    virtual Targets ResolveTargets() = 0;
    virtual bool HasService() = 0;
    virtual bool HasComponent() = 0;
    virtual void ValidatePackage(const std::filesystem::path& package) = 0;
    virtual void VerifyConfiguration(const Targets& targets) = 0;
    virtual bool Confirm(const std::wstring& action) = 0;
    virtual void Print(const std::wstring& text) = 0;
    virtual void LockNetwork() = 0;
    virtual void WriteDisarmedConfiguration(const Targets& targets) = 0;
    virtual void DisarmIfPresent() = 0;
    virtual void AllowBindings() = 0;
    virtual void AllowRuntimeRecovery() = 0;
    virtual Change InstallComponent(const std::filesystem::path& package) = 0;
    virtual Change RemoveComponent() = 0;
    virtual Change RemoveOrphanedService() = 0;
    virtual std::vector<std::wstring> ReadDriverPackages() = 0;
    virtual Change RemoveDriverPackage(const std::wstring& published_inf) = 0;
    virtual std::vector<Binding> ReadBindings() = 0;
    virtual Change DisableTargets(const Targets& targets) = 0;
    virtual Change EnableTargets(const Targets& targets) = 0;
    virtual void DeleteConfiguration() = 0;
};

int Execute(const Options& options, System& system);
std::unique_ptr<System> CreateWindowsSystem();
std::filesystem::path ExecutableDirectory();
void WriteText(const std::wstring& text, bool error = false);

} // namespace firewallx_ndis_filter::setup
