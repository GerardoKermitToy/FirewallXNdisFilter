#include "WindowsSupport.h"

namespace firewallx_ndis_filter::setup {
namespace {

class ServiceHandle {
public:
    ServiceHandle(const ServiceControlApi& api, SC_HANDLE handle) : api_(api), handle_(handle) {}
    ~ServiceHandle() { if (handle_) api_.close(handle_); }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    SC_HANDLE get() const { return handle_; }
private:
    const ServiceControlApi& api_;
    SC_HANDLE handle_;
};

DWORD ServiceState(const ServiceControlApi& api, SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    DWORD bytes = 0;
    if (!api.query_status(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes)) {
        throw Error{L"Query FirewallXNdisFilter service status: " + ErrorCode(GetLastError())};
    }
    return status.dwCurrentState;
}

} // namespace

ServiceRemoval RemoveWindowsDriverService(const ServiceControlApi& api) {
    ServiceHandle manager(api, api.open_manager(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.get()) throw Error{L"Open Service Control Manager: " + ErrorCode(GetLastError())};
    ServiceHandle service(api, api.open_service(manager.get(), kServiceName, SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE));
    if (!service.get()) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            // NetCfg can leave a service key that SCM no longer recognizes.
            // The caller has already disarmed and removed the component.
            const LSTATUS registry = api.delete_tree(HKEY_LOCAL_MACHINE, kServiceKey);
            if (registry != ERROR_SUCCESS && registry != ERROR_FILE_NOT_FOUND && registry != ERROR_PATH_NOT_FOUND) {
                CheckWin32(registry, L"Remove orphaned FirewallXNdisFilter service registry key");
            }
            return ServiceRemoval::Absent;
        }
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) return ServiceRemoval::RebootRequired;
        throw Error{L"Open FirewallXNdisFilter service: " + ErrorCode(error)};
    }

    DWORD state = ServiceState(api, service.get());
    bool wait_for_stop = true;
    if (state != SERVICE_STOPPED && state != SERVICE_STOP_PENDING) {
        SERVICE_STATUS status{};
        if (!api.control(service.get(), SERVICE_CONTROL_STOP, &status)) {
            const DWORD error = GetLastError();
            if (error != ERROR_SERVICE_NOT_ACTIVE) {
                WriteText(L"Windows could not stop FirewallXNdisFilter immediately; marking its service for deletion: " + ErrorCode(error) + L"\n");
                wait_for_stop = false;
            }
        }
        state = ServiceState(api, service.get());
    }
    // A stopped driver can be removed now. A still-running or stopping driver
    // is marked for deletion and retained until Windows can safely unload it.
    constexpr ULONGLONG kStopWaitMs = 5000;
    const ULONGLONG start = api.ticks();
    while (wait_for_stop && state != SERVICE_STOPPED && api.ticks() - start < kStopWaitMs) {
        api.sleep(100);
        state = ServiceState(api, service.get());
    }
    if (!api.remove(service.get())) {
        const DWORD error = GetLastError();
        if (error == ERROR_SERVICE_MARKED_FOR_DELETE) return ServiceRemoval::RebootRequired;
        throw Error{L"Delete FirewallXNdisFilter service: " + ErrorCode(error)};
    }
    return state == SERVICE_STOPPED ? ServiceRemoval::Deleted : ServiceRemoval::RebootRequired;
}

} // namespace firewallx_ndis_filter::setup
