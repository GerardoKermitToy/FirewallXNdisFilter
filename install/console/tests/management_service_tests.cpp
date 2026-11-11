#include "WindowsSupport.h"

#include <cstdio>
#include <cwchar>
#include <functional>
#include <stdexcept>
#include <vector>

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

struct Fake {
    DWORD manager_error = 0, open_error = 0, query_error = 0, stop_error = 0, delete_error = 0;
    LSTATUS registry_result = ERROR_FILE_NOT_FOUND;
    DWORD state = SERVICE_STOPPED;
    ULONGLONG now = 0, stop_at = 0;
    int managers_opened = 0, services_opened = 0, queries = 0, stops = 0, deletes = 0, closes = 0, sleeps = 0, key_deletes = 0;
    int manager_tag = 0, service_tag = 0;
    SC_HANDLE Manager() { return reinterpret_cast<SC_HANDLE>(&manager_tag); }
    SC_HANDLE Service() { return reinterpret_cast<SC_HANDLE>(&service_tag); }
};
Fake* current = nullptr;

SC_HANDLE WINAPI OpenManager(LPCWSTR machine, LPCWSTR database, DWORD access) {
    Require(!machine && !database && access == SC_MANAGER_CONNECT);
    ++current->managers_opened;
    if (current->manager_error) { SetLastError(current->manager_error); return nullptr; }
    return current->Manager();
}
SC_HANDLE WINAPI OpenDriver(SC_HANDLE manager, LPCWSTR name, DWORD access) {
    Require(manager == current->Manager() && std::wcscmp(name, kServiceName) == 0);
    Require(access == (SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE));
    ++current->services_opened;
    if (current->open_error) { SetLastError(current->open_error); return nullptr; }
    return current->Service();
}
BOOL WINAPI QueryStatus(SC_HANDLE service, SC_STATUS_TYPE level, LPBYTE buffer, DWORD size, LPDWORD needed) {
    Require(service == current->Service() && level == SC_STATUS_PROCESS_INFO && size == sizeof(SERVICE_STATUS_PROCESS));
    ++current->queries;
    if (current->query_error) { SetLastError(current->query_error); return FALSE; }
    auto* status = reinterpret_cast<SERVICE_STATUS_PROCESS*>(buffer);
    *status = {};
    status->dwCurrentState = current->state;
    *needed = sizeof(*status);
    return TRUE;
}
BOOL WINAPI StopDriver(SC_HANDLE service, DWORD control, LPSERVICE_STATUS status) {
    Require(service == current->Service() && control == SERVICE_CONTROL_STOP);
    ++current->stops;
    if (current->stop_error) {
        if (current->stop_error == ERROR_SERVICE_NOT_ACTIVE) current->state = SERVICE_STOPPED;
        SetLastError(current->stop_error);
        return FALSE;
    }
    current->state = current->stop_at ? SERVICE_STOP_PENDING : SERVICE_STOPPED;
    *status = {};
    status->dwCurrentState = current->state;
    return TRUE;
}
BOOL WINAPI DeleteDriver(SC_HANDLE service) {
    Require(service == current->Service());
    ++current->deletes;
    if (current->delete_error) { SetLastError(current->delete_error); return FALSE; }
    return TRUE;
}
BOOL WINAPI CloseDriverHandle(SC_HANDLE handle) {
    Require(handle == current->Manager() || handle == current->Service());
    ++current->closes;
    return TRUE;
}
LSTATUS WINAPI DeleteServiceKey(HKEY root, LPCWSTR key) {
    Require(root == HKEY_LOCAL_MACHINE && std::wcscmp(key, kServiceKey) == 0);
    ++current->key_deletes;
    return current->registry_result;
}
ULONGLONG WINAPI Ticks() { return current->now; }
void WINAPI Wait(DWORD milliseconds) {
    ++current->sleeps;
    current->now += milliseconds;
    if (current->stop_at && current->now >= current->stop_at) current->state = SERVICE_STOPPED;
}

ServiceControlApi Api(Fake& fake) {
    current = &fake;
    return {OpenManager, OpenDriver, QueryStatus, StopDriver, DeleteDriver, CloseDriverHandle, DeleteServiceKey, Ticks, Wait};
}

struct Case { const char* name; std::function<void()> test; };
} // namespace

int main() {
    const std::vector<Case> cases = {
        {"missing service is already removed", [] {
            Fake fake; fake.open_error = ERROR_SERVICE_DOES_NOT_EXIST;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::Absent);
            Require(fake.closes == 1 && fake.queries == 0 && fake.stops == 0 && fake.deletes == 0 && fake.key_deletes == 1);
        }},
        {"orphaned service registry key is removed when SCM service is missing", [] {
            Fake fake; fake.open_error = ERROR_SERVICE_DOES_NOT_EXIST; fake.registry_result = ERROR_SUCCESS;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::Absent);
            Require(fake.key_deletes == 1 && fake.closes == 1 && fake.deletes == 0);
        }},
        {"orphaned service registry cleanup failure is reported", [] {
            Fake fake; fake.open_error = ERROR_SERVICE_DOES_NOT_EXIST; fake.registry_result = ERROR_ACCESS_DENIED;
            Throws([&] { RemoveWindowsDriverService(Api(fake)); }, L"orphaned FirewallXNdisFilter service registry key");
            Require(fake.key_deletes == 1 && fake.closes == 1 && fake.deletes == 0);
        }},
        {"stopped service is deleted without stopping again", [] {
            Fake fake;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::Deleted);
            Require(fake.queries == 1 && fake.stops == 0 && fake.deletes == 1 && fake.closes == 2);
        }},
        {"running service is stopped and deleted", [] {
            Fake fake; fake.state = SERVICE_RUNNING;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::Deleted);
            Require(fake.stops == 1 && fake.deletes == 1 && fake.closes == 2 && fake.sleeps == 0);
        }},
        {"stop pending is waited for without a second stop", [] {
            Fake fake; fake.state = SERVICE_STOP_PENDING; fake.stop_at = 200;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::Deleted);
            Require(fake.stops == 0 && fake.deletes == 1 && fake.sleeps == 2);
        }},
        {"asynchronous stop is waited for", [] {
            Fake fake; fake.state = SERVICE_RUNNING; fake.stop_at = 300;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::Deleted);
            Require(fake.stops == 1 && fake.deletes == 1 && fake.sleeps == 3);
        }},
        {"service already stopped during stop is harmless", [] {
            Fake fake; fake.state = SERVICE_RUNNING; fake.stop_error = ERROR_SERVICE_NOT_ACTIVE;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::Deleted);
            Require(fake.stops == 1 && fake.deletes == 1 && fake.sleeps == 0);
        }},
        {"unstoppable service is marked for deletion and needs reboot", [] {
            Fake fake; fake.state = SERVICE_RUNNING; fake.stop_error = ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::RebootRequired);
            Require(fake.stops == 1 && fake.deletes == 1 && fake.sleeps == 0 && fake.closes == 2);
        }},
        {"stop timeout still marks service for deletion", [] {
            Fake fake; fake.state = SERVICE_STOP_PENDING;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::RebootRequired);
            Require(fake.stops == 0 && fake.deletes == 1 && fake.now == 5000 && fake.closes == 2);
        }},
        {"service already marked for deletion needs retry", [] {
            Fake fake; fake.open_error = ERROR_SERVICE_MARKED_FOR_DELETE;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::RebootRequired);
            Require(fake.closes == 1 && fake.deletes == 0);
        }},
        {"concurrent deletion needs retry", [] {
            Fake fake; fake.delete_error = ERROR_SERVICE_MARKED_FOR_DELETE;
            Require(RemoveWindowsDriverService(Api(fake)) == ServiceRemoval::RebootRequired);
            Require(fake.deletes == 1 && fake.closes == 2);
        }},
        {"SCM and service access failures are not hidden", [] {
            Fake manager; manager.manager_error = ERROR_ACCESS_DENIED;
            Throws([&] { RemoveWindowsDriverService(Api(manager)); }, L"Service Control Manager");
            Require(manager.closes == 0);
            Fake service; service.open_error = ERROR_ACCESS_DENIED;
            Throws([&] { RemoveWindowsDriverService(Api(service)); }, L"Open FirewallXNdisFilter service");
            Require(service.closes == 1);
        }},
        {"query and delete failures are not hidden", [] {
            Fake query; query.query_error = ERROR_ACCESS_DENIED;
            Throws([&] { RemoveWindowsDriverService(Api(query)); }, L"Query FirewallXNdisFilter service");
            Require(query.deletes == 0 && query.closes == 2);
            Fake remove; remove.delete_error = ERROR_ACCESS_DENIED;
            Throws([&] { RemoveWindowsDriverService(Api(remove)); }, L"Delete FirewallXNdisFilter service");
            Require(remove.deletes == 1 && remove.closes == 2);
        }},
    };
    int failures = 0;
    for (const auto& test : cases) {
        try { test.test(); std::printf("PASS: %s\n", test.name); }
        catch (const std::exception& error) { std::printf("FAIL: %s: %s\n", test.name, error.what()); ++failures; }
    }
    return failures ? 1 : 0;
}
