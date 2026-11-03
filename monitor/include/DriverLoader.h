#pragma once

#include <windows.h>
#include <winsvc.h>
#include <string>

namespace pmkext::monitor {

// Console-only ownership. The device clients never manage services.
class DriverLoader {
public:
    ~DriverLoader();
    DriverLoader() = default;
    DriverLoader(const DriverLoader&) = delete;
    DriverLoader& operator=(const DriverLoader&) = delete;

    bool Load(const std::wstring& sys_path, std::string& error);
    bool Cleanup(std::string& error);
    bool Started() const { return started_; }
    bool Created() const { return created_; }

private:
    SC_HANDLE manager_ = nullptr;
    SC_HANDLE service_ = nullptr;
    HANDLE image_ = INVALID_HANDLE_VALUE;
    bool created_ = false;
    bool started_ = false;
};

} // namespace pmkext::monitor
