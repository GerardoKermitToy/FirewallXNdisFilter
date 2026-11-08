#include "WindowsSupport.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <stdexcept>

using namespace firewallx_ndis_filter::setup;
namespace {

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

void Write(const std::filesystem::path& path, const std::vector<char>& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    Require(static_cast<bool>(output), "fixture write failed (or leaked file lock)");
}

void MustRefuse(const std::filesystem::path& store, const std::vector<Handle>& source,
                const wchar_t* file = nullptr) {
    bool refused = false;
    try { auto locked = LockMatchingPackage(store, source); }
    catch (const Error& error) {
        refused = true;
        if (file) Require(error.message.find(file) != std::wstring::npos, "wrong mismatched file reported");
    }
    Require(refused, "different Driver Store package was accepted");
}

void MustStayLocked(const std::filesystem::path& path) {
    Handle writer(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    Require(writer.get() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION,
            "verified file can be modified before activation");
    Require(!DeleteFileW(path.c_str()) && GetLastError() == ERROR_SHARING_VIOLATION,
            "verified file can be deleted before activation");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    std::filesystem::path fixture;
    bool created = false;
    int result = 1;
    try {
        fixture = std::filesystem::path(argv[1]) /
            (L"package-identity-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
        Require(std::filesystem::create_directory(fixture), "fixture directory already exists");
        created = true;
        const auto source_path = fixture / L"source", store = fixture / L"store";
        Require(std::filesystem::create_directory(source_path) && std::filesystem::create_directory(store),
                "cannot create private fixture directories");
        std::array<std::vector<char>, kPackageFiles.size()> bytes;
        const std::string inf = "[Version]\r\nDriverVer=10/27/2026,0.3.3.0\r\n";
        bytes[0] = std::vector<char>(inf.begin(), inf.end());
        for (size_t i = 1; i < bytes.size(); ++i) {
            bytes[i].resize(2 * 16384 + i + 1);
            for (size_t n = 0; n < bytes[i].size(); ++n) bytes[i][n] = static_cast<char>((n + i) % 251);
        }
        for (size_t i = 0; i < bytes.size(); ++i) {
            Write(source_path / kPackageFiles[i], bytes[i]);
            Write(store / kPackageFiles[i], bytes[i]);
        }
        auto source = LockPackageFiles(source_path);
        {
            auto locked = LockMatchingPackage(store, source);
            Require(locked.size() == kPackageFiles.size(), "incomplete staged package locks");
            for (const auto name : kPackageFiles) {
                MustStayLocked(source_path / name);
                MustStayLocked(store / name);
            }
            // Trust/hash checks or previous comparisons can leave file cursors
            // anywhere. Identity verification must start from byte zero itself.
            LARGE_INTEGER offset{};
            offset.QuadPart = 7;
            for (const auto& file : source) {
                Require(SetFilePointerEx(file.get(), offset, nullptr, FILE_BEGIN) != FALSE, "cannot move test cursor");
            }
            auto again = LockMatchingPackage(store, source);
            Require(again.size() == kPackageFiles.size(), "identity depends on current file cursor");
        }
        size_t refused = 0;
        for (size_t i = 0; i < bytes.size(); ++i) {
            // Exact same INF/version and same-sized SYS/DLL/CAT, but changed
            // bytes: this is the stale-store case signatures alone cannot rule out.
            std::vector<size_t> positions{0, bytes[i].size() - 1};
            if (bytes[i].size() > 16384) positions.insert(positions.end(), {16383, 16384});
            for (auto position : positions) {
                auto changed = bytes[i];
                changed[position] ^= 0x55;
                Write(store / kPackageFiles[i], changed);
                MustRefuse(store, source, kPackageFiles[i]);
                ++refused;
            }
            for (size_t length : {size_t{0}, bytes[i].size() - 1, bytes[i].size() + 1}) {
                auto changed = bytes[i];
                changed.resize(length);
                Write(store / kPackageFiles[i], changed);
                MustRefuse(store, source, kPackageFiles[i]);
                ++refused;
            }
            Write(store / kPackageFiles[i], bytes[i]);
            Require(std::filesystem::remove(store / kPackageFiles[i]), "cannot remove fixture after refusal");
            MustRefuse(store, source, kPackageFiles[i]);
            ++refused;
            Write(store / kPackageFiles[i], bytes[i]);
            auto restored = LockMatchingPackage(store, source);
            Require(restored.size() == kPackageFiles.size(), "failed verification leaked handles or damaged source");
        }
        std::vector<Handle> absent;
        MustRefuse(store, absent);
        std::vector<Handle> invalid(kPackageFiles.size());
        MustRefuse(store, invalid);
        source.clear();
        for (size_t i = 0; i < bytes.size(); ++i) {
            Write(source_path / kPackageFiles[i], bytes[i]);
            Write(store / kPackageFiles[i], bytes[i]);
        }
        std::printf("PASS: identical packages retained, %zu mismatched/missing package cases refused, cursor reset and file locks; no Driver Store inventory, staging or NetCfg activation.\n", refused);
        result = 0;
    } catch (const Error& error) {
        WriteText(L"FAIL: " + error.message + L"\n", true);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
    }
    if (created) {
        std::error_code error;
        std::filesystem::remove_all(fixture, error);
        if (error) { std::fprintf(stderr, "FAIL: fixture cleanup failed\n"); result = 1; }
    }
    return result;
}
