#include "IcsInterfaces.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <netcon.h>
#include <wrl/client.h>

#include <algorithm>
#include <cstdio>
#include <new>

namespace pmkext::monitor {
namespace {
using Microsoft::WRL::ComPtr;

struct ComApartment {
    HRESULT status = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ~ComApartment() { if (SUCCEEDED(status)) CoUninitialize(); }
};

bool QueryError(const char* operation, HRESULT status, std::string& error) {
    char text[160]{};
    std::snprintf(text, sizeof(text), "ICS %s failed: HRESULT 0x%08lX",
                  operation, static_cast<unsigned long>(status));
    error = text;
    return false;
}
} // namespace

bool QueryPublicIcsInterfaces(std::vector<uint32_t>& indices, std::string& error) {
    ComApartment apartment;
    if (FAILED(apartment.status) && apartment.status != RPC_E_CHANGED_MODE)
        return QueryError("COM initialization", apartment.status, error);
    ComPtr<INetSharingManager> manager;
    HRESULT status = CoCreateInstance(CLSID_NetSharingManager, nullptr, CLSCTX_INPROC_SERVER,
                                      IID_PPV_ARGS(manager.GetAddressOf()));
    if (FAILED(status)) return QueryError("manager creation", status, error);
    if (!manager) return QueryError("manager creation", E_UNEXPECTED, error);
    ComPtr<INetSharingEveryConnectionCollection> connections;
    status = manager->get_EnumEveryConnection(connections.GetAddressOf());
    if (FAILED(status)) return QueryError("connection collection", status, error);
    if (!connections) return QueryError("connection collection", E_UNEXPECTED, error);
    ComPtr<IUnknown> unknown;
    status = connections->get__NewEnum(unknown.GetAddressOf());
    if (FAILED(status)) return QueryError("connection enumeration", status, error);
    if (!unknown) return QueryError("connection enumeration", E_UNEXPECTED, error);
    ComPtr<IEnumVARIANT> enumerator;
    status = unknown.As(&enumerator);
    if (FAILED(status)) return QueryError("enumerator interface", status, error);
    if (!enumerator) return QueryError("enumerator interface", E_UNEXPECTED, error);

    std::vector<uint32_t> found;
    for (;;) {
        VARIANT item;
        VariantInit(&item);
        ULONG fetched = 0;
        status = enumerator->Next(1, &item, &fetched);
        if (status == S_FALSE && fetched == 0) {
            VariantClear(&item);
            break;
        }
        if (status != S_OK || fetched != 1) {
            VariantClear(&item);
            return QueryError("next connection", FAILED(status) ? status : E_UNEXPECTED, error);
        }
        IUnknown* object = item.vt == VT_UNKNOWN ? item.punkVal :
                           item.vt == VT_DISPATCH ? item.pdispVal : nullptr;
        ComPtr<INetConnection> connection;
        status = object ? object->QueryInterface(IID_PPV_ARGS(connection.GetAddressOf())) : E_UNEXPECTED;
        VariantClear(&item);
        if (FAILED(status)) return QueryError("connection interface", status, error);
        ComPtr<INetSharingConfiguration> sharing;
        status = manager->get_INetSharingConfigurationForINetConnection(connection.Get(), sharing.GetAddressOf());
        if (FAILED(status)) return QueryError("sharing configuration", status, error);
        if (!sharing) return QueryError("sharing configuration", E_UNEXPECTED, error);
        VARIANT_BOOL enabled = VARIANT_FALSE;
        status = sharing->get_SharingEnabled(&enabled);
        if (FAILED(status)) return QueryError("sharing enabled", status, error);
        if (enabled == VARIANT_FALSE) continue;
        SHARINGCONNECTIONTYPE role = ICSSHARINGTYPE_PRIVATE;
        status = sharing->get_SharingConnectionType(&role);
        if (FAILED(status)) return QueryError("sharing role", status, error);
        if (role != ICSSHARINGTYPE_PUBLIC) continue;

        ComPtr<INetConnectionProps> properties;
        status = manager->get_NetConnectionProps(connection.Get(), properties.GetAddressOf());
        if (FAILED(status)) return QueryError("connection properties", status, error);
        if (!properties) return QueryError("connection properties", E_UNEXPECTED, error);
        BSTR text = nullptr;
        status = properties->get_Guid(&text);
        GUID guid{};
        if (SUCCEEDED(status)) status = text ? CLSIDFromString(text, &guid) : E_UNEXPECTED;
        SysFreeString(text);
        if (FAILED(status)) return QueryError("connection GUID", status, error);
        if (IsEqualGUID(guid, GUID_NULL)) return QueryError("connection GUID", E_UNEXPECTED, error);
        NET_LUID luid{};
        NET_IFINDEX index = 0;
        DWORD code = ConvertInterfaceGuidToLuid(&guid, &luid);
        if (code == NO_ERROR) code = ConvertInterfaceLuidToIndex(&luid, &index);
        if (code != NO_ERROR) return QueryError("interface identity", HRESULT_FROM_WIN32(code), error);
        if (index == 0) return QueryError("interface index", E_UNEXPECTED, error);
        found.push_back(index);
    }
    indices.swap(found);
    error.clear();
    return true;
}

bool IcsInterfaces::Refresh(std::string& error, bool& changed) {
    std::vector<uint32_t> next;
    bool available = false;
    error.clear();
    try {
        available = query_(next, error);
        if (available) {
            std::sort(next.begin(), next.end());
            next.erase(std::unique(next.begin(), next.end()), next.end());
            if (!next.empty() && next.front() == 0) {
                available = false;
                error = "ICS returned a zero interface index";
            }
        }
    } catch (const std::bad_alloc&) {
        available = false;
        error = "ICS query OOM";
    }
    if (!available) next.clear();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        changed = indices_ != next;
        indices_.swap(next);
    }
    return available;
}

bool IcsInterfaces::IsPublic(uint32_t interface_index) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::binary_search(indices_.begin(), indices_.end(), interface_index);
}

std::vector<uint32_t> IcsInterfaces::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return indices_;
}

} // namespace pmkext::monitor
