// NetCfg notification object: require armed configuration and an unambiguous adapter.
// Not registered or loaded by the build; NetCfg owns its installation lifecycle.
#include "BindingPolicy.h"
#include "NetCfgTrace.h"
#include "AdapterInventory.h"
#include "NotifyRegistration.h"
#include <new>
#include <string>

namespace {
HMODULE moduleHandle;
volatile LONG objects = 0, locks = 0;

class NotifyObject final : public INetCfgComponentControl, public INetCfgComponentNotifyBinding {
    volatile LONG refs_ = 1;
    std::vector<GUID> adapters_;
public:
    NotifyObject() { InterlockedIncrement(&objects); }
    ~NotifyObject() { InterlockedDecrement(&objects); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (out == nullptr) return E_POINTER;
        *out = nullptr;
        if (iid == IID_IUnknown || iid == IID_INetCfgComponentControl)
            *out = static_cast<INetCfgComponentControl*>(this);
        else if (iid == IID_INetCfgComponentNotifyBinding)
            *out = static_cast<INetCfgComponentNotifyBinding*>(this);
        else return E_NOINTERFACE;
        AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        const LONG remaining = InterlockedDecrement(&refs_);
        if (remaining == 0) delete this;
        return static_cast<ULONG>(remaining);
    }
    HRESULT STDMETHODCALLTYPE Initialize(INetCfgComponent*, INetCfg* config, BOOL) override {
        try {
            const HRESULT hr = firewallx_ndis_filter::ReadBindingAdapterInventory(config, adapters_);
            firewallx_ndis_filter::TraceNetCfg("Initialize adapter inventory", hr);
            return hr;
        } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
        catch (...) { return E_UNEXPECTED; }
    }
    HRESULT STDMETHODCALLTYPE ApplyRegistryChanges() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE ApplyPnpChanges(INetCfgPnpReconfigCallback*) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE CancelChanges() override { return S_OK; }
    HRESULT STDMETHODCALLTYPE QueryBindingPath(DWORD flags, INetCfgBindingPath* path) override {
        return firewallx_ndis_filter::EvaluateBindingPath(flags, path, adapters_);
    }
    HRESULT STDMETHODCALLTYPE NotifyBindingPath(DWORD flags, INetCfgBindingPath*) override {
        firewallx_ndis_filter::TraceNetCfg("NotifyBindingPath", S_OK, flags);
        return S_OK;
    }
};

class ClassFactory final : public IClassFactory {
    volatile LONG refs_ = 1;
public:
    ClassFactory() { InterlockedIncrement(&objects); }
    ~ClassFactory() { InterlockedDecrement(&objects); }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (out == nullptr) return E_POINTER;
        *out = nullptr;
        if (iid != IID_IUnknown && iid != IID_IClassFactory) return E_NOINTERFACE;
        *out = static_cast<IClassFactory*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        const LONG remaining = InterlockedDecrement(&refs_);
        if (remaining == 0) delete this;
        return static_cast<ULONG>(remaining);
    }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** out) override {
        if (out == nullptr) return E_POINTER;
        *out = nullptr;
        if (outer != nullptr) return CLASS_E_NOAGGREGATION;
        auto* object = new (std::nothrow) NotifyObject;
        if (object == nullptr) return E_OUTOFMEMORY;
        const HRESULT hr = object->QueryInterface(iid, out);
        object->Release(); return hr;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) InterlockedIncrement(&locks);
        else InterlockedDecrement(&locks);
        return S_OK;
    }
};

}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) { moduleHandle = instance; DisableThreadLibraryCalls(instance); }
    return TRUE;
}
extern "C" HRESULT __stdcall DllGetClassObject(REFCLSID clsid, REFIID iid, void** out) {
    if (out == nullptr) return E_POINTER;
    *out = nullptr;
    if (clsid != firewallx_ndis_filter::kNotifyClsid) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new (std::nothrow) ClassFactory;
    if (factory == nullptr) return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(iid, out);
    factory->Release(); return hr;
}
extern "C" HRESULT __stdcall DllCanUnloadNow() {
    return InterlockedCompareExchange(&objects, 0, 0) == 0 &&
        InterlockedCompareExchange(&locks, 0, 0) == 0 ? S_OK : S_FALSE;
}
extern "C" HRESULT __stdcall DllRegisterServer() {
    try { return firewallx_ndis_filter::RegisterNotifyServer(moduleHandle); }
    catch (...) { return E_OUTOFMEMORY; }
}
extern "C" HRESULT __stdcall DllUnregisterServer() {
    try { return firewallx_ndis_filter::UnregisterNotifyServer(); }
    catch (...) { return E_OUTOFMEMORY; }
}
