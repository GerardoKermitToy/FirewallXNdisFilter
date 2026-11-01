#include "WindowsSupport.h"

#include <windows.data.json.h>
#include <wrl/wrappers/corewrappers.h>

namespace hyperv_xndis_filter::setup {
namespace {
using namespace ABI::Windows::Data::Json;
using Microsoft::WRL::Wrappers::HString;
using Microsoft::WRL::Wrappers::HStringReference;

std::wstring JsonText(IJsonObject* object, const wchar_t* name) {
    HString value;
    Check(object->GetNamedString(HStringReference(name).Get(), value.GetAddressOf()), L"Read HNS network string");
    UINT32 length = 0;
    const wchar_t* text = value.GetRawBuffer(&length);
    return {text, length};
}

struct Variant {
    VARIANT value{};
    ~Variant() { VariantClear(&value); }
};
struct Arguments {
    VARIANT values[3]{};
    ~Arguments() { for (auto& value : values) VariantClear(&value); }
};
} // namespace

std::vector<HnsNetwork> ParseHnsNetworks(const std::wstring& json) {
    Microsoft::WRL::Wrappers::RoInitializeWrapper runtime(RO_INIT_MULTITHREADED);
    Check(runtime, L"Initialize HNS JSON parser");
    ComPtr<IJsonObjectStatics> factory;
    Check(RoGetActivationFactory(HStringReference(RuntimeClass_Windows_Data_Json_JsonObject).Get(),
                                IID_PPV_ARGS(&factory)), L"Create HNS JSON parser");
    if (json.size() > UINT32_MAX) throw Error{L"HNS response is too large."};
    HString text;
    Check(text.Set(json.data(), static_cast<UINT32>(json.size())), L"Copy HNS JSON response");
    ComPtr<IJsonObject> root;
    Check(factory->Parse(text.Get(), &root), L"Parse HNS network response");
    boolean success = false;
    Check(root->GetNamedBoolean(HStringReference(L"Success").Get(), &success), L"Read HNS response status");
    if (!success) throw Error{L"HNS network discovery failed. No fallback is allowed."};
    ComPtr<IJsonArray> output;
    Check(root->GetNamedArray(HStringReference(L"Output").Get(), &output), L"Read HNS network list");
    ComPtr<ABI::Windows::Foundation::Collections::IVector<IJsonValue*>> values;
    Check(output.As(&values), L"Read HNS network count");
    UINT32 count = 0;
    Check(values->get_Size(&count), L"Read HNS network count");
    if (count > 4096) throw Error{L"HNS network enumeration exceeded the bounded limit."};
    std::vector<HnsNetwork> networks;
    for (UINT32 i = 0; i < count; ++i) {
        ComPtr<IJsonObject> object;
        Check(output->GetObjectAt(i, &object), L"Read HNS network");
        HnsNetwork network;
        network.type = JsonText(object.Get(), L"Type");
        if (network.type != L"ICS") continue;
        if (!ParseGuid(JsonText(object.Get(), L"ID"), network.id) ||
            !ParseGuid(JsonText(object.Get(), L"SwitchGuid"), network.switch_id)) {
            throw Error{L"Invalid HNS ICS network/switch GUID."};
        }
        networks.push_back(std::move(network));
    }
    return networks;
}

std::vector<HnsNetwork> ReadHnsNetworks() {
    // Same native read-only endpoint used by Windows' Get-HnsNetwork. No child
    // process, network creation, WSL startup, or HNS configuration mutation.
    CLSID clsid{};
    Check(CLSIDFromProgIDEx(L"hns.1", &clsid), L"Find native HNS API");
    ComPtr<IDispatch> hns;
    Check(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER,
                           IID_PPV_ARGS(&hns)), L"Connect to native HNS API");
    LPOLESTR method = const_cast<LPOLESTR>(L"Request2");
    DISPID id = 0;
    Check(hns->GetIDsOfNames(IID_NULL, &method, 1, LOCALE_INVARIANT, &id), L"Find HNS read method");
    Arguments arguments;
    const wchar_t* inputs[] = {L"", L"/networks", L"GET"}; // IDispatch arguments are reversed.
    for (size_t i = 0; i < 3; ++i) {
        arguments.values[i].vt = VT_BSTR;
        arguments.values[i].bstrVal = SysAllocString(inputs[i]);
        if (!arguments.values[i].bstrVal) throw std::bad_alloc();
    }
    DISPPARAMS parameters{arguments.values, nullptr, 3, 0};
    Variant result;
    Check(hns->Invoke(id, IID_NULL, LOCALE_INVARIANT, DISPATCH_METHOD, &parameters,
                      &result.value, nullptr, nullptr), L"Read HNS networks");
    if (result.value.vt != VT_BSTR || !result.value.bstrVal) throw Error{L"Missing HNS network response."};
    return ParseHnsNetworks({result.value.bstrVal, SysStringLen(result.value.bstrVal)});
}
} // namespace hyperv_xndis_filter::setup
