#include "BindingPolicy.h"
#include "TargetConfig.h"
#include "NetCfgTrace.h"

namespace hyperv_xndis_filter {

HRESULT EvaluateBindingPath(DWORD flags, INetCfgBindingPath* path, const std::vector<GUID>& adapters) {
    TraceNetCfg("QueryBindingPath", S_OK, flags);
    if (path == nullptr) return E_POINTER;
    if ((flags & (NCN_DISABLE | NCN_REMOVE)) != 0 || (flags & (NCN_ENABLE | NCN_ADD)) == 0) return S_OK;
    TargetConfig targets;
    const bool configured = ReadTargetConfig(targets, true) == ERROR_SUCCESS;
    BindingPathIdentity identity;
    const HRESULT hr = InspectBindingPath(path, kFilterInstanceId, adapters, identity);
    TraceNetCfg("InspectBindingPath", hr, flags);
    if (FAILED(hr)) return hr;
    const bool matches = configured && identity.adapters == 1 && TargetConfig::IsCurrentAdapter(identity.adapter);
    const HRESULT decision = BindingDecision(flags, identity.owns_path, configured, identity.adapters, matches);
    TraceNetCfg("BindingDecision", decision, flags);
    return decision;
}
}
