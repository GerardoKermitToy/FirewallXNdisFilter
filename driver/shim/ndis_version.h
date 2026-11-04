// Runtime registration and OOB bounds for the NDIS versions this LWF supports.
#pragma once

static inline UINT HvNdisVersion(UINT runtime) {
    const UINT versions[] = {
        NDIS_RUNTIME_VERSION_689, NDIS_RUNTIME_VERSION_688, NDIS_RUNTIME_VERSION_687,
        NDIS_RUNTIME_VERSION_686, NDIS_RUNTIME_VERSION_685, NDIS_RUNTIME_VERSION_684,
        NDIS_RUNTIME_VERSION_683, NDIS_RUNTIME_VERSION_682, NDIS_RUNTIME_VERSION_681,
        NDIS_RUNTIME_VERSION_680, NDIS_RUNTIME_VERSION_670, NDIS_RUNTIME_VERSION_660,
        NDIS_RUNTIME_VERSION_651, NDIS_RUNTIME_VERSION_650, NDIS_RUNTIME_VERSION_640
    };
    for (UINT version : versions) if (runtime >= version) return version;
    return 0;
}

static inline BOOLEAN HvSetNdisVersion(NDIS_FILTER_DRIVER_CHARACTERISTICS* c, UINT version) {
    if (version < NDIS_RUNTIME_VERSION_640 || version > NDIS_RUNTIME_VERSION_689) return FALSE;
    c->Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    c->Header.Revision = version >= NDIS_RUNTIME_VERSION_680 ?
        NDIS_FILTER_CHARACTERISTICS_REVISION_3 : NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    c->Header.Size = version >= NDIS_RUNTIME_VERSION_680 ?
        NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_3 : NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2;
    c->MajorNdisVersion = static_cast<UCHAR>(version >> 16);
    c->MinorNdisVersion = static_cast<UCHAR>(version & 0xffff);
    return TRUE;
}

static inline ULONG HvNblInfoCount(UINT version) {
    if (version >= NDIS_RUNTIME_VERSION_680) return MaxNetBufferListInfo;
    if (version >= NDIS_RUNTIME_VERSION_650) return GftFlowEntryId + 1;
    return RscTcpTimestampDelta + 1;
}
