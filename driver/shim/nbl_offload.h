// Native scalar offload/OOB handling, shared with offline packet tests.
#pragma once

static inline BOOLEAN HvNblReceiveCoalesced(PNET_BUFFER_LIST nbl) {
    return NET_BUFFER_LIST_INFO(nbl, TcpRecvSegCoalesceInfo) != NULL || NET_BUFFER_LIST_IS_URO_SET(nbl);
}

static inline BOOLEAN HvNblSendSegmented(PNET_BUFFER_LIST nbl) {
    return NET_BUFFER_LIST_INFO(nbl, TcpLargeSendNetBufferListInfo) != NULL || NET_BUFFER_LIST_IS_USO_SET(nbl);
}

static inline BOOLEAN HvCopyReceiveMetadataSupported(PNET_BUFFER_LIST nbl, ULONG infoCount) {
    // Only inline receive OOB with a known lifetime may outlive the callback.
    // URO SegCount/SegSize are scalars, not borrowed metadata pointers.
    for (ULONG i = 0; i < infoCount; ++i) {
        if (NET_BUFFER_LIST_INFO(nbl, i) == NULL) continue;
        switch (i) {
        case TcpIpChecksumNetBufferListInfo:
        case TcpReceiveNoPush:
        case Ieee8021QNetBufferListInfo:
        case NetBufferListFrameType:
        case NetBufferListHashValue:
        case NetBufferListHashInfo:
        case UdpRecvSegCoalesceOffloadInfo:
            break;
        default:
            return FALSE;
        }
    }
    return TRUE;
}

static inline void HvCopyReceiveUroInfo(PNET_BUFFER_LIST copy, PNET_BUFFER_LIST source) {
    NET_BUFFER_LIST_INFO(copy, UdpRecvSegCoalesceOffloadInfo) =
        NET_BUFFER_LIST_INFO(source, UdpRecvSegCoalesceOffloadInfo);
}
