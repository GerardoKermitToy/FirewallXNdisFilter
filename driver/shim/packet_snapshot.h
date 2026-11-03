#ifndef HYPERV_XNDIS_FILTER_PACKET_SNAPSHOT_H
#define HYPERV_XNDIS_FILTER_PACKET_SNAPSHOT_H

// Borrow only while the caller owns the NB. Storage is optional for contiguous
// input; a split prefix needs caller-owned scratch. Neither path moves offsets.
static inline const UCHAR* HvSnapshotView(PNET_BUFFER nb, UCHAR* storage, ULONG cap,
    ULONG* copied, ULONG* frameLength) {
    *copied = 0;
    *frameLength = nb == NULL ? 0 : NET_BUFFER_DATA_LENGTH(nb);
    ULONG length = cap < *frameLength ? cap : *frameLength;
    if (length == 0) return NULL;
    const auto* data = static_cast<const UCHAR*>(NdisGetDataBuffer(nb, length, storage, 1, 0));
    if (data == NULL) return NULL;
    *copied = length;
    return data;
}
// Event records must own their bytes even when NDIS returns a borrowed pointer.
static inline ULONG HvSnapshotCopy(PNET_BUFFER nb, UCHAR* out, ULONG cap,
    ULONG* copied, ULONG* frameLength) {
    const UCHAR* data = HvSnapshotView(nb, out, out == NULL ? 0 : cap, copied, frameLength);
    if (data == NULL) return 0;
    if (data != out) RtlCopyMemory(out, data, *copied);
    return 1;
}

#endif
