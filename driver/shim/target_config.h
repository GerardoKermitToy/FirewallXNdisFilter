// Exact host-vNIC allowlist shared by the kernel gate and offline user-mode tests.
#ifndef HYPERV_XNDIS_FILTER_TARGET_CONFIG_H
#define HYPERV_XNDIS_FILTER_TARGET_CONFIG_H

#define HV_TARGET_CONFIG_VERSION 3u
#define HV_TARGET_ENTRY_SIZE 24u
// Counts are bounded only by the native u32 registry-value byte length.
static inline int HvTargetsSize(unsigned int count, unsigned int* size) {
    if (count > (~0u - 4u) / HV_TARGET_ENTRY_SIZE) return 0;
    *size = 4u + count * HV_TARGET_ENTRY_SIZE;
    return 1;
}

static inline unsigned int HvTargetsRead32(const unsigned char* data) {
    return (unsigned int)data[0] | ((unsigned int)data[1] << 8) |
        ((unsigned int)data[2] << 16) | ((unsigned int)data[3] << 24);
}
static inline unsigned long long HvTargetsRead64(const unsigned char* data) {
    return (unsigned long long)HvTargetsRead32(data) |
        ((unsigned long long)HvTargetsRead32(data + 4) << 32);
}
static inline void HvTargetsWrite32(unsigned char* data, unsigned int value) {
    for (unsigned int i = 0; i < 4; ++i) data[i] = (unsigned char)(value >> (8 * i));
}
static inline void HvTargetsWrite64(unsigned char* data, unsigned long long value) {
    for (unsigned int i = 0; i < 8; ++i) data[i] = (unsigned char)(value >> (8 * i));
}
static inline int HvTargetsEqualGuid(const unsigned char* left, const unsigned char* right) {
    for (unsigned int i = 0; i < 16; ++i) if (left[i] != right[i]) return 0;
    return 1;
}
static inline int HvTargetsValid(const unsigned char* data, unsigned int size) {
    if (!data || size < 4) return 0;
    const unsigned int count = HvTargetsRead32(data);
    unsigned int expected = 0;
    if (!HvTargetsSize(count, &expected) || size != expected) return 0;
    for (unsigned int i = 0; i < count; ++i) {
        const unsigned char* entry = data + 4 + i * HV_TARGET_ENTRY_SIZE;
        unsigned char nonzero = 0;
        for (unsigned int j = 0; j < 16; ++j) nonzero |= entry[j];
        if (!nonzero || HvTargetsRead64(entry + 16) == 0) return 0;
        for (unsigned int j = 0; j < i; ++j) {
            const unsigned char* previous = data + 4 + j * HV_TARGET_ENTRY_SIZE;
            if (HvTargetsEqualGuid(entry, previous) ||
                HvTargetsRead64(entry + 16) == HvTargetsRead64(previous + 16)) return 0;
        }
    }
    return 1;
}
static inline int HvTargetsMatch(const unsigned char* data, unsigned int size,
    const unsigned char* guid, unsigned long long luid) {
    if (!guid || !luid || !HvTargetsValid(data, size)) return 0;
    for (unsigned int i = 0; i < HvTargetsRead32(data); ++i) {
        const unsigned char* entry = data + 4 + i * HV_TARGET_ENTRY_SIZE;
        if (HvTargetsRead64(entry + 16) == luid && HvTargetsEqualGuid(entry, guid)) return 1;
    }
    return 0;
}
#endif
