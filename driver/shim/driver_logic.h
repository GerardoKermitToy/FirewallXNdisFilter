// Internal pure-logic ABI; no WDK descriptors, callbacks or packet ownership.
#pragma once
#include <stdint.h>

#define HV_TARGET_CONFIG_VERSION 3u
#ifdef __cplusplus
extern "C" {
#endif
uint32_t HvTargetAdapterMatch(const uint8_t* data, uint32_t length,
    const uint8_t* guid, uint64_t luid);
int32_t HvDeviceControl(uint32_t code, uint32_t inputLength, uint8_t* output,
    uint32_t capacity, uint64_t runningCount, uint32_t* transferred);
#ifdef __cplusplus
}
#endif
