// Internal pure-logic ABI; no WDK descriptors, callbacks or packet ownership.
#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
int32_t FwxDeviceControl(uint32_t code, uint32_t inputLength, uint8_t* output,
    uint32_t capacity, uint64_t runningCount, uint32_t* transferred);
#ifdef __cplusplus
}
#endif
