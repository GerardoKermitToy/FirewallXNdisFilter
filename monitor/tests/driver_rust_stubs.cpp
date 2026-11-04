// Only the production no_std Rust panic boundary is faked. No device/registry
// entry points or WDK structure layouts are used by these portable logic tests.
#include <cstdlib>
extern "C" [[noreturn]] void hv_bugcheck() { std::abort(); }
