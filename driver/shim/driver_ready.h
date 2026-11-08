#pragma once

// Startup notification only; device access/version checks remain authoritative.
// Win32 Global maps to the kernel's session-independent BaseNamedObjects directory.
#define FWX_READY_EVENT_USER_NAME L"Global\\FirewallXNdisFilter.DriverReady"
#define FWX_READY_EVENT_KERNEL_NAME L"\\BaseNamedObjects\\FirewallXNdisFilter.DriverReady"
