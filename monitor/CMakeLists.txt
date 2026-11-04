cmake_minimum_required(VERSION 3.20)
project(hyperv_monitor LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "HyperVXNdisFilter monitor targets Windows only.")
endif()

if(MSVC)
    # Apply to every product, static library, example and offline test, including
    # the setup subdirectory. Keep Release optimized despite enabling the linker
    # debug option, which otherwise changes the default /OPT settings.
    add_compile_options(/Zi)
    add_link_options(/DEBUG:FULL "/PDBALTPATH:%_PDB%"
        "$<$<NOT:$<CONFIG:Debug>>:/OPT:REF>"
        "$<$<NOT:$<CONFIG:Debug>>:/OPT:ICF>")
    set(CMAKE_PDB_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
endif()

# Direct device access only. No transport subproject or installed driver is
# required to build the monitor and offline tests.
add_library(pmkext STATIC
    src/PortmasterKext.cpp
    src/DriverProtocol.cpp
    src/MonitorOptions.cpp
    src/DriverStartup.cpp
)
target_compile_features(pmkext PUBLIC cxx_std_20)
target_include_directories(pmkext PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_compile_definitions(pmkext PUBLIC
    UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX
    _WIN32_WINNT=0x0A00 WINVER=0x0A00
)
target_link_libraries(pmkext PUBLIC ws2_32 advapi32)
if(MSVC)
    target_compile_options(pmkext PRIVATE /W4 /permissive- /utf-8)
    target_compile_definitions(pmkext PUBLIC _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(pmkext PRIVATE -Wall -Wextra)
endif()

add_executable(hyperv_monitor src/main.cpp src/DriverLoader.cpp src/IcsInterfaces.cpp)
target_link_libraries(hyperv_monitor PRIVATE pmkext advapi32 ole32 oleaut32 uuid iphlpapi)
if(MSVC)
    target_compile_options(hyperv_monitor PRIVATE /W4 /permissive- /utf-8)
    # Help/invalid-CLI tests must run without elevation or device access. Actual
    # device sessions still require an elevated token because of the driver ACL.
    target_link_options(hyperv_monitor PRIVATE
        /ENTRY:wmainCRTStartup
        "/MANIFESTUAC:level='asInvoker' uiAccess='false'"
    )
else()
    target_compile_options(hyperv_monitor PRIVATE -Wall -Wextra)
    target_link_options(hyperv_monitor PRIVATE -municode)
endif()

# NetCfg loads this user-mode COM object during explicit installation/binding.
# Building it never registers it or changes network configuration.
add_library(hyperv_xndis_filter_notify SHARED
    ../install/notify/BindingPolicy.cpp
    ../install/notify/NotifyObject.cpp
    ../install/notify/HyperVXNdisFilterNotify.def
)
set_target_properties(hyperv_xndis_filter_notify PROPERTIES OUTPUT_NAME HyperVXNdisFilterNotify
    PDB_NAME HyperVXNdisFilterNotify
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_compile_features(hyperv_xndis_filter_notify PRIVATE cxx_std_20)
target_compile_definitions(hyperv_xndis_filter_notify PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_link_libraries(hyperv_xndis_filter_notify PRIVATE ole32 advapi32 uuid iphlpapi)
if(MSVC)
    target_compile_options(hyperv_xndis_filter_notify PRIVATE /W4 /WX /permissive- /utf-8 /guard:cf)
    target_link_options(hyperv_xndis_filter_notify PRIVATE /DYNAMICBASE /NXCOMPAT /GUARD:CF)
endif()

# Independent header-only consumers: no pmkext library or codec dependency.
function(add_header_client_target target source)
    add_executable(${target} ${source})
    target_compile_features(${target} PRIVATE cxx_std_20)
    target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
    target_compile_definitions(${target} PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN
        _WIN32_WINNT=0x0A00)
    target_link_libraries(${target} PRIVATE advapi32)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive- /utf-8)
    endif()
endfunction()
add_header_client_target(callback_client examples/callback_client.cpp)

include(CTest)
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../install/console" "${CMAKE_CURRENT_BINARY_DIR}/setup")
if(BUILD_TESTING)
    add_header_client_target(header_client_tests tests/header_client_tests.cpp)
    add_test(NAME header_client_tests COMMAND header_client_tests)
    set_tests_properties(header_client_tests PROPERTIES TIMEOUT 30 LABELS "no-driver")
    foreach(test_name IN ITEMS ip_address_tests protocol_codec_tests adapter_info_tests monitor_options_tests
                               driver_startup_tests delayed_verdict_tests record_output_tests
                               binding_policy_tests target_config_tests netcfg_binding_tests notify_registration_tests driver_logic_tests)
        add_executable(${test_name} "tests/${test_name}.cpp")
        target_link_libraries(${test_name} PRIVATE pmkext)
        if(MSVC)
            target_compile_options(${test_name} PRIVATE /W4 /permissive- /utf-8)
        endif()
        add_test(NAME ${test_name} COMMAND ${test_name})
        set_tests_properties(${test_name} PROPERTIES
            TIMEOUT 15
            WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
            LABELS "no-driver"
        )
    endforeach()
    add_executable(ics_interfaces_tests tests/ics_interfaces_tests.cpp src/IcsInterfaces.cpp)
    target_link_libraries(ics_interfaces_tests PRIVATE pmkext ole32 oleaut32 uuid iphlpapi)
    if(MSVC)
        target_compile_options(ics_interfaces_tests PRIVATE /W4 /WX /permissive- /utf-8)
    endif()
    add_test(NAME ics_interfaces_tests COMMAND ics_interfaces_tests)
    set_tests_properties(ics_interfaces_tests PROPERTIES TIMEOUT 15 LABELS "no-driver")
    find_program(CARGO_EXECUTABLE cargo REQUIRED)
    # These suites compile the production Rust native modules against generated
    # WDK layouts. Only kernel API side effects are faked; no C++ native copy.
    foreach(suite IN ITEMS native_packet native_ndis native_device native_wfp)
        if(suite STREQUAL "native_wfp")
            set(test_name wfp_management_tests)
            set(test_filter "native_wfp::")
        elseif(suite STREQUAL "native_ndis")
            set(test_name native_ndis_tests)
            set(test_filter "native::ndis::")
        elseif(suite STREQUAL "native_device")
            set(test_name native_device_tests)
            set(test_filter "native::device::")
        else()
            set(test_name "${suite}_tests")
            set(test_filter "${suite}::")
        endif()
        add_test(NAME ${test_name}
            COMMAND "${CMAKE_COMMAND}" -E env --unset=RUSTFLAGS --unset=CARGO_ENCODED_RUSTFLAGS
                "${CARGO_EXECUTABLE}" test --release --locked -p hyperv-native-tests --lib
                "${test_filter}" -- --test-threads=1)
        set_tests_properties(${test_name} PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE LABELS "no-driver"
            PASS_REGULAR_EXPRESSION "test result: ok\\. [1-9][0-9]* passed"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/..")
    endforeach()
    # Portable kernel logic uses its own host archive: adapter/header fixtures
    # must not pull the WFP fake-native ABI into otherwise independent tests.
    set(DRIVER_RUST_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/driver-rust")
    set(DRIVER_RUST_LIBRARY "${DRIVER_RUST_TARGET_DIR}/release/hyperv_driver_tests.lib")
    add_custom_command(OUTPUT "${DRIVER_RUST_LIBRARY}"
        COMMAND "${CMAKE_COMMAND}" -E env --unset=RUSTFLAGS --unset=CARGO_ENCODED_RUSTFLAGS
            "${CARGO_EXECUTABLE}" build --release --locked -p hyperv-driver-tests
            --target-dir "${DRIVER_RUST_TARGET_DIR}"
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
        DEPENDS tests/driver_rust/lib.rs tests/driver_rust/Cargo.toml tests/driver_rust/build.rs
            ../driver/src/adapter_info.rs ../driver/src/device_control.rs ../driver/src/target_config.rs
            ../protocol/src/lib.rs ../driver/build_constants.rs ../Cargo.toml ../Cargo.lock
        VERBATIM)
    add_custom_target(driver_rust_test_library DEPENDS "${DRIVER_RUST_LIBRARY}")
    foreach(test_name IN ITEMS adapter_info_tests header_client_tests driver_logic_tests)
        add_dependencies(${test_name} driver_rust_test_library)
        target_sources(${test_name} PRIVATE tests/driver_rust_stubs.cpp)
        target_link_libraries(${test_name} PRIVATE "${DRIVER_RUST_LIBRARY}")
    endforeach()
    if(MSVC)
        target_compile_options(driver_logic_tests PRIVATE /WX)
    endif()
    target_link_libraries(netcfg_binding_tests PRIVATE ole32 uuid)
    target_link_libraries(notify_registration_tests PRIVATE ole32 uuid)
    if(MSVC)
        target_compile_options(notify_registration_tests PRIVATE /WX)
    endif()
    if(MSVC)
        target_compile_options(netcfg_binding_tests PRIVATE /WX)
    endif()
    add_executable(notify_object_tests tests/notify_object_tests.cpp)
    target_compile_features(notify_object_tests PRIVATE cxx_std_20)
    target_link_libraries(notify_object_tests PRIVATE uuid)
    add_dependencies(notify_object_tests hyperv_xndis_filter_notify)
    if(MSVC)
        target_compile_options(notify_object_tests PRIVATE /W4 /permissive- /utf-8 /wd4191)
    endif()
    add_test(NAME notify_object_tests COMMAND notify_object_tests $<TARGET_FILE:hyperv_xndis_filter_notify>)
    set_tests_properties(notify_object_tests PROPERTIES TIMEOUT 15 LABELS "no-driver")
    add_executable(driver_loader_tests tests/driver_loader_tests.cpp)
    target_link_libraries(driver_loader_tests PRIVATE pmkext)
    if(MSVC)
        target_compile_options(driver_loader_tests PRIVATE /W4 /WX /permissive- /utf-8)
    endif()
    add_test(NAME driver_loader_tests COMMAND driver_loader_tests)
    set_tests_properties(driver_loader_tests PROPERTIES TIMEOUT 15 LABELS "no-driver")
    add_test(NAME monitor_help COMMAND hyperv_monitor --help)
    set_tests_properties(monitor_help PROPERTIES TIMEOUT 10 LABELS "no-driver"
                        PASS_REGULAR_EXPRESSION "positive seconds")
    add_test(NAME monitor_cli_tests
        COMMAND "${CMAKE_COMMAND}" "-DMONITOR=$<TARGET_FILE:hyperv_monitor>"
                "-DTEST_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/monitor_cli_tests.cmake")
    set_tests_properties(monitor_cli_tests PROPERTIES TIMEOUT 40 LABELS "no-driver")
    find_program(POWERSHELL_EXECUTABLE NAMES powershell.exe REQUIRED)
    add_test(NAME management_script_tests
        COMMAND "${POWERSHELL_EXECUTABLE}" -NoProfile -NonInteractive -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/tests/management_tests.ps1")
    set_tests_properties(management_script_tests PROPERTIES TIMEOUT 15 LABELS "no-driver")
    add_test(NAME build_options_tests
        COMMAND "${POWERSHELL_EXECUTABLE}" -NoProfile -NonInteractive -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/tests/build_options_tests.ps1")
    set_tests_properties(build_options_tests PROPERTIES TIMEOUT 15 LABELS "no-driver")
    add_test(NAME driver_version_tests
        COMMAND "${POWERSHELL_EXECUTABLE}" -NoProfile -NonInteractive -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/tests/driver_version_tests.ps1")
    set_tests_properties(driver_version_tests PROPERTIES TIMEOUT 15 LABELS "no-driver")
    add_test(NAME ndis_version_tests
        COMMAND "${POWERSHELL_EXECUTABLE}" -NoProfile -NonInteractive -ExecutionPolicy Bypass
                -File "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/tests/ndis_version_tests.ps1")
    set_tests_properties(ndis_version_tests PROPERTIES TIMEOUT 15 LABELS "no-driver")
endif()
