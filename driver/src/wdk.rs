//! Bindings are generated from the installed x64 WDK, never copied by hand.
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code,
    unsafe_op_in_unsafe_fn,
    unused_imports,
    clippy::all
)]
include!(concat!(env!("OUT_DIR"), "/wdk.rs"));
