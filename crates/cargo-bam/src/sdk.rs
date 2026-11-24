//! SDK header export (`bamabi.h`, `bamabi.hpp`, `bamabi.zig`) delegated to
//! [`bamabi_build::sdk`].

pub use bamabi_build::sdk::{CPP17_HEADER, ZIG_SDK, c99_header, export_sdk};
