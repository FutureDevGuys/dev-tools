//! One product-owned source for the native sudo records and embedding identity.

pub const PLUGIN_API_MAJOR: u32 = 1;
pub const PLUGIN_API_MINOR: u32 = 22;
pub const GROUP_API_MAJOR: u32 = 1;
pub const GROUP_API_MINOR: u32 = 0;

pub const PLUGIN_API_VERSION: u32 = (PLUGIN_API_MAJOR << 16) | PLUGIN_API_MINOR;
pub const GROUP_API_VERSION: u32 = (GROUP_API_MAJOR << 16) | GROUP_API_MINOR;

pub fn identity() -> String {
    format!(
        "sudo-plugin-api-{}.{}:group-api-{}.{}",
        PLUGIN_API_VERSION >> 16,
        PLUGIN_API_VERSION & 0xffff,
        GROUP_API_VERSION >> 16,
        GROUP_API_VERSION & 0xffff,
    )
}
