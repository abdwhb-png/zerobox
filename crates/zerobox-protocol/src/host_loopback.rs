//! Private descriptor-transfer contract for the dedicated host alias transport.
pub const ALIAS: &str = "host.zerobox.internal";
pub const ADDRESS: [u8; 4] = [198, 18, 0, 1];
pub const MAGIC: &[u8; 4] = b"ZHL1";
pub const ACK: u8 = 1;
