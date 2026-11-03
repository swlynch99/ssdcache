//! IO-free storage core shared by the server and the simulator.
pub mod fifo;
pub mod index;
pub mod policy;
pub mod shard;
pub mod slots;

/// "No slot / no entry / no location".
pub const NONE: u32 = u32::MAX;
