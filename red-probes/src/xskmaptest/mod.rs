
use cty::*;

// This is where you should define the types shared by the kernel and user
// space, eg:
//
// #[repr(C)]
// #[derive(Debug)]
// pub struct SomeEvent {
//     pub pid: u64,
//     ...
// }

pub const N_CORES: usize = if let Some(ct) = option_env!("XPP_TEST_CORES") {
	konst::result::unwrap_or!(konst::primitive::parse_usize(ct), 1)
} else {
	1
};

pub const N_CORES_ROUND_POT: usize = N_CORES.next_power_of_two();

pub const N_OPS: usize = if let Some(ct) = option_env!("XPP_TEST_OPS") {
	konst::result::unwrap_or!(konst::primitive::parse_usize(ct), 0)
} else {
	0
};

pub const TX_PERCENT: u32 = if let Some(ct) = option_env!("XPP_TEST_TX_RATE") {
	konst::result::unwrap_or!(konst::primitive::parse_u32(ct), 0)
} else {
	0
};

