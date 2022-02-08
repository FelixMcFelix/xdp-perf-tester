#![no_std]
#![no_main]
use probes::xskmaptest::*;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

pub static mut PKT_CT: u64 = 0;

#[map(link_section = "maps")]
static mut xsks_map: XskMap = XskMap::with_max_entries(N_CORES_ROUND_POT as u32);

#[xdp]
fn xdp_sock_prog(ctx: XdpContext) -> XdpResult {
	let target = unsafe {
		let target = if N_CORES.is_power_of_two() {
			PKT_CT & (N_CORES as u64 - 1)
		} else {
			PKT_CT % N_CORES as u64
		};

		PKT_CT = PKT_CT.wrapping_add(1);
		target as u32
	};

	for i in 0..N_OPS {
		black_box(1 + i);
	}

    if TX_PERCENT == u32::MAX {
        Ok(XdpAction::Tx)
    } else if TX_PERCENT == 0 || bpf_get_prandom_u32() > TX_PERCENT {
		Ok(unsafe {
			xsks_map
				.redirect(target)
				.map(|_| XdpAction::Redirect)
				.unwrap_or(XdpAction::Drop)
		})
	} else {
		Ok(XdpAction::Tx)
	}
}

// Lifted wholesale from https://docs.rs/criterion/latest/src/criterion/lib.rs.html#172-178
fn black_box<T>(dummy: T) -> T {
	unsafe {
		let ret = core::ptr::read_volatile(&dummy);
		core::mem::forget(dummy);
		ret
	}
}
