#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::PerfEventArray,
    programs::XdpContext,
};
use rias_common::PacketBuffer;

#[map]
pub static DATA: PerfEventArray<PacketBuffer> = PerfEventArray::new(0);

#[xdp]
pub fn rias(ctx: XdpContext) -> u32 {
    match try_rias(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_rias(ctx: XdpContext) -> Result<u32, ()> {
    let len = ctx.data_end() - ctx.data();
    DATA.output(&ctx, &PacketBuffer { size: len }, len as u32);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
