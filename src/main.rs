use kvm_ioctls::VcpuExit;
use libafl_bolts::rands::{self, Rand, RandomSeed as _};
use anyhow::{Ok, Result};
use log;
use rand::RngCore;

mod constants;
mod kvm;
mod vm;
mod cpu_state;

fn main() -> Result<()> {
    env_logger::init();
    let mut rng = rands::StdRand::new();
    let mut vm = vm::GuestVM::new(
        "examples/01_getpid/fuzzvm.physmem",
        "examples/01_getpid/fuzzvm.qemuregs",
    )?;

    loop {
        vm.restore()?;
        // patch some stuff
        vm.set_breakpoint(constants::FORCE_SIG_FAULT_ADDR); // detect signal for crash
        vm.set_breakpoint(constants::LIBC_GETPID_ADDR); // modify pid
        vm.set_breakpoint(constants::STOP_ADDR); // end run
        vm.write_virt(constants::USER_SINGLE_STEP_REPORT_ADDR, 0xc3 as u8); // remove in kernel single step SIGTRAP

        let mut input_data: [u8; 17] = [
            0x66, 0x75, 0x7a, 0x7a, 0x6d, 0x65, 0x74, 0x6f, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x6d,
            0x65, 0x61, 0x00, // "fuzzmetosolvemea\0"
        ];
        // replace a random byte in the input with a new byte
        let offset = rng.below(input_data.len() as u64) as usize;
        let rand_byte = rng.next_u32() as u8;
        input_data[offset] = rand_byte;
        log::trace!("Setting byte {rand_byte:#x} at input_data[{offset}]");
        // set input data
        vm.write_virt(0x555555556000, input_data);
        loop {
            match vm.run()? {
                VcpuExit::Debug(debug_exit) => {
                    if vm.is_trace() {
                        let exception = debug_exit.exception;
                        log::debug!("VcpuExit::Debug {exception:#x}");
                        let rip = vm.vcpu.sync_regs().regs.rip;
                        let cr3 = vm.vcpu.sync_regs().sregs.cr3;
                        log::debug!("{rip:#x?} {cr3:#x}");
                    }
                    if vm.vcpu.sync_regs().regs.rip == constants::LIBC_GETPID_ADDR {
                        // Hit breakpoint in getpid()
                        // Set rax=0xdeadbeef & return
                        let rsp = vm.vcpu.sync_regs().regs.rsp;
                        let ret_addr = vm.read_virt::<u64>(rsp);
                        log::debug!("RSP: {rsp:#x} -> {ret_addr:#x}");
                        let mut regs = vm.vcpu.get_regs().unwrap();
                        regs.rip = ret_addr;
                        regs.rsp += 8;
                        regs.rax = 0xdeadbeef;
                        vm.vcpu.set_regs(&regs).unwrap();
                    }
                    if vm.vcpu.sync_regs().regs.rip == constants::STOP_ADDR {
                        log::info!("End of run! @{:#x}", vm.vcpu.sync_regs().regs.rip);
                        break;
                    }

                    if vm.vcpu.sync_regs().regs.rip == constants::FORCE_SIG_FAULT_ADDR {
                        let signal = i32::try_from(vm.vcpu.sync_regs().regs.rdi).unwrap();
                        if signal == libc::SIGSEGV {
                            log::info!(
                                "We found a crash! code:{} address:{:#x}",
                                vm.vcpu.sync_regs().regs.rsi,
                                vm.vcpu.sync_regs().regs.rdx
                            );
                            return Ok(());
                        } else {
                            log::warn!("Fault with unexpected signal: {signal}");
                        }
                    }
                }
                r => {
                    log::error!("Unexpected exit reason: VcpuExit::{r:x?}");
                    break;
                }
            }
        }
    }
}


