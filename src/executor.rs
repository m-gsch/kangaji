use std::marker::PhantomData;

use kvm_ioctls::VcpuExit;
use libafl::{
    executors::{Executor, ExitKind, HasObservers},
    inputs::{HasTargetBytes, UsesInput},
    observers::{ObserversTuple, UsesObservers},
    state::{HasExecutions, State, UsesState},
    Error,
};
use libafl_bolts::{tuples::MatchName, AsSlice, ErrorBacktrace};

use crate::{constants, kangaji::Kangaji};

pub struct KangajiExecutor<OT, S> {
    pub vm: Kangaji,
    /// The observers used by this executor
    observers: OT,
    phantom: PhantomData<S>,
}

impl<OT, S> KangajiExecutor<OT, S>
where
    OT: MatchName + ObserversTuple<S>,
    S: UsesInput,
{
    pub fn new(vm: Kangaji, observers: OT) -> Self {
        Self {
            vm,
            observers,
            phantom: PhantomData,
        }
    }
}

impl<EM, OT, S, Z> Executor<EM, Z> for KangajiExecutor<OT, S>
where
    EM: UsesState<State = S>,
    S: State + HasExecutions,
    S::Input: HasTargetBytes,
    OT: MatchName + ObserversTuple<S>,
    Z: UsesState<State = S>,
{
    fn run_target(
        &mut self,
        _fuzzer: &mut Z,
        state: &mut Self::State,
        _mgr: &mut EM,
        input: &Self::Input,
    ) -> Result<ExitKind, Error> {
        self.vm.restore().unwrap();
        *state.executions_mut() += 1;
        // patch some stuff
        self.vm
            .write_virt(constants::USER_SINGLE_STEP_REPORT_ADDR, 0xc3 as u8); // remove in kernel single step SIGTRAP
        let data = input.target_bytes();
        let data = data.as_slice();
        let mut input_data: [u8; 17] = [
            0x66, 0x75, 0x7a, 0x7a, 0x6d, 0x65, 0x74, 0x6f, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x6d,
            0x65, 0x61, 0x00, // "fuzzmetosolvemea\0"
        ];
        for i in 0..4 {
            input_data[15-i] = *data.get(i).unwrap_or(&u8::MIN);
        }
        // set input data
        self.vm.write_virt(0x555555556000, input_data);
        loop {
            match self.vm.run().unwrap() {
                VcpuExit::Debug(_) => {
                    if self.vm.vcpu.sync_regs().regs.rip == constants::LIBC_GETPID_ADDR {
                        // Hit breakpoint in getpid()
                        // Set rax=0xdeadbeef & return
                        let rsp = self.vm.vcpu.sync_regs().regs.rsp;
                        let ret_addr = self.vm.read_virt::<u64>(rsp);
                        log::debug!("RSP: {rsp:#x} -> {ret_addr:#x}");
                        let mut regs = self.vm.vcpu.get_regs().unwrap();
                        regs.rip = ret_addr;
                        regs.rsp += 8;
                        regs.rax = 0xdeadbeef;
                        self.vm.vcpu.set_regs(&regs).unwrap();
                    }
                    if self.vm.vcpu.sync_regs().regs.rip == constants::STOP_ADDR {
                        log::debug!("End of run! @{:#x}", self.vm.vcpu.sync_regs().regs.rip);
                        break;
                    }

                    if self.vm.vcpu.sync_regs().regs.rip == constants::FORCE_SIG_FAULT_ADDR {
                        let signal = i32::try_from(self.vm.vcpu.sync_regs().regs.rdi).unwrap();
                        if signal == libc::SIGSEGV {
                            log::info!(
                                "We found a crash! code:{} address:{:#x}",
                                self.vm.vcpu.sync_regs().regs.rsi,
                                self.vm.vcpu.sync_regs().regs.rdx
                            );
                            return Ok(ExitKind::Crash);
                        } else {
                            log::warn!("Fault with unexpected signal: {signal}");
                        }
                    }
                }
                r => {
                    log::error!("Unexpected exit reason: VcpuExit::{r:x?}");
                    return Err(Error::IllegalState(
                        "Unexpected exit reason.".to_owned(),
                        ErrorBacktrace::default(),
                    ));
                }
            }
        }
        Ok(ExitKind::Ok)
    }
}

impl<OT, S> UsesState for KangajiExecutor<OT, S>
where
    S: State,
{
    type State = S;
}

impl<OT, S> UsesObservers for KangajiExecutor<OT, S>
where
    OT: ObserversTuple<S>,
    S: State,
{
    type Observers = OT;
}

impl<OT, S> HasObservers for KangajiExecutor<OT, S>
where
    S: State,
    OT: ObserversTuple<S>,
{
    fn observers(&self) -> &OT {
        &self.observers
    }

    fn observers_mut(&mut self) -> &mut OT {
        &mut self.observers
    }
}
