use std::path::PathBuf;

use anyhow::{Ok, Result};
use libafl::{corpus::{InMemoryCorpus, OnDiskCorpus}, events::SimpleEventManager, feedbacks::{ConstFeedback, CrashFeedback}, inputs::BytesInput, monitors::SimpleMonitor, mutators::{havoc_mutations, StdScheduledMutator}, observers::{Observer, TimeObserver}, schedulers::RandScheduler, stages::StdMutationalStage, state::StdState, Fuzzer, StdFuzzer};
use libafl_bolts::{rands::{self, RandomSeed}, tuples::tuple_list};

mod constants;
mod cpu_state;
mod kvm;
mod kangaji;
mod executor;

fn main() -> Result<()> {
    env_logger::init();
    let mut vm = kangaji::Kangaji::new(
        "examples/01_getpid/fuzzvm.physmem",
        "examples/01_getpid/fuzzvm.qemuregs",
    )?;

    // let mut input_data: [u8; 17] = [
    //     0x66, 0x75, 0x7a, 0x7a, 0x6d, 0x65, 0x74, 0x6f, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x6d,
    //     0x65, 0x61, 0x00, // "fuzzmetosolvemea\0"
    // ];

    let mut input_data: [u8; 17] = [
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x00, // "aaaaaaaaaaaaaaaa\0"
    ];

    let mut curr_input = input_data;

    // we don't have any instrumentation in here to tell us when we find a new path
    // so we just have no feedback
    let mut feedback = ConstFeedback::False;

    // Our "objective" is a feedback that tells our fuzzer when we have a win!
    // we could include timeouts, certain outputs, created files, etc
    // here we will just win when our target crashes
    let mut objective = CrashFeedback::new();

    // we need to make our monitor
    // this is just to report stats back to our screen
    // libafl includes some nicer ways to show this too, like the TuiMonitor
    let monitor = SimpleMonitor::new( |s| println!("{s}") );

    // the event manager takes in events/stats during the fuzzer
    // here we could programatically respond to those events
    // but we will just use a manager that sends the events on to the monitor
    let mut mgr = SimpleEventManager::new(monitor);


    let observer = tuple_list!(TimeObserver::new("time"));
    // we need to make our executor
    // this defines how we execute each test case
    // this could be using qemu, frida, or using a forkserver compiled in
    // we will just use the most simple "CommandExecutor" which runs a child process
    // by default it will use stdin to send over the input, unless we specify otherwise
    let mut kangaji = executor::KangajiExecutor::new(vm,observer);

    kangaji.vm.set_coverage_breakpoints("examples/01_getpid/example1.bin.ghidra.covbps")?;
    kangaji.vm.set_breakpoint(constants::FORCE_SIG_FAULT_ADDR); // detect signal for crash
    kangaji.vm.set_breakpoint(constants::LIBC_GETPID_ADDR); // modify pid
    kangaji.vm.set_breakpoint(constants::STOP_ADDR); // end run

    // we need a state to hold our fuzzing state
    // a state tracks our corpora (inputs and solutions)
    // and other metadata
    let mut state = StdState::new(
        rands::StdRand::new(),
        InMemoryCorpus::<BytesInput>::new(),
        OnDiskCorpus::new(PathBuf::from("./solutions")).unwrap(),
        &mut feedback,
        &mut objective,
    ).unwrap();


    // We need to make our stages
    // these will be executed in order for each new executed testcase
    // All we need are normal byte mutations for now
    // But here we could also have tracing stages,
    // calibration, generation, sync stages, etc
    // see implementations of the Stage trait in LibAFL
    let mutator = StdScheduledMutator::with_max_stack_pow(
        havoc_mutations(),
        9,                                                      // maximum mutation iterations
    );

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // we need a scheduler for our fuzzer to choose how to schedule inputs in our corpus
    let scheduler = RandScheduler::new();
    // now we can build our fuzzer
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);


    // load the initial corpus in our state
    // since we lack feedback, we have to force this,
    // otherwise it will only load inputs it deems interesting
    // which will result in an empty corpus for us
    state.load_initial_inputs_forced(&mut fuzzer, &mut kangaji, &mut mgr, &[PathBuf::from("./examples/01_getpid/corpus")]).unwrap();

    // fuzz
    fuzzer.fuzz_loop(&mut stages, &mut kangaji, &mut state, &mut mgr).expect("Error in fuzz loop");
    // loop {
    //     vm.restore()?;
    //     // patch some stuff
    //     vm.write_virt(constants::USER_SINGLE_STEP_REPORT_ADDR, 0xc3 as u8); // remove in kernel single step SIGTRAP

    //     curr_input = if vm.new_coverage() {
    //         input_data = curr_input;
    //         input_data
    //     } else {
    //         input_data
    //     };

    //     // replace a random byte in the input with a new byte
    //     let offset = rng.below(curr_input.len() as u64) as usize;
    //     let rand_byte = rng.next_u32() as u8;
    //     curr_input[offset] = rand_byte;
    //     log::trace!("Setting byte {rand_byte:#x} at curr_input[{offset}]");
    //     // set input data
    //     vm.write_virt(0x555555556000, curr_input);
    //     loop {
    //         match vm.run()? {
    //             VcpuExit::Debug(_) => {
    //                 if vm.vcpu.sync_regs().regs.rip == constants::LIBC_GETPID_ADDR {
    //                     // Hit breakpoint in getpid()
    //                     // Set rax=0xdeadbeef & return
    //                     let rsp = vm.vcpu.sync_regs().regs.rsp;
    //                     let ret_addr = vm.read_virt::<u64>(rsp);
    //                     log::debug!("RSP: {rsp:#x} -> {ret_addr:#x}");
    //                     let mut regs = vm.vcpu.get_regs().unwrap();
    //                     regs.rip = ret_addr;
    //                     regs.rsp += 8;
    //                     regs.rax = 0xdeadbeef;
    //                     vm.vcpu.set_regs(&regs).unwrap();
    //                 }
    //                 if vm.vcpu.sync_regs().regs.rip == constants::STOP_ADDR {
    //                     log::debug!("End of run! @{:#x}", vm.vcpu.sync_regs().regs.rip);
    //                     break;
    //                 }

    //                 if vm.vcpu.sync_regs().regs.rip == constants::FORCE_SIG_FAULT_ADDR {
    //                     let signal = i32::try_from(vm.vcpu.sync_regs().regs.rdi).unwrap();
    //                     if signal == libc::SIGSEGV {
    //                         log::info!(
    //                             "We found a crash! code:{} address:{:#x}",
    //                             vm.vcpu.sync_regs().regs.rsi,
    //                             vm.vcpu.sync_regs().regs.rdx
    //                         );
    //                         return Ok(());
    //                     } else {
    //                         log::warn!("Fault with unexpected signal: {signal}");
    //                     }
    //                 }
    //             }
    //             r => {
    //                 log::error!("Unexpected exit reason: VcpuExit::{r:x?}");
    //                 break;
    //             }
    //         }
    //     }
    // }
    Ok(())
}
