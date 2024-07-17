use libafl::{
    corpus::{CachedOnDiskCorpus, OnDiskCorpus},
    events::{
        CustomBufEventResult, EventConfig, HasCustomBufHandlers, Launcher,
        LlmpRestartingEventManager,
    },
    feedbacks::CrashFeedback,
    generators::RandPrintablesGenerator,
    monitors::MultiMonitor,
    mutators::{havoc_mutations, StdScheduledMutator},
    observers::ListObserver,
    schedulers::RandScheduler,
    stages::StdMutationalStage,
    state::{HasMaxSize, StdState},
    Fuzzer, StdFuzzer,
};
use libafl_bolts::{
    core_affinity::Cores,
    ownedref::OwnedMutPtr,
    rands,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::tuple_list,
};

mod constants;
mod cpu_state;
mod executor;
mod feedback;
mod kangaji;
mod kvm;
mod mutators;
mod observer;

fn main() {
    env_logger::init();

    let mut run_client =
        |state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _, _>, _core_id| {
            let buf_handler: Box<
                dyn FnMut(&mut _, &str, &[u8]) -> Result<CustomBufEventResult, libafl::Error>,
            > = Box::new(|_state, _s, bytes| {
                for addr_bytes in bytes.chunks_exact(9) {
                    let cov_addr = u64::from_ne_bytes(addr_bytes[..8].try_into().unwrap());
                    log::info!(
                        "Clearing breakpoint at @{cov_addr:#x} byte[{:#x}]",
                        addr_bytes[8]
                    );
                    // [TODO] if we clear the breakpoints before sending the NewTestcase to the other cores it is not included in their corpus :(
                    unsafe {
                        kangaji::Kangaji::write_phys(
                            cov_addr,
                            kangaji::SNAPSHOT_BASE,
                            addr_bytes[8..].try_into().unwrap(),
                        );
                        kangaji::Kangaji::write_phys(
                            cov_addr,
                            kangaji::PHYSMEM_BASE,
                            addr_bytes[8..].try_into().unwrap(),
                        );
                    }
                }
                Ok(CustomBufEventResult::Handled)
            });
            mgr.add_custom_buf_handler(buf_handler);
            let mut kangaji = kangaji::Kangaji::new(
                "examples/01_getpid/fuzzvm.physmem",
                "examples/01_getpid/fuzzvm.qemuregs",
            )
            .unwrap();
            kangaji
                .set_coverage_breakpoints("examples/01_getpid/example1.bin.ghidra.covbps")
                .unwrap();
            kangaji.set_breakpoint(constants::FORCE_SIG_FAULT_ADDR); // detect signal for crash
            kangaji.set_breakpoint(constants::LIBC_GETPID_ADDR); // modify pid
            kangaji.set_breakpoint(constants::STOP_ADDR); // end run
                                                          // patch some stuff
            kangaji.patch_byte(constants::USER_SINGLE_STEP_REPORT_ADDR, 0xc3); // remove in kernel single step SIGTRAP

            // An Observer is an entity that provides an information observed during the execution of the program under test to the fuzzer.
            // https://aflplus.plus/libafl-book/core_concepts/observer.html
            let observer_list = OwnedMutPtr::Owned(Box::new(Vec::<u8>::new()));
            let observer = ListObserver::new("CoverageBreakpointObserver", observer_list);

            // The Feedback is an entity that classifies the outcome of an execution of the program under test as interesting or not.
            // The only difference is that interesting Objectives won't be mutated further, and are counted as Solutions, a successful fuzzing campaign.
            // https://aflplus.plus/libafl-book/core_concepts/feedback.html
            let mut feedback = feedback::CoverageFeedback::new(&observer);
            let mut objective = CrashFeedback::new();

            // An Executor is the entity that defines not only how to execute the target, but all the volatile operations that are related to just a single run of the target.
            // https://aflplus.plus/libafl-book/core_concepts/executor.html
            let mut executor = executor::KangajiExecutor::new(kangaji, tuple_list!(observer));

            // The State contains all the metadata that are evolved while running the fuzzer, Corpus included.
            // https://aflplus.plus/libafl-book/design/architecture.html
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    rands::StdRand::new(),
                    CachedOnDiskCorpus::new("./examples/corpus", 4096).unwrap(),
                    OnDiskCorpus::new("./examples/solutions").unwrap(),
                    &mut feedback,
                    &mut objective,
                )
                .unwrap()
            });

            // The Scheduler is the entity representing the policy to pop testcases from the Corpus.
            // https://aflplus.plus/libafl-book/core_concepts/corpus.html
            let scheduler = RandScheduler::new();

            // We group the entities that are "actions", like the CorpusScheduler and the Feedbacks, in a common place, the Fuzzer.
            // https://aflplus.plus/libafl-book/design/architecture.html
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            // Limit size of inputs for the expand mutations
            state.set_max_size(16);

            // Generator of printable bytearrays of max size 16
            let mut generator = RandPrintablesGenerator::new(16);

            // Generate 8 initial inputs
            state
                .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
                .expect("Failed to generate the initial corpus");

            // The Mutator is an entity that takes one or more Inputs and generates a new instance of Input derived by its inputs.
            // https://aflplus.plus/libafl-book/core_concepts/mutator.html
            let mutator = StdScheduledMutator::new(havoc_mutations());

            // A Stage is an entity that operates on a single Input received from the Corpus.
            // https://aflplus.plus/libafl-book/core_concepts/stage.html
            let mut stages = tuple_list!(StdMutationalStage::new(mutator));

            // fuzz
            fuzzer
                .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                .expect("Error in fuzz loop");

            Ok::<(), libafl::Error>(())
        };

    // // we need to make our monitor
    // // this is just to report stats back to our screen
    // // libafl includes some nicer ways to show this too, like the TuiMonitor
    // let monitor = SimpleMonitor::new(|s| println!("{s}"));
    // // The EventManager interface is used to send Events over the wire using Low Level Message Passing, a custom message passing mechanism over shared memory or TCP.
    // // https://aflplus.plus/libafl-book/message_passing/message_passing.html
    // let mgr = SimpleEventManager::new(monitor);
    // run_client(None, mgr, 0).unwrap();

    // The shared memory allocator
    let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

    // The stats reporter for the broker
    let monitor = MultiMonitor::new(|s| println!("{s}"));

    // Build and run a Launcher
    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .broker_port(1337)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&Cores::from_cmdline("1-4").unwrap())
        .build()
        .launch()
    {
        Ok(()) => (),
        Err(libafl::Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
        Err(err) => panic!("Failed to run launcher: {err:?}"),
    }
}
