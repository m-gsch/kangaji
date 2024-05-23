pub const APIC_BASE: u64 = 0xfee0_0000;
pub const FORCE_SIG_FAULT_ADDR: u64 = 0xffffffff81099cb0;
pub const USER_SINGLE_STEP_REPORT_ADDR: u64 = 0xffffffff81041e30;
pub const LIBC_GETPID_ADDR: u64 = 0x00007ffff7fbef1a;
pub const STOP_ADDR: u64 = 0x00007ffff7fc19b3; // ld-musl-x86_64.so.1!__libc_exit_fini;
pub const PAGE_SIZE: u64 = 0x1000;
