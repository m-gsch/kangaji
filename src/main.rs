use std::fs::OpenOptions;
use std::os::fd::AsRawFd as _;
use std::ptr::null_mut;

use anyhow::{anyhow, Result};
use kvm_bindings::{
    kvm_guest_debug, kvm_guest_debug_arch, kvm_msr_entry, kvm_pit_config, kvm_segment,
    kvm_userspace_memory_region, Msrs, KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP,
    KVM_GUESTDBG_USE_SW_BP, KVM_MAX_CPUID_ENTRIES, KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd};

struct GuestVM {
    physmem_base: u64,
    physmem_size: usize,
    cpu_state: CpuState,
    vcpu: VcpuFd,
}
//KVM_(GET|SET)_(REGS|SREGS|FPU|MSR|LAPIC|CPUID2|GUEST_DEBUG)
#[derive(Default, Debug)]
struct CpuState {
    regs: kvm_bindings::kvm_regs,
    sregs: kvm_bindings::kvm_sregs,
    fpu: kvm_bindings::kvm_fpu,
    msr_entries: [kvm_msr_entry; 6],
    lapic: kvm_bindings::kvm_lapic_state,
    cpuid: kvm_bindings::kvm_cpuid2,
    dregs: kvm_bindings::kvm_debugregs,
}

impl CpuState {
    // Modified from Snapchange https://github.com/awslabs/snapchange/blob/main/src/cmdline.rs#L942
    fn parse_qemu_regs(&mut self, qemuregs: &str) -> Result<()> {
        // Parse the input line-by-line
        // Skip all starting lines until we come across the first line containing RAX
        let mut lines = qemuregs
            .split('\n')
            .skip_while(|line| !line.contains("RAX=") && !line.contains("RBX="));

        /// Get the next line of input or return error
        macro_rules! next_line {
            () => {
                lines.next().ok_or(anyhow!("InvalidQemuRegisterInput"))?
            };
        }

        let mut curr_line = next_line!().split(' ');

        /// Get the next element in the current line
        macro_rules! next_elem {
            () => {
                curr_line
                    .next()
                    .ok_or(anyhow!("InvalidQemuRegisterInput"))?
            };
        }

        /// Parse the VM selector line
        macro_rules! next_selector {
            () => {{
                let tmp = next_line!().replace(" =", "_=");
                curr_line = tmp.split(' ');

                // CS =0033 0000000000000000 ffffffff 00a0fb00 DPL=3 CS64 [-RA]
                let selector = u16::from_str_radix(&next_elem!()[4..], 16)?;
                let base = u64::from_str_radix(&next_elem!(), 16)?;
                let limit = u32::from_str_radix(&next_elem!(), 16)?;
                let access_rights = u32::from_str_radix(&next_elem!(), 16)? >> 8;
                let type_ = (access_rights & 0b1111) as u8;
                let present = ((access_rights >> 7) & 1) as u8;
                let dpl = ((access_rights >> 5) & 0b11) as u8;
                let s = ((access_rights >> 4) & 1) as u8;
                /* 11:8 reserved */
                let avl = ((access_rights >> 12) & 1) as u8;
                let l = ((access_rights >> 13) & 1) as u8;
                let db = ((access_rights >> 14) & 1) as u8;
                let g = ((access_rights >> 15) & 1) as u8;
                let unusable = ((access_rights >> 16) & 1) as u8;
                kvm_segment {
                    base,
                    limit,
                    selector,
                    type_,
                    present,
                    dpl,
                    db,
                    s,
                    l,
                    g,
                    avl,
                    unusable,
                    ..Default::default()
                }
            }};
        }

        // At this point, we assume the start of the info registers has been found

        // Example
        // RAX=0000555555555125 RBX=0000000000000000 RCX=00007ffff7fbf718 RDX=00007fffffffeca8
        self.regs.rax = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.rbx = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.rcx = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.rdx = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // RSI=00007fffffffec98 RDI=0000000000000001 RBP=00007fffffffeba0 RSP=00007fffffffeba0
        curr_line = next_line!().split(' ');
        self.regs.rsi = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.rdi = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.rbp = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.rsp = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // R8 =0000000000000000 R9 =00007ffff7fe21b0 R10=0000000000000000 R11=00000000000000c2
        let tmp = next_line!().replace(" =", "_=");
        curr_line = tmp.split(' ');
        self.regs.r8 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.r9 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.r10 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.r11 = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // R12=0000555555555040 R13=0000000000000000 R14=0000000000000000 R15=0000000000000000
        curr_line = next_line!().split(' ');
        self.regs.r12 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.r13 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.r14 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.r15 = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // RIP=0000555555555129 RFL=00000246 [---Z-P-] CPL=3 II=0 A20=1 SMM=0 HLT=0
        curr_line = next_line!().split(' ');
        self.regs.rip = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.regs.rflags = u64::from_str_radix(&next_elem!()[4..], 16)? & !0x100; // Clear Trap Flag

        // ES =0000 0000000000000000 000fffff 00000000
        self.sregs.es = next_selector!();

        // CS =0033 0000000000000000 ffffffff 00a0fb00 DPL=3 CS64 [-RA]
        self.sregs.cs = next_selector!();

        // SS =002b 0000000000000000 ffffffff 00c0f300 DPL=3 DS   [-WA]
        self.sregs.ss = next_selector!();

        // DS =0000 0000000000000000 000fffff 00000000
        self.sregs.ds = next_selector!();

        // FS =0000 00007ffff7fc7540 ffffffff 00c00000
        self.sregs.fs = next_selector!();

        // GS =0000 0000000000000000 000fffff 00000000
        self.sregs.gs = next_selector!();

        // LDT=0000 0000000000000000 000fffff 00000000
        self.sregs.ldt = next_selector!();

        // TR =0040 fffffe000004a000 00004087 00008b00 DPL=0 TSS64-busy
        self.sregs.tr = next_selector!();

        // Set 64-bit TSS busy
        // A VM entry failed one of the checks identified in Section 27.3.1.
        // TR. The different sub-fields are considered separately:
        // Bits 3:0 (Type).
        // — If the guest will not be IA-32e mode, the Type must be 3 (16-bit busy TSS) or 11 (32-bit busy TSS).
        // — If the guest will be IA-32e mode, the Type must be 11 (64-bit busy TSS).
        self.sregs.tr.type_ = 0xb;

        // GDT=     fffffe0000048000 0000007f
        let tmp = next_line!().replace("     ", " ");
        curr_line = tmp.split(' ');
        let _name = next_elem!();
        self.sregs.gdt.base = u64::from_str_radix(next_elem!(), 16)?;
        self.sregs.gdt.limit = u16::from_str_radix(next_elem!(), 16)?;

        // IDT=     fffffe0000000000 00000fff
        let tmp = next_line!().replace("     ", " ");
        curr_line = tmp.split(' ');
        let _name = next_elem!();
        self.sregs.idt.base = u64::from_str_radix(next_elem!(), 16)?;
        self.sregs.idt.limit = u16::from_str_radix(next_elem!(), 16)?;

        // CR0=80050033 CR2=000055be87f4bff0 CR3=0000000024557000 CR4=000006e0
        curr_line = next_line!().split(' ');
        self.sregs.cr0 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.sregs.cr2 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.sregs.cr3 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        self.sregs.cr4 = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // Leave debug regs empty
        // DR0=0000000000000000 DR1=0000000000000000 DR2=0000000000000000 DR3=0000000000000000
        curr_line = next_line!().split(' ');
        let _dr0 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        let _dr1 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        let _dr2 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        let _dr3 = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // DR6=00000000ffff0ff0 DR7=0000000000000400
        curr_line = next_line!().split(' ');
        let _dr6 = u64::from_str_radix(&next_elem!()[4..], 16)?;
        let _dr7 = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // CCS=0000000000000000 CCD=0000000000000000 CCO=EFLAGS
        curr_line = next_line!().split(' ');
        let _ccs = u64::from_str_radix(&next_elem!()[4..], 16)?;
        let _ccd = u64::from_str_radix(&next_elem!()[4..], 16)?;
        // let _cc0 = u64::from_str_radix(&next_elem!()[4..], 16)?;

        // EFER=0000000000000d01
        curr_line = next_line!().split(' ');
        self.sregs.efer = u64::from_str_radix(&next_elem!()[5..], 16)?;

        // FCW=037f FSW=0000 [ST=0] FTW=00 MXCSR=00001f80
        curr_line = next_line!().split(' ');
        self.fpu.fcw = u16::from_str_radix(&next_elem!()[4..], 16)?;
        self.fpu.fsw = u16::from_str_radix(&next_elem!()[4..], 16)?;
        let _flag = next_elem!();
        self.fpu.ftwx = u8::from_str_radix(&next_elem!()[4..], 16)?;
        self.fpu.mxcsr = u32::from_str_radix(&next_elem!()[6..], 16)?;

        for fpr_chunk in self.fpu.fpr.chunks_exact_mut(2) {
            // FPR0=0000000000000000 0000 FPR1=0000000000000000 0000
            curr_line = next_line!().split(' ');
            let fpr0_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
            let fpr0_upper = u128::from_str_radix(next_elem!(), 16)?;
            let fpr0 = fpr0_upper << 64 | fpr0_lower;
            let fpr1_lower = u128::from_str_radix(&next_elem!()[5..], 16)?;
            let fpr1_upper = u128::from_str_radix(next_elem!(), 16)?;
            let fpr1 = fpr1_upper << 64 | fpr1_lower;
            fpr_chunk[0] = fpr0.to_le_bytes();
            fpr_chunk[1] = fpr1.to_le_bytes();
        }

        // Preallocate the string used to parse the XMM registers
        let mut xmm_str = String::new();

        /// Parse the XMM register line from the QEMU register file
        // XMM00=0000000000000000 0000ff00000000ff XMM01=2f2f2f2f2f2f2f2f 2f2f2f2f2f2f2f2f
        macro_rules! parse_xmm {
            () => {{
                xmm_str.clear();
                let xmm_hi = &next_elem!()[6..];
                let xmm_lo = next_elem!();
                xmm_str.push_str(xmm_hi);
                xmm_str.push_str(xmm_lo);
                u128::from_str_radix(&xmm_str, 16)?
            }};
        }

        for xmm_chunk in self.fpu.xmm.chunks_exact_mut(2) {
            curr_line = next_line!().split(' ');
            let xmm0 = parse_xmm!();
            let xmm1 = parse_xmm!();
            xmm_chunk[0] = xmm0.to_le_bytes();
            xmm_chunk[1] = xmm1.to_le_bytes();
        }

        // Code=f8 02 00 00 00 c7 45 f4 03 00 00 00 c7 45 f0 0f 27 00 00 cc <0f> 01 c1 8b
        // Ignore the code bytes for now
        let _ = next_line!().split(' ');

        // APIC_BASE=fee00d00
        let tmp = next_line!();
        assert!(
            tmp.contains("APIC_BASE"),
            "Expected APIC_BASE. Found: {tmp}",
        );
        // self.sregs.apic_base = u64::from_str_radix(&tmp[0xa..], 16)?;

        // EFER=d01
        let tmp = next_line!();
        assert!(tmp.contains("EFER"), "Expected EFER. Found: {tmp}");
        let msr_efer = u64::from_str_radix(&tmp[0x5..], 16)?;

        // STAR=23001000000000
        let tmp = next_line!();
        assert!(tmp.contains("STAR"), "Expected STAR. Found: {tmp}");
        let msr_star = u64::from_str_radix(&tmp[0x5..], 16)?;

        // LSTAR=ffffffff83e00000
        let tmp = next_line!();
        assert!(tmp.contains("LSTAR"), "Expected LSTAR. Found: {tmp}");
        let msr_lstar = u64::from_str_radix(&tmp[0x6..], 16)?;

        // CSTAR=ffffffff83e01680
        let tmp = next_line!();
        assert!(tmp.contains("CSTAR"), "Expected CSTAR. Found: {tmp}");
        let msr_cstar = u64::from_str_radix(&tmp[0x6..], 16)?;

        // SFMASK=257fd5
        let tmp = next_line!();
        assert!(tmp.contains("SFMASK"), "Expected SFMASK. Found: {tmp}");
        let msr_sfmask = u64::from_str_radix(&tmp[0x7..], 16)?;

        // KERNELGSBASE=0
        let tmp = next_line!();
        assert!(
            tmp.contains("KERNELGSBASE"),
            "Expected KERNELGSBASE. Found: {tmp}",
        );
        let msr_kernel_gs_base = u64::from_str_radix(&tmp[0xd..], 16)?;

        self.msr_entries = [
            kvm_msr_entry {
                index: Msr::Ia32Efer as u32,
                data: msr_efer,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Star as u32,
                data: msr_star,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Lstar as u32,
                data: msr_lstar,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Cstar as u32,
                data: msr_cstar,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32Fmask as u32,
                data: msr_sfmask & !0x100,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_msr_entry {
                index: Msr::Ia32KernelGsBase as u32,
                data: msr_kernel_gs_base,
                ..kvm_bindings::kvm_msr_entry::default()
            },
        ];

        Ok(())
    }
}

impl GuestVM {
    fn new(physmem_path: &str, qemuregs_filepath: &str) -> Result<Self> {
        let mut cpu_state = CpuState::default();
        let qemuregs = std::fs::read_to_string(qemuregs_filepath)?;
        cpu_state.parse_qemu_regs(&qemuregs)?;

        let physmem_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(physmem_path)?;
        let physmem_size: usize = physmem_file.metadata()?.len() as usize;

        // 1. Instantiate KVM.
        let kvm = Kvm::new().unwrap();

        // 2. Create a VM.
        let vm = kvm.create_vm().unwrap();

        vm.create_irq_chip()?;
        let pit_config = kvm_pit_config::default();
        vm.create_pit2(pit_config)?;

        // 3. Create one vCPU.
        let vcpu_fd = vm.create_vcpu(0)?;

        // Create the local APIC
        let apic = vcpu_fd.get_lapic()?;

        // Set the APIC for the guest VM
        vcpu_fd.set_lapic(&apic)?;

        let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        vcpu_fd.set_cpuid2(&cpuid)?;

        // Set xcr0 to 7 to enable avx, sse, and x87
        let mut xcrs = vcpu_fd.get_xcrs()?;
        xcrs.xcrs[0].xcr = 0x0;
        xcrs.xcrs[0].value = 0x7;
        vcpu_fd.set_xcrs(&xcrs)?;

        // Setup debug mode for the guest
        let debug_struct = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_SINGLESTEP,
            pad: 0,
            arch: kvm_guest_debug_arch {
                debugreg: [0x000055555555537f, 0, 0, 0, 0, 0, 0, 0x400],
            },
        };

        // Enable guest mode in the guest
        vcpu_fd.set_guest_debug(&debug_struct)?;

        // 3. Initialize Guest Memory.
        let physmem_base = unsafe {
            libc::mmap(
                null_mut(),
                physmem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                physmem_file.as_raw_fd(),
                0,
            ) as u64
        };

        // Allocate memory from [0, APIC_BASE] in the guest
        let mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: 0xfee0_0000, // APIC_BASE
            userspace_addr: physmem_base,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        unsafe { vm.set_user_memory_region(mem_region)? };

        // When initializing the guest memory slot specify the
        // `KVM_MEM_LOG_DIRTY_PAGES` to enable the dirty log.
        let mem_region = kvm_userspace_memory_region {
            slot: 1,
            guest_phys_addr: 0xfee0_0000 + 0x1000,
            memory_size: physmem_size as u64 - 0xfee0_0000 - 0x1000,
            userspace_addr: physmem_base + 0xfee0_0000 + 0x1000,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        unsafe { vm.set_user_memory_region(mem_region)? };

        // 4. Initialize general purpose and special registers.
        // x86_64 specific registry setup.
        vcpu_fd.set_regs(&cpu_state.regs)?;
        vcpu_fd.set_sregs(&cpu_state.sregs)?;
        vcpu_fd.set_fpu(&cpu_state.fpu)?;

        let msrs = Msrs::from_entries(&cpu_state.msr_entries)?;
        vcpu_fd.set_msrs(&msrs)?;

        Ok(Self {
            physmem_base,
            physmem_size,
            cpu_state,
            vcpu: vcpu_fd,
        })
    }
    fn translate_addr(&self, virt_addr: u64) -> u64 {
        // Get Page Map Level 4 (PML4) table address from CR3
        // 2:0 Ignored
        // 3 (PWT)
        // 4 (PCD)
        // 11:5 Ignored
        // M–1:12 Physical address of the 4-KByte aligned PML4 table used for linear-address translation
        // 63:M Reserved (must be 0) [M is an abbreviation for MAXPHYADDR, which is at most 52]

        let pml4_addr = self.cpu_state.sregs.cr3 & 0x000f_ffff_ffff_f000;

        // Get PML4 entry (PML4E) from linear address
        // 2:0 are all 0
        // 11:3 are bits 47:39 of the linear address
        // 51:12 are from CR3

        let pml4_index = (virt_addr >> 39) & 0x1ff;
        let pml4e_addr = pml4_addr + (pml4_index << 3);
        let pml4_entry = self.read_phys::<u64>(pml4e_addr);
        println!("{pml4_entry:#x}");

        // Get Page-Directory-Pointer Table (PDPT) address from PML4E
        // 0 (P) Present; must be 1 to reference a page-directory-pointer table
        // 1 (R/W) Read/write; if 0, writes may not be allowed to the 512-GByte region controlled by this entry
        // 2 (U/S) User/supervisor; if 0, user-mode accesses are not allowed to the 512-GByte region controlled by this entry
        // 3 (PWT) Page-level write-through; indirectly determines the memory type used to access the page-directory-pointer table referenced by this entry
        // 4 (PCD) Page-level cache disable; indirectly determines the memory type used to access the page-directory-pointer table referenced by this entry
        // 5 (A) Accessed; indicates whether this entry has been used for linear-address translation
        // 6 Ignored
        // 7 (PS) Reserved (must be 0)
        // 10:8 Ignored
        // 11 (R) For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging)
        // M–1:12 Physical address of 4-KByte aligned page-directory-pointer table referenced by this entry
        // 51:M Reserved (must be 0)
        // 62:52 Ignored
        // 63 (XD) If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 512-GByte region controlled by this entry); otherwise, reserved (must be 0)
        let pdpt_addr = pml4_entry & 0x000f_ffff_ffff_f000;

        // Get PDPT entry (PDPTE) from linear address
        // 2:0 are all 0
        // 11:3 are bits 38:30 of the linear address
        // 51:12 are from the PML4E
        let pdpt_index = (virt_addr >> 30) & 0x1ff;
        let pdpte_addr = pdpt_addr + (pdpt_index << 3);
        let pdpt_entry = self.read_phys::<u64>(pdpte_addr);
        println!("{pdpt_entry:#x}");

        // Get Page Directory (PD) address from PDPTE
        // 0 (P) Present; must be 1 to reference a page directory
        // 1 (R/W) Read/write; if 0, writes may not be allowed to the 1-GByte region controlled by this entry
        // 2 (U/S) User/supervisor; if 0, user-mode accesses are not allowed to the 1-GByte region controlled by this entry
        // 3 (PWT) Page-level write-through; indirectly determines the memory type used to access the page directory referenced by this entry
        // 4 (PCD) Page-level cache disable; indirectly determines the memory type used to access the page directory referenced by this entry
        // 5 (A) Accessed; indicates whether this entry has been used for linear-address translation
        // 6 Ignored
        // 7 (PS) Page size; must be 0 (otherwise, this entry maps a 1-GByte page)
        // 10:8 Ignored
        // 11 (R) For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging)
        // (M–1):12 Physical address of 4-KByte aligned page directory referenced by this entry
        // 51:M Reserved (must be 0)
        // 62:52 Ignored
        // 63 (XD) If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 1-GByte region controlled by this entry); otherwise, reserved (must be 0)
        let pd_addr = pdpt_entry & 0x000f_ffff_ffff_f000;

        // Get PD entry (PDE) from linear address
        // 2:0 are all 0
        // 11:3 are bits 29:21 of the linear address
        // 51:12 are from the PDPTE
        let pd_index = (virt_addr >> 21) & 0x1ff;
        let pde_addr = pd_addr + (pd_index << 3);
        let pd_entry = self.read_phys::<u64>(pde_addr);
        println!("{pd_entry:#x}");

        // Get Page Table (PT) address from PDE
        // 0 (P) Present; must be 1 to reference a page table
        // 1 (R/W) Read/write; if 0, writes may not be allowed to the 2-MByte region controlled by this entry
        // 2 (U/S) User/supervisor; if 0, user-mode accesses are not allowed to the 2-MByte region controlled by this entry (see Section
        // 3 (PWT) Page-level write-through; indirectly determines the memory type used to access the page table referenced by this entry
        // 4 (PCD) Page-level cache disable; indirectly determines the memory type used to access the page table referenced by this entry
        // 5 (A) Accessed; indicates whether this entry has been used for linear-address translation
        // 6 Ignored
        // 7 (PS) Page size; must be 0 (otherwise, this entry maps a 2-MByte page)
        // 10:8 Ignored
        // 11 (R) For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging)
        // (M–1):12 Physical address of 4-KByte aligned page table referenced by this entry
        // 51:M Reserved (must be 0)
        // 62:52 Ignored
        // 63 (XD) If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 2-MByte region controlled by this entry); otherwise, reserved (must be 0)
        let pt_addr = pd_entry & 0x000f_ffff_ffff_f000;

        // Get PT entry (PTE) from linear address
        // 2:0 are all 0
        // 11:3 are bits 20:12 of the linear address
        // 51:12 are from the PDE
        let pt_index = (virt_addr >> 12) & 0x1ff;
        let pte_addr = pt_addr + (pt_index << 3);
        let pt_entry = self.read_phys::<u64>(pte_addr);
        println!("{pt_entry:#x}");

        // Get 4-KByte Page from PTE
        // 0 (P) Present; must be 1 to map a 4-KByte page
        // 1 (R/W) Read/write; if 0, writes may not be allowed to the 4-KByte page referenced by this entry
        // 2 (U/S) User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page referenced by this entry
        // 3 (PWT) Page-level write-through; indirectly determines the memory type used to access the 4-KByte page referenced bythis entry
        // 4 (PCD) Page-level cache disable; indirectly determines the memory type used to access the 4-KByte page referenced by thisentry
        // 5 (A) Accessed; indicates whether software has accessed the 4-KByte page referenced by this entry
        // 6 (D) Dirty; indicates whether software has written to the 4-KByte page referenced by this entry
        // 7 (PAT) Indirectly determines the memory type used to access the 4-KByte page referenced by this entry
        // 8 (G) Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise
        // 10:9 Ignored
        // 11 (R) For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinarypaging)
        // (M–1):12 Physical address of the 4-KByte page referenced by this entry
        // 51:M Reserved (must be 0)
        // 58:52 Ignored
        // 62:59 Protection key; if CR4.PKE = 1 or CR4.PKS = 1, this may control the page’s access rights;otherwise, it is ignored and not used to control access rights.
        // 63 (XD) If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 4-KByte page controlled bythis entry); otherwise, reserved (must be 0)
        let page_addr = pt_entry & 0x000f_ffff_ffff_f000;

        // Get physical address from 4-KByte Page
        // 11:0 are from the original linear address
        // 51:12 are from the PTE
        let page_offset = virt_addr & 0xFFF;
        page_addr + page_offset
    }
    fn read_phys<T: Copy>(&self, phys_addr: u64) -> T {
        assert!((phys_addr as usize + std::mem::size_of::<T>()) < self.physmem_size);
        unsafe { std::ptr::read_unaligned((self.physmem_base + phys_addr) as *const T) }
    }
    fn read_virt<T: Copy>(&self, virt_addr: u64) -> T {
        let phys_addr = self.translate_addr(virt_addr);
        println!("Phys addr: {phys_addr:#x}");
        self.read_phys::<T>(phys_addr)
    }
    fn write_phys<T>(&self, phys_addr: u64, value: T) {
        assert!((phys_addr as usize + std::mem::size_of::<T>()) < self.physmem_size);
        unsafe {
            std::ptr::write_unaligned((self.physmem_base + phys_addr) as *mut T, value);
        }
    }
    fn write_virt<T>(&self, virt_addr: u64, value: T) {
        let phys_addr = self.translate_addr(virt_addr);
        println!("Phys addr: {phys_addr:#x}");
        self.write_phys(phys_addr, value);
    }

    fn run(&mut self) {
        // Run code on the vCPU.
        loop {
            match self.vcpu.run().expect("run failed") {
                VcpuExit::IoIn(addr, data) => {
                    println!("VcpuExit::IoIn addr:{addr:#x} data:{data:#x?}.");
                    let regs = self.vcpu.get_regs().unwrap();
                    println!("{regs:#x?}");
                }
                VcpuExit::IoOut(addr, data) => {
                    println!("VcpuExit::IoOut addr:{addr:#x} data:{data:#x?}.");
                    let regs = self.vcpu.get_regs().unwrap();
                    println!("{regs:#x?}");
                }
                VcpuExit::MmioRead(addr, data) => {
                    println!("VcpuExit::MmioRead addr:{addr:#x} data:{data:#x?}.");
                    let regs = self.vcpu.get_regs().unwrap();
                    println!("{regs:#x?}");
                }
                VcpuExit::MmioWrite(addr, data) => {
                    println!("VcpuExit::MmioWrite addr:{addr:#x} data:{data:#x?}.");
                    let regs = self.vcpu.get_regs().unwrap();
                    println!("{regs:#x?}");
                }
                VcpuExit::Hlt => {
                    println!("VcpuExit::Hlt");
                    let regs = self.vcpu.get_regs().unwrap();
                    println!("{regs:#x?}");
                }
                VcpuExit::Debug(debug_exit) => {
                    println!("VcpuExit::Debug");
                    let mut regs = self.vcpu.get_regs().unwrap();
                    let mut sregs = self.vcpu.get_sregs().unwrap();
                    let rip = regs.rip;
                    let cr3 = sregs.cr3;
                    println!("{rip:#x?} {cr3:#x}");
                    if regs.rip == 0x00007ffff7fbef1a {
                        let rsp = regs.rsp;
                        let ret_addr = self.read_virt::<u64>(rsp);
                        println!("RSP: {rsp:#x} -> {ret_addr:#x}");
                        regs.rip = ret_addr;
                        regs.rax = 0xdeadbeef;
                        self.vcpu.set_regs(&regs).unwrap();
                    }
                    if regs.rip == 0x000055555555537f {
                        break;
                    }
                    if regs.rip == 0xffffffff81099cb0 {
                        let signal = i32::try_from(regs.rdi).unwrap();
                        if signal == libc::SIGTRAP {
                            // Immediate return
                            println!("{regs:#x?}");
                            regs.rip = 0xffffffff81e89ae1;
                            regs.rsp += 8;
                            self.vcpu.set_regs(&regs).unwrap();
                        } else {
                            println!("Fault with different signal: {signal}");
                        }
                    }
                    // regs.rflags &=  !0x100;
                    // self.vcpu.set_regs(&regs).unwrap();
                }
                r => panic!("Unexpected exit reason: VcpuExit::{:x?}", r),
            }
        }
    }
}

fn main() -> Result<()> {
    let mut vm = GuestVM::new("fuzzvm.physmem", "fuzzvm.qemuregs")?;

    let input_data: [u8; 17] = [
        0x66, 0x75, 0x7a, 0x7a, 0x6d, 0x65, 0x74, 0x6f, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x6d, 0x65,
        0x21, 0x00, // "fuzzmetosolveme!/0"
    ];
    let asm_code: [u8; 5] = [
        0x90, 0x90, 0x90, 0x90, 0x90, // nop
    ];

    vm.write_virt(0x555555556000, input_data);
    // vm.write_virt(0x5555555551e1, asm_code);
    vm.write_virt(0xffffffff81099cb0, 0xcc as u8); // breakpoint in force_sig_fault
    vm.write_virt(0x00007ffff7fbef1a, 0xcc as u8); // breakpoint in getpid
    vm.write_virt(0x000055555555537f, 0xcc as u8); // end run
    // let bytes = vm.read_virt::<[u8;32]>(0x5555555551e1);
    // println!("{bytes:x?}");
    vm.run();
    // let phys_addr = vm.translate_addr(0x55555570de8f);
    // println!("{phys_addr:#x}");

    Ok(())
}

/// Model specific registers found available from KVM
#[repr(u32)]
pub enum Msr {
    /// Extended feature Enables
    Ia32Efer = 0xc000_0080,

    /// System Call Target Address (R/W)
    Ia32Star = 0xc000_0081,

    /// IA-32e Mode System Call Target Address (R/W)
    ///
    /// Target RIP for the called procedure when SYSCALL is executed in 64-bit mode.
    Ia32Lstar = 0xc000_0082,

    /// IA-32e Mode System Call Target Address (R/W)
    ///
    /// Not used, as the SYSCALL instruction is not recognized in compatibility mode.
    Ia32Cstar = 0xc000_0083,

    /// System Call Flag Mask (R/W)
    Ia32Fmask = 0xc000_0084,

    /// Swap Target of BASE Address of GS (R/W)
    Ia32KernelGsBase = 0xc000_0102,
}
