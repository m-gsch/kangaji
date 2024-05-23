use crate::kvm;
use anyhow::{anyhow, Result};

#[derive(Default, Debug)]
pub struct CpuState {
    pub regs: kvm_bindings::kvm_regs,
    pub sregs: kvm_bindings::kvm_sregs,
    pub fpu: kvm_bindings::kvm_fpu,
    pub msr_entries: [kvm_bindings::kvm_msr_entry; 6],
    _lapic: kvm_bindings::kvm_lapic_state,
    _cpuid: kvm_bindings::kvm_cpuid2,
    _dregs: kvm_bindings::kvm_debugregs,
}

impl CpuState {
    // Modified from Snapchange https://github.com/awslabs/snapchange/blob/main/src/cmdline.rs#L942
    pub fn parse_qemu_regs(&mut self, qemuregs: &str) -> Result<()> {
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
                kvm_bindings::kvm_segment {
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
            kvm_bindings::kvm_msr_entry {
                index: kvm::Msr::Ia32Efer as u32,
                data: msr_efer,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_bindings::kvm_msr_entry {
                index: kvm::Msr::Ia32Star as u32,
                data: msr_star,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_bindings::kvm_msr_entry {
                index: kvm::Msr::Ia32Lstar as u32,
                data: msr_lstar,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_bindings::kvm_msr_entry {
                index: kvm::Msr::Ia32Cstar as u32,
                data: msr_cstar,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_bindings::kvm_msr_entry {
                index: kvm::Msr::Ia32Fmask as u32,
                data: msr_sfmask & !0x100,
                ..kvm_bindings::kvm_msr_entry::default()
            },
            kvm_bindings::kvm_msr_entry {
                index: kvm::Msr::Ia32KernelGsBase as u32,
                data: msr_kernel_gs_base,
                ..kvm_bindings::kvm_msr_entry::default()
            },
        ];

        Ok(())
    }
}
