use std::{fs, os::fd::AsRawFd};

use anyhow::{anyhow, Result, Context};
use kvm_bindings::{
    kvm_guest_debug, kvm_pit_config, kvm_userspace_memory_region, Msrs,
    KVM_GUESTDBG_ENABLE, KVM_GUESTDBG_SINGLESTEP, KVM_GUESTDBG_USE_SW_BP, KVM_MAX_CPUID_ENTRIES,
    KVM_MEM_LOG_DIRTY_PAGES,
};
use kvm_ioctls::{Kvm, SyncReg, VcpuExit, VcpuFd, VmFd};

use crate::constants;
use crate::cpu_state::CpuState;
use crate::kvm::MemoryRegion;

pub struct GuestVM {
    physmem_base: u64,
    physmem_size: usize,
    snapshot_base: u64,
    cpu_state: CpuState,
    pub vcpu: VcpuFd,
    pub vm: VmFd,
    pub memory_regions: [MemoryRegion; 2],
}

impl GuestVM {
    pub fn new(physmem_path: &str, qemuregs_filepath: &str) -> Result<Self> {
        let mut cpu_state = CpuState::default();
        let qemuregs = fs::read_to_string(qemuregs_filepath)?;
        cpu_state.parse_qemu_regs(&qemuregs)?;

        let physmem_file = fs::OpenOptions::new()
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

        /// Argument to enable the `DirtyLogProtect2` capability
        const KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE: u64 = 1;

        /// Capability number for `DirtyLogProtect2`
        const KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2: u32 = 168;

        // Create the capability to enable in the VM
        let cap = kvm_bindings::kvm_enable_cap {
            cap: KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
            args: [KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE, 0, 0, 0],
            ..kvm_bindings::kvm_enable_cap::default()
        };

        // Enable the capability
        vm.enable_cap(&cap)?;

        // 3. Create one vCPU.
        let mut vcpu = vm.create_vcpu(0)?;
        vcpu.set_sync_valid_reg(SyncReg::Register);
        vcpu.set_sync_valid_reg(SyncReg::SystemRegister);

        // Create the local APIC
        let apic = vcpu.get_lapic()?;

        // Set the APIC for the guest VM
        vcpu.set_lapic(&apic)?;

        let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        vcpu.set_cpuid2(&cpuid)?;

        // Set xcr0 to 7 to enable avx, sse, and x87
        let mut xcrs = vcpu.get_xcrs()?;
        xcrs.xcrs[0].xcr = 0x0;
        xcrs.xcrs[0].value = 0x7;
        vcpu.set_xcrs(&xcrs)?;

        // Setup debug mode for the guest
        let debug_struct = kvm_guest_debug {
            control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP,
            ..Default::default()
        };

        // Enable guest mode in the guest
        vcpu.set_guest_debug(&debug_struct)?;

        // 3. Initialize Guest Memory.
        let physmem_base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                physmem_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                physmem_file.as_raw_fd(),
                0,
            ) as u64
        };

        // Snapshot for restoring memory
        let snapshot_base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                physmem_size,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                physmem_file.as_raw_fd(),
                0,
            ) as u64
        };

        // Set memory regions in the guest
        // if setting LAPIC, KVM internally creates a memory region for APIC at APIC_BASE of page size
        // so we need to leave a "hole" there or else we get a EEXIST since memory regions overlap
        // 0x00000000   |----------------|
        //              |    Memory      |
        //              |    Region      |
        // APIC_BASE    |----------------|
        //              |     Internal   |
        // APIC_BASE +  | Memory Region  |
        // 0x1000       |----------------|
        //              |    Memory      |
        //              |    Region      |
        // PHYSMEM_SIZE |----------------|
        

        // For ease of access we are saving the bitmap in a u64 vector.
            // We are using ceil to make sure we count all dirty pages even
            // when `memory_size` is not a multiple of `page_size * 64`.
            let div_ceil = |dividend, divisor| (dividend + divisor - 1) / divisor;

            let bitmap_size = div_ceil(constants::APIC_BASE, constants::PAGE_SIZE * 64);

        let slot0_mem_region = MemoryRegion {
            dirty_bitmap: vec![0; bitmap_size as usize],
            base: 0,
            size: u32::try_from(constants::APIC_BASE)?,
        };
        let user_mem_region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: 0,
            memory_size: constants::APIC_BASE, // APIC_BASE
            userspace_addr: physmem_base,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        unsafe { vm.set_user_memory_region(user_mem_region)? };

        let bitmap_size = div_ceil(physmem_size as u64 - constants::APIC_BASE - 0x1000, constants::PAGE_SIZE * 64);
        let slot1_mem_region = MemoryRegion {
            dirty_bitmap: vec![0; bitmap_size as usize],
            base: constants::APIC_BASE + 0x1000,
            size: u32::try_from(physmem_size - constants::APIC_BASE as usize - 0x1000)?,
        };
        let user_mem_region = kvm_userspace_memory_region {
            slot: 1,
            guest_phys_addr: slot1_mem_region.base as u64,
            memory_size: slot1_mem_region.size as u64,
            userspace_addr: physmem_base + constants::APIC_BASE + 0x1000,
            flags: KVM_MEM_LOG_DIRTY_PAGES,
        };

        unsafe { vm.set_user_memory_region(user_mem_region)? };

        // 4. Initialize general purpose and special registers.
        // x86_64 specific registry setup.
        vcpu.set_regs(&cpu_state.regs)?;
        vcpu.set_sregs(&cpu_state.sregs)?;
        vcpu.set_fpu(&cpu_state.fpu)?;

        let msrs = Msrs::from_entries(&cpu_state.msr_entries)?;
        vcpu.set_msrs(&msrs)?;

        Ok(Self {
            physmem_base,
            physmem_size,
            snapshot_base,
            cpu_state,
            vcpu,
            vm,
            memory_regions: [slot0_mem_region, slot1_mem_region],
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
        log::trace!("PML4E {pml4_entry:#x}");

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
        assert!(pml4_entry & 1 == 1, "PML4E not present!");
        let pdpt_addr = pml4_entry & 0x000f_ffff_ffff_f000;

        // Get PDPT entry (PDPTE) from linear address
        // 2:0 are all 0
        // 11:3 are bits 38:30 of the linear address
        // 51:12 are from the PML4E
        let pdpt_index = (virt_addr >> 30) & 0x1ff;
        let pdpte_addr = pdpt_addr + (pdpt_index << 3);
        let pdpt_entry = self.read_phys::<u64>(pdpte_addr);
        log::trace!("PDPTE {pdpt_entry:#x}");

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
        assert!(pdpt_entry & 1 == 1, "PDPTE not present!");
        assert!(pdpt_entry >> 7 & 1 == 0, "PDPTE maps a 1-GByte page!");
        let pd_addr = pdpt_entry & 0x000f_ffff_ffff_f000;

        // Get PD entry (PDE) from linear address
        // 2:0 are all 0
        // 11:3 are bits 29:21 of the linear address
        // 51:12 are from the PDPTE
        let pd_index = (virt_addr >> 21) & 0x1ff;
        let pde_addr = pd_addr + (pd_index << 3);
        let pd_entry = self.read_phys::<u64>(pde_addr);
        log::trace!("PDE {pd_entry:#x}");

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
        assert!(pd_entry & 1 == 1, "PDE not present!");

        if pd_entry >> 7 & 1 == 1 {
            // PDE maps a 2-MByte page!
            log::trace!("PDE maps a 2-MByte page");
            // Get 2-MByte Page from PDE
            // 0 (P) Present; must be 1 to map a 2-MByte page
            // 1 (R/W) Read/write; if 0, writes may not be allowed to the 2-MByte page referenced by this entry
            // 2 (U/S) User/supervisor; if 0, user-mode accesses are not allowed to the 2-MByte page referenced by this entry
            // 3 (PWT) Page-level write-through; indirectly determines the memory type used to access the 2-MByte page referenced by this entry
            // 4 (PCD) Page-level cache disable; indirectly determines the memory type used to access the 2-MByte page referenced by this entry
            // 5 (A) Accessed; indicates whether software has accessed the 2-MByte page referenced by this entry
            // 6 (D) Dirty; indicates whether software has written to the 2-MByte page referenced by this entry
            // 7 (PS) Page size; must be 1 (otherwise, this entry references a page table)
            // 8 (G) Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise
            // 10:9 Ignored
            // 11 (R) For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with ordinary paging)
            // 12 (PAT) Indirectly determines the memory type used to access the 2-MByte page referenced by this entry
            // 20:13 Reserved (must be 0)
            // (M–1):21 Physical address of the 2-MByte page referenced by this entry
            // 51:M Reserved (must be 0)
            // 58:52 Ignored
            // 62:59 Protection key; if CR4.PKE = 1 or CR4.PKS = 1, this may control the page’s access rights; otherwise, it is ignored and not used to control access rights.
            // 63 (XD) If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 2-MByte page controlled by this entry); otherwise, reserved (must be 0)
            let page_addr = pd_entry & 0x000f_ffff_fffe_0000;
            let page_offset = virt_addr & 0x1f_ffff;
            return page_addr + page_offset;
        }
        let pt_addr = pd_entry & 0x000f_ffff_ffff_f000;

        // Get PT entry (PTE) from linear address
        // 2:0 are all 0
        // 11:3 are bits 20:12 of the linear address
        // 51:12 are from the PDE
        let pt_index = (virt_addr >> 12) & 0x1ff;
        let pte_addr = pt_addr + (pt_index << 3);
        let pt_entry = self.read_phys::<u64>(pte_addr);
        log::trace!("PTE {pt_entry:#x}");

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
        assert!(pt_entry & 1 == 1, "PTE not present!");
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
    
    pub fn read_virt<T: Copy>(&self, virt_addr: u64) -> T {
        let phys_addr = self.translate_addr(virt_addr);
        log::trace!("virt_addr({virt_addr:#x}) -> phys_addr({phys_addr:#x})");
        self.read_phys::<T>(phys_addr)
    }

    fn write_phys<T>(&self, phys_addr: u64, value: T) {
        assert!((phys_addr as usize + std::mem::size_of::<T>()) < self.physmem_size);
        unsafe {
            std::ptr::write_unaligned((self.physmem_base + phys_addr) as *mut T, value);
        }
    }

    pub fn write_virt<T>(&self, virt_addr: u64, value: T) {
        let phys_addr = self.translate_addr(virt_addr);
        log::trace!("virt_addr({virt_addr:#x}) -> phys_addr({phys_addr:#x})");
        self.write_phys(phys_addr, value);
    }

    pub fn set_breakpoint(&self, virt_addr: u64){
        self.write_virt(virt_addr, 0xcc as u8);
    }

    pub fn is_trace(&self) -> bool {
        1 == 0
    }

    pub fn restore(&mut self) -> Result<()> {
        self.vcpu.sync_regs_mut().regs = self.cpu_state.regs;
        self.vcpu.set_sync_dirty_reg(SyncReg::Register);
        self.vcpu.sync_regs_mut().sregs = self.cpu_state.sregs;
        self.vcpu.set_sync_dirty_reg(SyncReg::SystemRegister);
        self.vcpu.set_fpu(&self.cpu_state.fpu)?;
        // Set MSRs
        let msrs = Msrs::from_entries(&self.cpu_state.msr_entries)?;
        self.vcpu.set_msrs(&msrs)?;
        // Do I need to restore debugregs, xcrs & lapic?
        // Restore pages here & clear dirty log
        self.restore_dirty_pages()?;

        Ok(())
    }

    fn restore_dirty_pages(&mut self) -> Result<()> {
        // Get the bitmaps indicating what pages have been dirtied
        self.get_dirty_logs()?;

        // Every bit set is a dirty page by index
        // bitmap_index * 64(bits in u64) + bit_index
        // to get mem address slot_mem_base + index*page_size

        let mut dirty_pages_addr = Vec::new();

        for mem_region in self.memory_regions.iter() {
            for (i, &bitmapi) in mem_region.dirty_bitmap.iter().enumerate() {
                if bitmapi == 0 {
                    continue;
                }
                for b in 0..64 {
                    if (bitmapi & (1 << b)) != 0 {
                        let page_index = (i * 64 + b) as u64;
                        dirty_pages_addr.push(mem_region.base + page_index * constants::PAGE_SIZE);
                    }
                }
            }
        }

        log::debug!("Restoring {} dirtied pages", dirty_pages_addr.len());
        // Copy each dirty page from the og snapshot
        // using avx512 for page copy would be cool and fast
        for addr in dirty_pages_addr {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (self.snapshot_base + addr) as *const u8,
                    (self.physmem_base + addr) as *mut u8,
                    0x1000,
                );
            }
        }

        // Clear dirty logs
        self.clear_dirty_logs()?;

        Ok(())
    }

    pub fn run(&mut self) -> Result<VcpuExit> {
        if self.is_trace() {
            // Single step is on
            let debug_struct = kvm_guest_debug {
                control: KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP | KVM_GUESTDBG_SINGLESTEP,
                ..Default::default()
            };
            // Enable guest mode in the guest
            self.vcpu.set_guest_debug(&debug_struct).unwrap();
        }
        // Run code on the vCPU.
        self.vcpu.run().context(anyhow!("KVMVcpuFdError"))
    }
}
