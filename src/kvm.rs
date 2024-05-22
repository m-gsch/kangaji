use anyhow::{anyhow, Result};
use kvm_bindings::{kvm_clear_dirty_log, KVMIO};
use kvm_bindings::{kvm_clear_dirty_log__bindgen_ty_1, kvm_dirty_log, kvm_dirty_log__bindgen_ty_1};
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::ioctl_iow_nr;

use crate::constants;
use crate::vm;

pub struct MemoryRegion {
    pub dirty_bitmap: Vec<u64>,
    pub base: u64,
    pub size: u32,
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

/// Expression that calculates an ioctl number.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// # use std::os::raw::c_uint;
/// use vmm_sys_util::ioctl::_IOC_NONE;
///
/// const KVMIO: c_uint = 0xAE;
/// ioctl_expr!(_IOC_NONE, KVMIO, 0x01, 0);
/// ```
#[macro_export]
macro_rules! ioctl_expr {
    ($dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        (($dir << vmm_sys_util::ioctl::_IOC_DIRSHIFT)
            | ($ty << vmm_sys_util::ioctl::_IOC_TYPESHIFT)
            | ($nr << vmm_sys_util::ioctl::_IOC_NRSHIFT)
            | ($size << vmm_sys_util::ioctl::_IOC_SIZESHIFT)) as ::std::os::raw::c_ulong
    };
}

/// Declare a function that returns an ioctl number.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// # use std::os::raw::c_uint;
/// use vmm_sys_util::ioctl::_IOC_NONE;
///
/// const KVMIO: c_uint = 0xAE;
/// ioctl_ioc_nr!(KVM_CREATE_VM, _IOC_NONE, KVMIO, 0x01, 0);
/// ```
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        #[allow(non_snake_case)]
        #[allow(clippy::cast_lossless)]
        pub fn $name() -> ::std::os::raw::c_ulong {
            ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr, $($v:ident),+) => {
        #[allow(non_snake_case)]
        #[allow(clippy::cast_lossless)]
        pub fn $name($($v: ::std::os::raw::c_uint),+) -> ::std::os::raw::c_ulong {
            ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
}

/// Declare an ioctl that reads and writes data.
///
/// ```
/// # #[macro_use] extern crate vmm_sys_util;
/// const VHOST: ::std::os::raw::c_uint = 0xAF;
/// ioctl_iowr_nr!(VHOST_GET_VRING_BASE, VHOST, 0x12, ::std::os::raw::c_int);
/// ```
#[macro_export]
macro_rules! ioctl_iowr_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        ioctl_ioc_nr!(
            $name,
            vmm_sys_util::ioctl::_IOC_READ | vmm_sys_util::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        ioctl_ioc_nr!(
            $name,
            vmm_sys_util::ioctl::_IOC_READ | vmm_sys_util::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}

ioctl_iow_nr!(KVM_GET_DIRTY_LOG, KVMIO, 0x42, kvm_dirty_log);
ioctl_iowr_nr!(KVM_CLEAR_DIRTY_LOG, KVMIO, 0xc0, kvm_clear_dirty_log);

impl vm::GuestVM {
    pub fn get_dirty_logs(&mut self) -> Result<()> {
        for (slot, mem_region) in self.memory_regions.iter_mut().enumerate() {
            // Create the structure for this clear
            let dirty_bitmap = mem_region.dirty_bitmap.as_mut_ptr().cast::<libc::c_void>();

            let dirty_log = kvm_dirty_log {
                slot: u32::try_from(slot)?,
                padding1: 0,
                __bindgen_anon_1: kvm_dirty_log__bindgen_ty_1 { dirty_bitmap },
            };

            // Safe because we know that our file is a VM fd, and we know that the amount
            // of memory we allocated for the bitmap is at least one bit per page.
            let ret = unsafe { ioctl_with_ref(&self.vm, KVM_GET_DIRTY_LOG(), &dirty_log) };

            // Check if ioctl failed
            if ret != 0 {
                return Err(anyhow!("GetDirtyLogError"));
            }
        }

        // Return success
        Ok(())
    }

    pub(crate) fn clear_dirty_logs(&mut self) -> Result<()> {
        for (slot, mem_region) in self.memory_regions.iter_mut().enumerate() {
            let dirty_bitmap = mem_region.dirty_bitmap.as_mut_ptr().cast::<libc::c_void>();

            let clear_log = kvm_clear_dirty_log {
                slot: u32::try_from(slot)?,
                num_pages: mem_region.size / constants::PAGE_SIZE as u32,
                first_page: 0,
                __bindgen_anon_1: kvm_clear_dirty_log__bindgen_ty_1 { dirty_bitmap },
            };

            // Safe because we know that our file is a VM fd, and we know that the amount
            // of memory we allocated for the bitmap is at least one bit per page.
            let ret = unsafe { ioctl_with_ref(&self.vm, KVM_CLEAR_DIRTY_LOG(), &clear_log) };

            // Check if ioctl failed
            if ret != 0 {
                return Err(anyhow!("ClearDirtyLogError"));
            }
        }

        Ok(())
    }
}
