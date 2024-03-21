// SPDX-License-Identifier: Apache-2.0

mod linux;

use kvm_bindings::*;
use vmm_sys_util::*;

use crate::vcpu::linux::ioctl::Cmd;

vmm_sys_util::ioctl_iowr_nr!(KVM_MEMORY_ENCRYPT_OP, KVMIO, 0xba, std::os::raw::c_ulong);

impl crate::vm::TdxVm {
    pub fn init_vcpu(vcpu: &kvm_ioctls::VcpuFd, hob_addr: u64) -> Result<(), crate::vm::TdxError> {
        let mut cmd = Cmd {
            id: 2,
            flags: 0,
            data: hob_addr as *const u64 as _,
            error: 0,
            _unused: 0,
        };
        let ret = unsafe { ioctl::ioctl_with_mut_ptr(vcpu, KVM_MEMORY_ENCRYPT_OP(), &mut cmd) };
        if ret < 0 {
            // TODO: convert this into a TDX error
            // Need to implement a method that allows us to create a TDX error based on an integer
            // error code
        }
        Ok(())
    }
}
