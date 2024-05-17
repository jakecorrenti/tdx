// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;
use kvm_bindings::*;
use tdx::launch::{TdxVm, TdxVcpu};

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();
    let tdx_vm = TdxVm::new(&kvm_fd).unwrap();
    let mut cap: kvm_enable_cap = Default::default();
    cap.cap = KVM_CAP_MAX_VCPUS;
    cap.flags = 0;
    cap.args[0] = 100;
    tdx_vm.fd.enable_cap(&cap).unwrap();
    let caps = tdx_vm.get_capabilities().unwrap();
    let _ = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();

    cap = Default::default();
    cap.cap = KVM_CAP_SPLIT_IRQCHIP;
    cap.args[0] = 24;
    tdx_vm.fd.enable_cap(&cap).unwrap();
    let vcpu = TdxVcpu::new(&tdx_vm, 0).unwrap();
    vcpu.init_vcpu(0).unwrap();
}
