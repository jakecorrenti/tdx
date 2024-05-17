// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;
use kvm_bindings::*;
use tdx::launch::TdxVm;

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();
    let tdx_vm = TdxVm::new(&kvm_fd).unwrap();
    let mut cap: kvm_enable_cap = Default::default();
    cap.cap = KVM_CAP_MAX_VCPUS;
    cap.flags = 0;
    cap.args[0] = 100;
    let caps = tdx_vm.get_capabilities().unwrap();
    let _ = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();
    let vcpu = tdx_vm.fd.create_vcpu(0).unwrap();
}
