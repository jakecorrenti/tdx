// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;

use tdx::launch::TdxVm;
use tdx::tdvf::*;

#[test]
fn launch() {
    let kvm_fd = Kvm::new().unwrap();
    let tdx_vm = TdxVm::new(&kvm_fd, 100).unwrap();
    let caps = tdx_vm.get_capabilities().unwrap();
    let _ = tdx_vm.init_vm(&kvm_fd, &caps).unwrap();
    let _vcpufd = tdx_vm.fd.create_vcpu(0).unwrap();
    let mut fs = std::fs::File::open("/usr/share/edk2/ovmf/OVMF.inteltdx.fd").unwrap();
    let (sections, _guid_found) = parse_sections(&mut fs).unwrap();
    let hob_section = get_hob_section(&sections).unwrap();
}
