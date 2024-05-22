// SPDX-License-Identifier: Apache-2.0

use kvm_ioctls::Kvm;

use tdx::launch::TdxVcpu;
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
    let vcpu = TdxVcpu::new(&tdx_vm, 0).unwrap();

        let mut cpuid = kvm_fd.get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES).unwrap();
    { 
        let entries = cpuid.as_mut_slice();
        for entry in entries.iter_mut() {
            match entry.index {
                0x1 => entry.ecx &= (1 << 21),
                _ => (),
            }
        }
    }
    vcpu.fd.set_cpuid2(&cpuid).unwrap();

    vcpu.init_vcpu(hob_section.address).unwrap();

    //     // Update the CPUID entries to disable the EPB feature.
    // const ECX_EPB_SHIFT: u32 = 3;
    // {
    //    let entries = kvm_cpuid.as_mut_slice();
    //    for entry in entries.iter_mut() {
    //        match entry.function {
    //            6 => entry.ecx &= !(1 << ECX_EPB_SHIFT),
    //            _ => (),
    //        }
    //    }
    // }
    //
    // vcpu.set_cpuid2(&kvm_cpuid).unwrap();
}
