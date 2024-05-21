/// https://github.com/tianocore/edk2/blob/284dbac43da752ee34825c8b3f6f9e8281cb5a19/OvmfPkg/ResetVector/Ia16/ResetVectorVtf0.asm#L35
/// https://github.com/tianocore/edk2/blob/284dbac43da752ee34825c8b3f6f9e8281cb5a19/OvmfPkg/ResetVector/X64/IntelTdxMetadata.asm#L4
use std::io::{Read, Seek, SeekFrom};
use uuid::{Error, Uuid};

const EXPECTED_TABLE_FOOTER_GUID: &str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const EXPECTED_METADATA_OFFSET_GUID: &str = "e47a6535-984a-4798-865e-4685a7bf8ec2";

#[repr(packed)]
#[derive(Default, Debug)]
pub struct TdvfDescriptor {
    signature: [u8; 4],
    length: u32,
    version: u32,
    num_sections: u32, // NumberOfSectionEntry
}

#[repr(packed)]
#[derive(Clone, Copy, Default, Debug)]
pub struct TdvfSection {
    pub data_offset: u32,
    pub data_size: u32,
    pub address: u64,
    pub size: u64,
    pub section_type: TdvfSectionType,
    pub attributes: u32,
}

#[repr(u32)]
#[derive(Debug, Default, Copy, Clone)]
pub enum TdvfSectionType {
    Bfv,
    Cfv,
    TdHob,
    TempMem,
    PermMem,
    Payload,
    PayloadParam,
    #[default]
    Reserved = 0xffffffff,
}

/// Locate the GUID at the footer of the OVMF flash file
fn locate_table_footer_guid(fd: &mut std::fs::File) -> Result<Uuid, Error> {
    // there are 32 bytes between the footer GUID and the bottom of the flash file, so we need to
    // move -48 bytes from the bottom of the file to read the 16 byte GUID
    fd.seek(SeekFrom::End(-0x30))
        .expect("Unable to seek to the offset in the file");

    let mut table_footer_guid: [u8; 16] = [0; 16];
    fd.read_exact(&mut table_footer_guid)
        .expect("Unable to read the exact amount of bytes required to fill the buffer");

    Uuid::from_slice_le(table_footer_guid.as_slice())
}

/// Locate the size of the entry table in the OVMF flash file
fn locate_table_size(fd: &mut std::fs::File) -> Result<u16, Error> {
    // from the bottom of the file, there is 32 bytes between the footer GUID, 16 bytes for the
    // GUID, and there are 2 bytes for the size of the entry table. We need to move -50 bytes from
    // the bottom of the file to read those 2 bytes.
    fd.seek(SeekFrom::End(-0x32))
        .expect("Unable to seek to the offset in the file.");

    let mut table_size: [u8; 2] = [0; 2];
    fd.read_exact(&mut table_size)
        .expect("Unable to read the exact amount of bytes required to fill the buffer");

    Ok(u16::from_le_bytes(table_size))
}

/// Reads the entry table into the provided table vector
fn read_table_contents(fd: &mut std::fs::File, table: &mut Vec<u8>, table_size: u16) {
    // table_size + the 32 bytes between the footer GUID and the EOF
    let table_start = -(table_size as i64 + 0x20);
    fd.seek(SeekFrom::End(table_start))
        .expect("Unable to seek to the start of the table");
    fd.read_exact(table.as_mut_slice())
        .expect("Unable to read GUID table");
}

/// Try to calculate the offset from the bottom of the flash file for the TDX Metadata GUID offset
fn calculate_tdx_metadata_guid_offset(table: &mut Vec<u8>, table_size: usize) -> Option<u32> {
    // starting from the end of the table and after the footer guid and table size bytes (16 + 2)
    let mut offset = table_size - 18;
    while offset >= 18 {
        // entries are laid out as follows:
        //
        // - data (arbitrary bytes identified by the guid)
        // - length from start of data to end of guid (2 bytes)
        // - guid (16 bytes)

        // move backwards through the table to locate the entry guid
        let entry_uuid = Uuid::from_slice_le(&table[offset - 16..offset])
            .expect("Unable to convert slice to UUID for entry");
        // move backwards through the table to locate the entry size
        let entry_size =
            u16::from_le_bytes(table[offset - 18..offset - 16].try_into().unwrap()) as usize;

        // Avoid going through an infinite loop if the entry size is 0
        if entry_size == 0 {
            break;
        }

        offset -= entry_size;

        let expected_uuid = Uuid::parse_str(EXPECTED_METADATA_OFFSET_GUID)
            .expect("Unable to convert GUID string to UUID");
        if entry_uuid == expected_uuid && entry_size == 22 {
            return Some(u32::from_le_bytes(
                table[offset..offset + 4].try_into().unwrap(),
            ));
        }
    }

    None
}

/// Calculate the offset from the bottom of the file where the TDX Metadata offset block is
/// located
pub fn get_tdvf_descriptor_offset(fd: &mut std::fs::File) -> Result<(u32, bool), Error> {
    let located = locate_table_footer_guid(fd).unwrap();
    let expected =
        Uuid::parse_str(EXPECTED_TABLE_FOOTER_GUID).expect("Unable to parse string into Uuid");

    // we found the table footer guid
    if located == expected {
        // find the table size
        let table_size = locate_table_size(fd).expect("Unable to locate TDVF table size");

        let mut table: Vec<u8> = vec![0; table_size as usize];
        read_table_contents(fd, &mut table, table_size);

        // starting from the top and go backwards down the table.
        // starting after the footer GUID and the table length
        if let Some(offset) = calculate_tdx_metadata_guid_offset(&mut table, table_size as usize) {
            return Ok((offset, true));
        }
    }

    // if we get here then the firmware doesn't support exposing the offset through the GUID table
    fd.seek(SeekFrom::End(-0x20))
        .expect("Unable to seek to descriptor offset");

    let mut descriptor_offset: [u8; 4] = [0; 4];
    fd.read_exact(&mut descriptor_offset)
        .expect("Unable to read exact amount of bytes into buffer");

    Ok((u32::from_le_bytes(descriptor_offset), false))
}

/// Parse the entries table and return the TDVF sections
pub fn parse_sections(fd: &mut std::fs::File) -> Result<(Vec<TdvfSection>, bool), Error> {
    let (offset, found_guid) = get_tdvf_descriptor_offset(fd).unwrap();
    fd.seek(SeekFrom::End(-(offset as i64))).unwrap();
    let mut descriptor: TdvfDescriptor = Default::default();
    fd.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            &mut descriptor as *mut _ as *mut u8,
            std::mem::size_of::<TdvfDescriptor>(),
        )
    })
    .unwrap();

    if &descriptor.signature != b"TDVF" {
        // invalid descriptor signature
    }

    if descriptor.length as usize
        != std::mem::size_of::<TdvfDescriptor>()
            + std::mem::size_of::<TdvfSection>() * descriptor.num_sections as usize
    {
        // invalid descriptor size
    }

    if descriptor.version != 1 {
        // invalid descriptor version
    }

    let mut sections = Vec::new();
    sections.resize_with(descriptor.num_sections as usize, TdvfSection::default);

    // SAFETY: we read exactly the advertised sections
    fd.read_exact(unsafe {
        std::slice::from_raw_parts_mut(
            sections.as_mut_ptr() as *mut u8,
            descriptor.num_sections as usize * std::mem::size_of::<TdvfSection>(),
        )
    })
    .unwrap();

    Ok((sections, found_guid))
}

pub fn get_hob_section<'a>(sections: &'a Vec<TdvfSection>) -> Option<&'a TdvfSection> {
    for section in sections {
        match section.section_type {
            TdvfSectionType::TdHob => {
                return Some(&section);
            }
            _ => continue,
        }
    }
    None
}
