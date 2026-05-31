//! Kernel loading + Linux 64-bit boot protocol setup (SPEC-1 FR-2).
//!
//! MicroMachines boots an ELF `vmlinux` directly — no bootloader, no firmware.
//! That means the VMM must do what GRUB/BIOS normally would: copy the kernel
//! image into guest RAM, write the kernel command line, and fill the `boot_params`
//! "zero page" (loader type, header magic, cmdline pointer, and the e820 memory
//! map) so the kernel knows how much RAM it has and where its arguments are. The
//! resulting entry point and zero-page address are handed to the vCPU setup in
//! [`crate::vcpu::Vcpu::configure_boot`].
use std::fs::File;
use std::path::Path;

use linux_loader::cmdline::Cmdline;
use linux_loader::configurator::linux::LinuxBootConfigurator;
use linux_loader::configurator::{BootConfigurator, BootParams};
use linux_loader::loader::bootparam::boot_params;
use linux_loader::loader::elf::Elf;
use linux_loader::loader::{load_cmdline, KernelLoader};
use vm_memory::{GuestAddress, GuestMemoryMmap};

use crate::machine::{Result, VmmError};

// --- Guest-physical layout for boot data (low memory, below the 1 MiB kernel). ---
/// Where the kernel image is loaded (top of low memory at 1 MiB).
const HIMEM_START: u64 = 0x0010_0000;
/// The `boot_params` "zero page" the kernel reads via `RSI`.
const ZERO_PAGE_START: u64 = 0x0000_7000;
/// Where the kernel command line is written.
const CMDLINE_START: u64 = 0x0002_0000;
/// Maximum command-line length we reserve.
const CMDLINE_MAX_SIZE: usize = 0x1_0000;
/// Start of the Extended BIOS Data Area — the top of the first usable RAM chunk.
const EBDA_START: u64 = 0x0009_fc00;

// --- boot_params header magic / loader identification. ---
const E820_RAM: u32 = 1;
const KERNEL_LOADER_OTHER: u8 = 0xff;
const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448; // "HdrS"
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

/// The two addresses the vCPU boot setup needs: the kernel entry point (`RIP`)
/// and the zero-page / `boot_params` address (`RSI`).
#[derive(Debug, Clone, Copy)]
pub struct KernelBoot {
    pub entry_point: GuestAddress,
    pub boot_params_addr: GuestAddress,
}

/// Load the kernel, write the command line, and configure `boot_params` for a
/// guest with `mem_size_bytes` of RAM. Returns the entry/zero-page addresses.
pub fn load_and_configure(
    guest_memory: &GuestMemoryMmap,
    kernel_path: &Path,
    cmdline: &str,
    mem_size_bytes: u64,
) -> Result<KernelBoot> {
    let entry_point = load_kernel(guest_memory, kernel_path)?;
    let cmdline_len = write_cmdline(guest_memory, cmdline)?;
    configure_boot_params(guest_memory, cmdline_len, mem_size_bytes)?;

    Ok(KernelBoot {
        entry_point,
        boot_params_addr: GuestAddress(ZERO_PAGE_START),
    })
}

/// Load an ELF `vmlinux` into guest memory and return its entry point.
fn load_kernel(guest_memory: &GuestMemoryMmap, kernel_path: &Path) -> Result<GuestAddress> {
    let mut file = File::open(kernel_path)
        .map_err(|e| VmmError::KernelLoad(format!("opening {}: {e}", kernel_path.display())))?;

    let result = Elf::load(
        guest_memory,
        None,
        &mut file,
        Some(GuestAddress(HIMEM_START)),
    )
    .map_err(|e| VmmError::KernelLoad(format!("ELF load failed: {e}")))?;

    Ok(result.kernel_load)
}

/// Write the kernel command line into guest memory at [`CMDLINE_START`], returning
/// its length (excluding the trailing NUL) for the `boot_params` header.
fn write_cmdline(guest_memory: &GuestMemoryMmap, cmdline: &str) -> Result<usize> {
    let mut kernel_cmdline = Cmdline::new(CMDLINE_MAX_SIZE)
        .map_err(|e| VmmError::KernelLoad(format!("cmdline alloc: {e}")))?;
    kernel_cmdline
        .insert_str(cmdline)
        .map_err(|e| VmmError::KernelLoad(format!("cmdline insert: {e}")))?;

    load_cmdline(guest_memory, GuestAddress(CMDLINE_START), &kernel_cmdline)
        .map_err(|e| VmmError::KernelLoad(format!("writing cmdline: {e}")))?;

    Ok(cmdline.len())
}

/// Fill the `boot_params` zero page: loader identification, the cmdline pointer,
/// and the e820 memory map (usable RAM below the EBDA, then from 1 MiB to the top
/// of guest RAM). Written to guest memory via the Linux boot configurator.
fn configure_boot_params(
    guest_memory: &GuestMemoryMmap,
    cmdline_len: usize,
    mem_size_bytes: u64,
) -> Result<()> {
    let mut params = boot_params::default();
    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    params.hdr.cmd_line_ptr = CMDLINE_START as u32;
    params.hdr.cmdline_size = (cmdline_len + 1) as u32;

    // Usable RAM below the EBDA.
    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;
    // Usable RAM from the kernel base to the top of guest memory.
    if mem_size_bytes > HIMEM_START {
        add_e820_entry(
            &mut params,
            HIMEM_START,
            mem_size_bytes - HIMEM_START,
            E820_RAM,
        )?;
    }

    let zero_page = BootParams::new::<boot_params>(&params, GuestAddress(ZERO_PAGE_START));
    LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap>(&zero_page, guest_memory)
        .map_err(|e| VmmError::KernelLoad(format!("writing boot_params: {e}")))
}

/// Append one entry to the `boot_params` e820 memory map, bounded by the fixed
/// 128-entry table.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) -> Result<()> {
    let index = params.e820_entries as usize;
    if index >= params.e820_table.len() {
        return Err(VmmError::KernelLoad("too many e820 entries".to_string()));
    }
    params.e820_table[index].addr = addr;
    params.e820_table[index].size = size;
    params.e820_table[index].type_ = mem_type;
    params.e820_entries += 1;
    Ok(())
}
