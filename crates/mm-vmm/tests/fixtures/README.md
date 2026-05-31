# Boot integration test fixtures

The KVM boot integration test (`tests/boot_kvm.rs`) needs two artifacts in this
directory. They are **not** committed (kernels and images are large and
license-encumbered); `scripts/fetch-test-fixtures.sh` populates them on the KVM
runner (Task 13), and the CI `kvm-integration` job runs it before the test.

| File           | What it is                                                            |
|----------------|-----------------------------------------------------------------------|
| `vmlinux`      | An uncompressed x86_64 Linux kernel ELF with virtio-mmio + 8250 serial built in. |
| `rootfs.ext4`  | A minimal ext4 root image whose `/sbin/ready` (or PID 1) opens the boot vsock, writes one byte (the readiness edge the VMM waits on), then powers off. |

## Kernel requirements

Build (or download) an **ELF `vmlinux`** (not `bzImage`) with at least:

```text
CONFIG_VIRTIO=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y   # parse `virtio_mmio.device=` from cmdline
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_VIRTIO_CONSOLE=y
```

`CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` is essential: the VMM advertises each device
by appending `virtio_mmio.device=4K@<addr>:<gsi>` to the kernel command line
rather than using a device tree.

## Rootfs requirements

The image must contain an init/`/sbin/ready` that:

1. opens an `AF_VSOCK` connection (or just the device) and writes one byte — this
   is the readiness signal `Machine::wait_for_ready` blocks on;
2. then triggers power-off (e.g. `reboot(RB_POWER_OFF)`), so the vCPU halts and
   the test's `shutdown()` returns.

`crates/mm-init` (the MicroMachines guest init) satisfies this when statically
linked and installed as the image's `/init` with `mm.workload=/sbin/ready`.

## Manual run

```bash
./scripts/fetch-test-fixtures.sh
cargo test -p mm-vmm --features kvm-integration -- --ignored boots_to_userspace
```
