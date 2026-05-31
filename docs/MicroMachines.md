# MicroMachines

MicroMachines is a rust based open source virtualization technology that is purpose-built
for creating and managing secure, multi-tenant container and function-based
services that provide serverless operational models with a container UX and
built-in GitOps management built in.

MicroMachines is a virtual machine monitor (VMM) that uses the Linux Kernel Virtual Machine (KVM) to create and run microVMs, like FireCracker but with more built in features useful for most development/deployment situations like internal automatic ip/ssh access, you can compile the vm into a self contained executable, or you can compile into unikernels (lightweight bootable disk images) and MicroVM rather than binaries. It also comes with a built in "Sandbox" Mode, which allows you to run agents/apps from within the sandboxed enviroment.

**Development/Reference_Only/** : is reference only, using them for inspiration and context never mporting them directly.


