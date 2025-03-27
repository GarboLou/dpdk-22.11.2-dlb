# dpdk-22.11.2-dlb

We use [DPDK 22.11.2](https://fast.dpdk.org/rel/dpdk-22.11.2.tar.xz) following the instruction of Intel DLB 8.9.0 software release. We apply the provided DPDK patch. In addition, we fix some bugs (also reported to Intel and resolved in future releases) in the DPDK PMD driver. We also include DPDK-based microbenchmarks for DLB in this repo.


## Build DPDK
Use the following command to build DPDK.
```
meson -Dexamples=all build
cd build
sudo ninja
```