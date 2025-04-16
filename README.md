# Restricting memory access of the iip TCP/IP stack by using MPK

This repository contains a [pluggable](#structure-of-the-implementation) extesion of the [iip TCP/IP stack](https://github.com/yasukata/iip) for restricting its memory access by using the Memory Protection Key (MPK) feature of a CPU.

**WARNING: The authors will not bear any responsibility if the implementations, provided by the authors, cause any problems.**

## goal

The goal of the implementation in this repository is to reduce the possibility that memory accesses, which are not intended by the developers of programs running in the same address space, cause undesirable consequences; for example, an unintended memory write may overwrite some database metadata to be flushed to a storage device and break the database.

The technical goal is to cause a segmentation fault to enable actions such as stopping the program when the code of iip accesses memory regions it should not, or when implementations other than iip access [memory regions](#objects-dedicated-to-iip) dedicated to iip.

Note that security enhancement is not the goal of the implementation of this repository.

## requirements

- CPU: Memory Protection Keys (MPK) support, and AVX-512 support for [memory copy](#data-copy-between-memory-regions-associated-with-different-pkeys)
- OS: Linux
- compiler: gcc (for several builtin functions)

To check whether a CPU has the MPK support or not, the following command, which checks if ```pku``` is found in ```/proc/cpuinfo```, could be used.

```
if [ `cat /proc/cpuinfo|grep pku|wc -l` -gt 0 ]; then echo "MPK is supported"; else echo "MPK is not supported"; fi
```

Note: the programs in this repostory are tested on Linux 6.2 and Ubuntu 22.04.

## how to use

This extension can be applied [without changing the code of iip and an application leveraging iip](#structure-of-the-implementation).

This section shows how to use it with an example application named [bench-iip](https://github.com/yasukata/bench-iip.git).

Please first follow the instruction of README in the bench-iip repository to build the bench-iip application.

Once the compilation by ```IOSUB_DIR=./iip-dpdk make``` shown in README of bench-iip is finished, there are supposedly the following directories.
- bench-iip
- bench-iip/iip-dpdk
- bench-iip/iip

To apply the extension in this repository, please type the following commands in the ```bench-iip``` directory; we will have ```bench-iip/mpk-iip/libisolate-iip-mpk.so``` and ```bench-iip/a.out```.
Note that the commands below do not compile the programs if there is already ```bench-iip/mpk-iip/libisolate-iip-mpk.so``` or ```bench-iip/a.out```, therefore, please rename or remove them beforehand (```make clean``` for ```bench-iip/mpk-iip/libisolate-iip-mpk.so``` and ```bench-iip/a.out``` can be done by ```make -C mpk-iip clean; IOSUB_DIR=./iip-dpdk make clean```).

```
git clone https://github.com/yasukata/mpk-iip.git
```

```
make -C mpk-iip; IOSUB_DIR=./iip-dpdk CFLAGS="-D_GNU_SOURCE -DIIP_MAIN_C=\<mpk-iip/side-app.c\>" LDFLAGS="-L./mpk-iip -lisolate-iip-mpk" make
```

The usage of the program is mostly the same as the case where this extension is not applied, however, we need several environment variable settings.
- ```LD_BIND_NOW=1``` is needed to avoid memory access to the code section by the dynamic linker/loader subsystem after we associate pkeys with memory regions.
- ```GLIBC_TUNABLES="glibc.pthread.rseq=0"``` is to suppresses the use of restartable sequences feature by libc to avoid an issue causing a segmentation fault ( https://lkml.org/lkml/2025/2/17/606 ).
- ```MPK_IIP_OPT_MASK_SIGNAL=1``` is for this implementation; when this is configured, this implementation requests the kernel not to raise signal handlers during the execution of the iip program. This option is not recommended because of its negative performance impact, however, it would be useful for some quick tests; specifically, the tap device driver in DPDK configures a signal handler, therefore, we need this setting for the example below.
- Besides these, we need to add ```./mpk-iip``` to ```LD_LIBRARY_PATH``` to load ```bench-iip/mpk-iip/libisolate-iip-mpk.so```.

Once the environment variables above are specified, the example command shown in [README of bench-iip](https://github.com/yasukata/bench-iip?tab=readme-ov-file#run) will be like as follows.

```
sudo MPK_IIP_OPT_MASK_SIGNAL=1 LD_BIND_NOW=1 GLIBC_TUNABLES="glibc.pthread.rseq=0" LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu:./mpk-iip ./a.out -l 0 --proc-type=primary --file-prefix=pmd1 --vdev=net_tap,iface=tap001 --no-pci -- -a 0,10.100.0.20 -- -p 10000 -m "```echo -e 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nAA'```"
```

## limitation

As shown [above](#how-to-use), underlying systems, such as a dynamic linker/loader and an OS kernel, can intercept the control flow of a user-space program and insert certain work at an arbitrary moment, and some inserted work would attempt memory access disallowed by the MPK setting.

The limitation of the implementation in this repository is that it does not maintain a sophisticated means to cope with issues deriving from underlying systems specific to users' environments, and users are assumed to handle issues of their environments by themselves.

## commentary

### structure of the implementation

The default structure is shown below; the default ```bench-iip/main.c``` [directly includes](https://github.com/yasukata/bench-iip/blob/a476244dad0c7285ebfc3f4a03faa961e1c5e569/main.c#L78-L82) ```bench-iip/iip/main.c``` and leverges the iip functionalities through function calls.

```
bench-iip/main.c include bench-iip/iip/main.c
             |               ^
             |               |
             |--[call]--> function
```

On the other hand, for the implementation in this repository, we wish to separate the memory regions, where the code of iip is loaded, and the other code memory regions for fine-grained pkey setting.
To this end, we build the iip program as a shared library named ```bench-iip/mpk-iip/libisolate-iip-mpk.so``` that assumes to be dynamically linked to an application program.
```bench-iip/mpk-iip/libisolate-iip-mpk.so``` is implemented with ```bench-iip/mpk-iip/side-iip.c``` which  [directly includes](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L105) ```bench-iip/iip/main.c```. Essentially, ```bench-iip/mpk-iip/side-iip.c``` provides the MPK-aware entry points for an application to access the functionalities of iip.
The organization of ```bench-iip/mpk-iip/libisolate-iip-mpk.so``` is shown as below.; we use the macro feature of the C language to insert the MPK-aware entry point transparently, and we [replace iip_~ with renamed_iip_~](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L42-L103). 

```
    bench-iip/mpk-iip/side-iip.c include bench-iip/iip/main.c
                   ^        |               ^
                   |        |               |
--> MPK-aware entry point   |--[call]--> function
```

The MPK-aware entry points provided by ```bench-iip/mpk-iip/side-iip.c``` are used by an application such as ```bench-iip/main.c``` through ```bench-iip/mpk-iip/side-app.c```.
We change the file path defined in ```bench-iip/main.c``` for including ```bench-iip/mpk-iip/side-app.c``` instead of ```bench-iip/iip/main.c``` by ```-DIIP_MAIN_C=\<mpk-iip/side-app.c\>"``` shown [above](#how-to-use).
```bench-iip/mpk-iip/side-app.c``` implements a set of iip API functions and they internally perform the PKRU register value update and calls the MPK-aware entry points implemented by ```mpk-iip/side-iip.c```. It looks like the following.

```
bench-iip/main.c include bench-iip/mpk-iip/side-iip.c
             |                ^        |
             |                |        |
             |--[call]--> function     |--[PKRU update + call]--> MPK-aware entry point
```

The application program and ```bench-iip/mpk-iip/libisolate-iip-mpk.so``` are linked by a dynamic linker; the following shows how a call invoked in ```bench-iip/main.c``` is redirected to a function in ```bench-iip/iip/main.c```.

```
(----------------- a.out -------------------)<========== linked ==========>(--- mpk-iip/libisolate-iip-mpk.so ---)
 bench-iip/main.c include bench-iip/mpk-iip/side-app.c        bench-iip/mpk-iip/side-iip.c include bench-iip/iip/main.c
              |                ^        |                                         ^        |               ^
              |                |        |                                         |        |               |
              |--[call]--> function     |--[PKRU update + call]--> MPK-aware entry point   |--[call]--> function
```

### pkeys

This implementation uses three pkeys.

- pkey0: the default pkey
- pkey1: [__iip_mpk_pkey_shared_ro](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L980)
- pkey2: [__iip_mpk_pkey](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L980)

This implementation applies two permissions: for non-iip programs and for iip.
Each is configured by the PKRU register value shown in the table below.

|permission|pkey0|pkey1|pkey1
|---|---|---|---|
|for non-iip programs|READ+WRITE|READ+WRITE||
|[for iip](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1024-L1036)||READ|READ+WRITE|

### objects dedicated to iip

The following is the list of memory objects dedicated to iip; we assign [pkey2](#pkeys) to memory regions having these.
- [packet data including the header and payload](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-both.c#L43-L44) (we allocate them independently of the packet I/O framework [as part of the workspace of iip](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1042-L1059); so, we need to [copy the packet data between iip and a packet I/O framework](#data-copy-between-memory-regions-associated-with-different-pkeys).)
- [packet representation data structure](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1076)
- [information of TCP connections](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1097)
- [stack memory](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1022) (we allocate this independently of the default stack memory region [as part of the workspace of iip](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1051); we [switch the stack memory region at the permission switch](#switching-memory-access-permission).)

### data copy between memory regions associated with different pkeys

To copy data between memory regions having different pkeys, we use our [special implementation of memcpy](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L140).

When this implementation copies out, it first loads the data to be copied onto the zmm registers which are installed for the [AVX-512 support](#requirements), then it updates the PKRU register value to change the permission, and afterward, it copies the data on the zmm registers to the destination memory address. At last, it restores the PKRU register value.

When this implementation copies in, it first updates the PKRU register value to change the permission, then, it loads the data to be copied onto the zmm registers, afterward, it restores the PKRU register value, and copies the data on the zmm registers to the destination memory address.

### switching memory access permission

The memory access permission is switched by a function named [mpk_call](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L388).

mpk_call takes 6 arguments:
1. a value to be set to the PKRU register at the switch
2. a value to be set to %rsp (stack pointer) at the switch
3. NOT FOR mpk_call: passed to a function called after the memory access permission switch
4. NOT FOR mpk_call: passed to a function called after the memory access permission switch
5. NOT FOR mpk_call: passed to a function called after the memory access permission switch
6. a pointer to the function to be called after the memory access permission switch

mpk_call performs the following:
1. [store the current %rsp value to %rbp](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L394)
2. [set a value, specified as its second argument (%rsi), to %rsp](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L395) for switching the stack to be used
3. [execute rdpkru to preserve the current value of the PKRU register on %ebx](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L396-L400)
4. execute wrpkru to set a value, specified as its first argument (%edi), [to the PKRU register](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L401-L409)
5. [call a function whose address is specified as its sixth argument (%r9)](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L416)
6. after the function returns: [execute wrpkru to restore a value, preserved on %ebx by step 3, to the PKRU register](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L423)
7. [restore the stack pointer from %rbp saved by step 1](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L426)

The first two arguments of [a function called through mpk_call](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L416) are filled by mpk_call:
1. the value of the PKRU register applied before the switch [(passed via %rdi)](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L404)
2. the value of %rsp applied before the switch [(passed via %rsi)](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L412)

These two arguments are used for nested calls of mpk_call.
In some cases, a callback function called from iip may call a function of iip (for example, in a callback function named [iip_ops_udp_payload](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L889), a function of iip named [iip_udp_send](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1279) would be called to send an application-level reply with UDP), and by specifing these two values for mpk_call's first two arguments, we can switch back the permission while using the same stack memory region in a nested manner.
To do this, we maintain these values on [a memory region part of the workspace](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L773-L774).

### amortizing the costs of permission switching

The operations for the [permission switching](#switching-memory-access-permission) would be costly. This implementation maintains a technique to amortize the costs of permission switching.

- When an application calls iip_run for pushing received packets to iip, [it passes the packets in a batched manner](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1388-L1405); this is essentially the same as the default implementation of iip.
- When an application calls iip_tcp_send for requesting to send a TCP payload, [it pushes the payload to a queue](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1216-L1222), and [passed to iip in a batched manner](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-app.c#L1335-L1365).
- When iip calls iip_ops_tcp_payload which is origainally a callback function for passing a TCP payload to an applicaition, [it pushes the TCP payload to a queue instead](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L1405-L1417), and afterward, [it passes them to the application in a batched manner](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L1438). We do the same for [iip_ops_tcp_acked](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L1426-L1434).
- When iip calls iip_ops_l2_flush which is a callback function to request the packet I/O framework to trigger a packet transmission, [it passes packets to the packet I/O framework in a batched manner](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L1091-L1119).

### reducing the memory copy for packet data

The implementation in this repository [preserves buffers for packet data independently of a packet I/O framework](#objects-dedicated-to-iip). This means that it has to copy the data between the packet buffers of a packet I/O framework and the buffers for packet data preserved by this implementation.

However, [memory copy overhead negates bulk data transfer performance](https://github.com/yasukata/bench-iip/tree/a476244dad0c7285ebfc3f4a03faa961e1c5e569?tab=readme-ov-file#bulk-transfer), therefore, this implementation has a technique to reduce the memory copy for packet data.

The idea is that a TCP/IP stack usually does not need to touch a TCP payload if it does not need to perform checksumming, therfore:
- for the data requested by an application to send through iip_tcp_send, [if the underlying NIC supports the checksum offload feature and the scatter-gather feature, we skip memory copy for the payload](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L1755-L1757).
- for the received data, [if the underlying NIC supports the checksum offload, we partially copy packet data to pass its header to iip](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L1691-L1694).

## performance numbers

### machines

We use the same CPU, NIC, OS configuration shown in [README of bench-iip](https://github.com/yasukata/bench-iip/tree/a476244dad0c7285ebfc3f4a03faa961e1c5e569?tab=readme-ov-file#machines).

- CPU: Two of 16-core Intel(R) Xeon(R) Gold 6326 CPU @ 2.90GHz (32 cores in total)
- NIC: Mellanox ConnectX-5 100 Gbps NIC (the NICs of the two machines are directly connected via a cable)
- OS: Linux 6.2

We call each of two machine1 and machine2.

- machine1 runs with the configurations shown in the [compilation for each setup](#compilation-for-each-setup) section.
- machine2 works as a load generator that uses iip and DPDK without adopting the implementation; its setup is the same as the one used in the benchmarks shown in README of [bench-iip](https://github.com/yasukata/bench-iip/tree/a476244dad0c7285ebfc3f4a03faa961e1c5e569?tab=readme-ov-file#rough-numbers).

### commits

- iip: 289e026094b25f09d4504fb759d324c45c18eb84
- iip-dpdk: e361ef24ca615f49816903e1873f20527b3317e9
- bench-iip: a476244dad0c7285ebfc3f4a03faa961e1c5e569
- mpk-iip: eb44796d2c73180c78b37081ff59e964c3c8a3a6

### tweak for performance

While the implementation in this repository can be applied without modification to programs in iip and bench-iip, the following change to [iip](https://github.com/yasukata/iip/blob/289e026094b25f09d4504fb759d324c45c18eb84/main.c#L3260-L3263) may improve its performance for small packet processing in server workloads; the implementation in this repository has a performance enhancement technique that [batches application-specific processing for received TCP data](https://github.com/yasukata/mpk-iip/blob/eb44796d2c73180c78b37081ff59e964c3c8a3a6/side-iip.c#L1704), and the following change delays the transmission of an ack-only no-TCP-payload packet which will not be necessary when the application-specific processing sends back an application-level response which works as the ack.

```diff
                                                                _next_us = _next_us_tmp;
                                                }
                                        }
+#if __EXPERIMENT_NO_BATCHING
                                        if (!conn->head[3][0]) {
                                                if ((__iip_ntohl(conn->ack_seq_be) != conn->ack_seq_sent)) /* we got payload, but ack is not pushed by the app */
                                                        __iip_tcp_push(s, conn, NULL, 0, 1, 0, 0, 0, NULL, opaque);
                                        }
+#endif
                                        if (conn->do_ack_cnt) { /* push ack telling rx misses */
                                                struct pb *queue[2] = { 0 };
                                                if (conn->sack_ok && conn->head[4][1]) {
```

For the experiments here, we apply the change above.

### compilation for each setup

- iip default: iip that does not adopt the implementation in this repository

```
EXPERIMENT_CONF="-D__EXPERIMENT_NO_BATCHING=1" CFLAGS="$EXPERIMENT_CONF" IOSUB_DIR=./iip-dpdk make
```

- mpk-iip: iip that adopts the implementation in this repository

```
make -C mpk-iip; IOSUB_DIR=./iip-dpdk CFLAGS="-D_GNU_SOURCE -DIIP_MAIN_C=\<mpk-iip/side-app.c\>" LDFLAGS="-L./mpk-iip -lisolate-iip-mpk" make
```

- mpk-iip w/o rdpkru/wrpkru: iip that adopts the implementation in this repository, but rdpkru and wrpkru instructions are omitted from its code (note that this setup is just for this experiment and does not provide the memory access restriction by MPK)

```
export EXPERIMENT_CONF="-D__EXPERIMENT_NO_PKRU=1"; CFLAGS="$EXPERIMENT_CONF" make -C mpk-iip; IOSUB_DIR=./iip-dpdk CFLAGS="-D_GNU_SOURCE -DIIP_MAIN_C=\<mpk-iip/side-app.c\> $EXPERIMENT_CONF" LDFLAGS="-L./mpk-iip -lisolate-iip-mpk" make
```

- mpk-iip w/o batching: iip that adopts the implementation in this repository and deactivates the [batching technique](#amortizing-the-costs-of-permission-switching)

```
export EXPERIMENT_CONF="-D__EXPERIMENT_NO_BATCHING=1"; CFLAGS="$EXPERIMENT_CONF" make -C mpk-iip; IOSUB_DIR=./iip-dpdk CFLAGS="-D_GNU_SOURCE -DIIP_MAIN_C=\<mpk-iip/side-app.c\> $EXPERIMENT_CONF" LDFLAGS="-L./mpk-iip -lisolate-iip-mpk" make
```

- mpk-iip w/o memcpy skip: iip that adopts the implementation in this repository and deactivates the [memory copy skip technique](#reducing-the-memory-copy-for-packet-data)

```
export EXPERIMENT_CONF="-D__EXPERIMENT_NO_MEMCOPYSKIP=1"; CFLAGS="$EXPERIMENT_CONF" make -C mpk-iip; IOSUB_DIR=./iip-dpdk CFLAGS="-D_GNU_SOURCE -DIIP_MAIN_C=\<mpk-iip/side-app.c\> $EXPERIMENT_CONF" LDFLAGS="-L./mpk-iip -lisolate-iip-mpk" make
```

- Linux TCP/IP stack: the kernel-space TCP/IP stack implementation of Linux; the implementation and the command for compilation are shown at [README of bench-iip](https://github.com/yasukata/bench-iip/tree/a476244dad0c7285ebfc3f4a03faa961e1c5e569?tab=readme-ov-file#multi-core-server-performance). **CAUTION: the numbers of the Linux kernel TCP/IP stack are shown just for reference purposes, and comparison between iip and the Linux kernel TCP/IP stack is apples-to-oranges comparison.**

### small message exchange

1 core case

- machine1 (iip)

```
cnt=0; while [ $cnt -lt 8 ]; do sudo LD_BIND_NOW=1 GLIBC_TUNABLES="glibc.pthread.rseq=0" LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu:./mpk-iip ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -e 0 -- -p 10000 -l 1; cnt=$(($cnt+1)); done
```

- machine1 (Linux TCP/IP stack)

```
cnt=0; while [ $cnt -lt 8 ]; do ./app -c 0 -p 10000 -l 1 -g 1; cnt=$(($cnt+1)); done
```

- machine2

```
core=0; conn=1; while [ $conn -le 4 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-$core --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 1 -t 5 -c $conn -l 1; if [ $core -eq 31 ]; then conn=$(($conn*2)); fi; if [ $core -lt 31 ]; then core=$((($core+1)*2-1)); fi; done | tee -a result.txt
```

multi-core case

- machine1 (iip)

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_BIND_NOW=1 GLIBC_TUNABLES="glibc.pthread.rseq=0" LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu:./mpk-iip ./a.out -n 2 -l 0-$(($cnt == 0 ? 0 : $(($cnt-1)))) --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p $((10000+$cnt)) -g 1 -l 1; cnt=$(($cnt+4)); done
```

- machine1 (Linux TCP/IP stack)

```
ulimit -n unlimited; cnt=0; while [ $cnt -le 32 ]; do ./app -c 0-$(($cnt == 0 ? 0 : $(($cnt-1)))) -p $((10000+$cnt)) -g 1 -l 1; cnt=$(($cnt+4)); done
```

- machine2

```
cnt=0; while [ $cnt -le 32 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 2 -l 0-31 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p $((10000+$cnt)) -g 1 -l 1 -t 5 -c $(($cnt == 0 ? 1 : $cnt)) 2>&1 | tee -a ./result.txt; cnt=$(($cnt+4)); done
```

throughput result

<img src="https://raw.githubusercontent.com/yasukata/img/master/mpk-iip/small/throughput.svg" width="450px">

According to the results, the rdpkru and wrpkru instructions seem not to be the primary source of the overhead, and the large portion of the overhead comes from the operations to proxy the function calls over the memory access permission gate.

### bulk transfer

receive case

- machine1

```
cnt=0; while [ $cnt -le 20 ]; do sudo LD_BIND_NOW=1 GLIBC_TUNABLES="glibc.pthread.rseq=0" LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu:./mpk-iip ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -p 10000 -g 2 -v 1; cnt=$(($cnt+1)); done
```

- machine2

```
cnt=0; while [ $cnt -le 20 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -s 10.100.0.20 -p 10000 -g 2 -t 5 -c 1 -d 8 -l $((63488+63488*$cnt*32)) -v 1 2>&1 | tee -a ./result.txt; cnt=$(($cnt+1)); done
```

send case

- machine1

```
cnt=0; while [ $cnt -le 20 ]; do sudo LD_BIND_NOW=1 GLIBC_TUNABLES="glibc.pthread.rseq=0" LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu:./mpk-iip ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.20 -- -s 10.100.0.10 -p 10000 -g 2 -t 5 -c 1 -d 8 -l $((63488+63488*$cnt*32)) -v 1; cnt=$(($cnt+1)); done
```

- machine2

```
cnt=0; while [ $cnt -le 20 ]; do sudo LD_LIBRARY_PATH=./iip-dpdk/dpdk/install/lib/x86_64-linux-gnu ./a.out -n 1 -l 0 --proc-type=primary --file-prefix=pmd1 --allow 17:00.0 -- -a 0,10.100.0.10 -- -p 10000 -g 2 -v 1  2>&1 | tee -a ./result.txt; cnt=$(($cnt+1)); done
```

throughput result

<img src="https://raw.githubusercontent.com/yasukata/img/master/mpk-iip/bulk/throughput.svg" width="450px">

iip adopting the implementation in this repository reaches the speed limit of the 100 Gbps NIC.

On the other hand, in the case of mpk-iip w/o memcpy skip that deactivates the [technique for reducing memory copy](#reducing-the-memory-copy-for-packet-data), we find the TX throughput goes lower according to the size of the data to be transferred.
