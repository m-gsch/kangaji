# Kangaji 🐶
A very basic snapshot fuzzer using KVM to test ideas and learn.

**Very WIP!**

Currently able to run a full fuzz loop with coverage and find the crash in [example01](https://github.com/awslabs/snapchange/tree/main/examples/01_getpid) from Snapchange.
I'm also re-using the QEMU patches for snapshotting from Snapchange.

```
[2024-06-01T13:59:52Z INFO  kangaji::vm] Hit coverage breakpoint at @0x55555555536e
[2024-06-01T13:59:52Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555551d5
[2024-06-01T13:59:52Z INFO  kangaji::vm] Hit coverage breakpoint at @0x555555555040
[2024-06-01T13:59:52Z INFO  kangaji::vm] Hit coverage breakpoint at @0x555555555316
[2024-06-01T13:59:52Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555551f8
[2024-06-01T13:59:52Z INFO  kangaji::vm] Hit coverage breakpoint at @0x55555555520b
[2024-06-01T13:59:52Z INFO  kangaji::vm] Hit coverage breakpoint at @0x55555555521e
[2024-06-01T13:59:53Z INFO  kangaji::vm] Hit coverage breakpoint at @0x555555555231
[2024-06-01T13:59:53Z INFO  kangaji::vm] Hit coverage breakpoint at @0x555555555244
[2024-06-01T13:59:53Z INFO  kangaji::vm] Hit coverage breakpoint at @0x555555555257
[2024-06-01T13:59:53Z INFO  kangaji::vm] Hit coverage breakpoint at @0x55555555526a
[2024-06-01T13:59:53Z INFO  kangaji::vm] Hit coverage breakpoint at @0x55555555527d
[2024-06-01T13:59:54Z INFO  kangaji::vm] Hit coverage breakpoint at @0x555555555290
[2024-06-01T13:59:54Z INFO  kangaji::vm] Hit coverage breakpoint at @0x55555555529f
[2024-06-01T13:59:54Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555552ae
[2024-06-01T13:59:55Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555552bd
[2024-06-01T13:59:55Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555552cc
[2024-06-01T13:59:55Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555552db
[2024-06-01T13:59:55Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555552ea
[2024-06-01T13:59:56Z INFO  kangaji::vm] Hit coverage breakpoint at @0x5555555552f9
[2024-06-01T13:59:56Z INFO  kangaji::vm] Hit coverage breakpoint at @0x55555555530a
[2024-06-01T13:59:56Z INFO  kangaji] We found a crash! code:1 address:0xcafecafe
```