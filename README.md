# traceme
A Linux kernel module to Anti-Anti-ptrace for statically linked program.

# How it works
This module simply hooking the `sys_ptrace` call to tamper the result for special process.

# Usage

## Install the dependencies

For Debian-based distro:
```
sudo apt-get install linux-headers-`uname -r`
```

For RedHat-based distro, use following command instead:
```
sudo yum install kernel-devel
```

## Build the module

One make to rule them all:
```
make
```

## Running module

Find the address of `sys_call_table`:
```
sudo cat /proc/kallsyms | grep -i sys_call_table
```

On 64-bit Linux distro, the output is similar as below:
```
ffffffffa8e00220 R sys_call_table
ffffffffa8e015e0 R ia32_sys_call_table
```

Running the module with following arguments:
```
sudo insmod ./main.ko input_sys_call_table=ffffffffa8e00220 input_ia32_sys_call_table=ffffffffa8e015e0 
```

If you were running on 32-bit Linux distro, there are only one `sys_call_table` could be found. Just run without the last argument:
```
sudo insmod ./main.ko input_sys_call_table=ffffffffa8e00220
```

The logging message from syslog:
```
$ tail /var/log/syslog

Nov 17 15:51:09 kernel: [ 1581.374842] sys_call_table located at ffffffffa8e00220, original sys_ptrace ffffffffa80943a0 hooked
Nov 17 15:51:09 kernel: [ 1581.374843] ia32_sys_call_table located at ffffffffa8e015e0, original sys_ptrace ffffffffa8094780 hooked
```

Running strace command to trace the desire program
```
$ strace -ff -s 1024 ./malicious

$ tail /var/log/message

Nov 17 15:54:22 kernel: [ 1774.377737] Tampering process: malicious, pid: 3239
```
