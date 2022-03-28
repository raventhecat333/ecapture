#  How eCapture works

![](./images/how-ecapture-works.png)

The data capture of various user-mode processes implemented by eBPF HOOK uprobe does not require changes to the original program.
* SSL/HTTPS data export function, for HTTPS data packet fetching, no CA certificate is required.
* bash command capture, HIDS bash command monitoring solution.
* Database audit solutions for databases such as mysql query.

# eCapture Architecure
![](./images/ecapture-architecture.png)

# demonstration

## eCapture User Manual
[![eCapture User Manual](./images/ecapture-user-manual.png)](https://www.youtube.com/watch?v=CoDIjEQCvvA "eCapture User Manual")

# Use 
## Run directly
download [release](https://github.com/ehids/ecapture/releases) The binary package can be used directly.

System configuration requirements)
* The system linux kernel version must be higher than 4.18.
* Turn on BTF [BPF Type Format (BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html) Support.

### 
Verification method：
```shell
cfc4n@vm-server:~$# uname -r
4.18.0-305.3.1.el8.x86_64
cfc4n@vm-server:~$# cat /boot/config-`uname -r` | grep CONFIG_DEBUG_INFO_BTF
CONFIG_DEBUG_INFO_BTF=y
```

### openssl's certificate-free capture package 
It can be used by performing any https network request.
```shell
curl https://www.qq.com
```

## note
It is known that on centos 8.2 systems, wget's network behavior cannot be obtained because wget does not use openssl's so dynamic link library`libssl.so `, but `/lib64/libgnutls.so.30`, which will be supported later.

### bash shell capture
```shell
ps -ef | grep foo
```

# WeChat public account
![](./images/wechat_gzhh.png)

## Compile by yourself
Self-compilation has requirements for the compilation environment, please refer to the introduction in the chapter "Principles".

# principles

## eBPF technology 
[ebpf](https://ebpf.io) (Refer to the insructions on the official website)

## uprobe HOOK

### ssl hook for https 
This project hooks the return values of the`ssl_write` and `ssl_read` functions of`/lib/x86_64-linux-gnu/libssl.so.1.1`, gets the plain text information, and passes it to the user process through the ebpf map.
```go
Probes: []*manager.Probe{
    {
        Section:          "uprobe/SSL_write",
        EbpfFuncName:     "probe_entry_SSL_write",
        AttachToFuncName: "SSL_write",
        //UprobeOffset:     0x386B0,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    {
        Section:          "uretprobe/SSL_write",
        EbpfFuncName:     "probe_ret_SSL_write",
        AttachToFuncName: "SSL_write",
        //UprobeOffset:     0x386B0,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    {
        Section:          "uprobe/SSL_read",
        EbpfFuncName:     "probe_entry_SSL_read",
        AttachToFuncName: "SSL_read",
        //UprobeOffset:     0x38380,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    {
        Section:          "uretprobe/SSL_read",
        EbpfFuncName:     "probe_ret_SSL_read",
        AttachToFuncName: "SSL_read",
        //UprobeOffset:     0x38380,
        BinaryPath: "/lib/x86_64-linux-gnu/libssl.so.1.1",
    },
    /**/
},
```
### bash's readline hook
the hook`/bin/bash` of the `readline` function

# Compilation method
The openssl class library used for individual programs is statically compiled，You can also modify the source code to implement it yourself. If the function name is not in the symbol table，You can also decompile it yourself to find the offset address of the function，Fill in the `UprobeOffset` attribute and compile it.
The author's environment is `ubuntu 21.04`, which is common for linux kernel 5.10 and above。
**It is recommended to use the `UBUNTU 21.04` version of linux for testing. **

# Compile method
The openssl class library used for individual programs is statically compiled, and you can also modify the source code to implement it yourself. If the function name is not in the symbol table, you can also decompile it yourself to find the offset address of the function, fill in it on the "UprobeOffset" attribute, and compile it. The author's environment is `ubuntu 21.04`, which is common for linux kernel 5.10 and above. **It is recommended to use the `UBUNTU 21.04` version of linux for testing. **
 
## Requires
* golang 1.16
* gcc 10.3.0
* clang 12.0.0  
* cmake 3.18.4
* clang backend: llvm 12.0.0   

### Minimum requirements (not verified by author)
* gcc 5.1 or above
* clang 9
* cmake 3.14


## compile
```shell
git clone git@github.com:ehids/ecapture.git
cd ecapture
make
bin/ecapture
```
### reminder
When compiling for the first time, you need to download it first using : `go get -d github.com/shuLhan/go-bindata/cmd/go-bindata`

# Reference materials
[BPF Portability and CO-RE](https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html)
[ebpfmanager v0.2.2](https://github.com/ehids/ebpfmanager)
