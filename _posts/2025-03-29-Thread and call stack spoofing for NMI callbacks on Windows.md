---
title: "Thread and Call Stack Spoofing for NMI Callbacks on Windows"
date: 2025-03-30
categories: [Windows Kernel]
tags: [Windows, Kernel, Reverse Engineering]
---
## Introduction
Microsoft has a long history of regulating third-party kernel drivers for Windows. Since Windows XP, drivers had to be digitally signed by Microsoft in order to be installed without warnings, ensuring drivers met certain quality and security standards. Nowadays, obtaining a certificate can be rather expensive for cheat authors and malware authors - who instead opt to manually map their unsigned drivers into kernel memory with tools like [kdmapper](https://github.com/TheCruZ/kdmapper).

One of the most powerful methods that some anti-cheats and anti-rootkits employ to detect execution of unsigned drivers involves the use of non-maskable interrupts (NMIs).

NMIs are high-priority hardware interrupts that cannot be ignored or masked by regular interrupt masking techniques, making them typically reserved for hardware failures, memory errors and other situations where immediate processing is necessary. When an NMI hits a core, Windows calls each function in the NMI callback list. If there are no callbacks in the list or none of the callbacks handle the NMI (by returning `true`) then `HalHandleNMI` is called, which typically results in a bug check. Any driver can register an NMI callback using the [KeRegisterNmiCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisternmicallback) API.

By registering their own NMI callback and launching NMIs to each core, anti-cheats and anti-rootkits can gather information about the interrupted thread, the values of RIP and RSP when the interrupt occurred, the call stack of the running thread and more. If the interrupted RIP and RSP or any return address from the stack trace point to memory outside the ranges of valid kernel modules, then the processor was likely executing an unsigned driver. Although there isn't a guarantee the NMI will catch the processor executing outside valid memory ranges, by regularly sending NMIs it's only a matter of time before it's found.

In this post we'll demonstrate a PoC technique to spoof the state of the processor as if it were idle by hooking `HalPreprocessNmi` and manually adding our own restoration function to the end of the NMI callback list to restore the state of the processor before the interrupt returns. 

The source code is available [on Github](https://github.com/lxkast/frame).
## A Brief Explanation of NMIs
Firstly let's talk about how the CPU handles NMIs.

The CPU uses an [Interrupt Descriptor Table](https://wiki.osdev.org/Interrupt_Descriptor_Table) to store information about how each interrupt should be handled. Notably, it stores the address of the kernel routine to execute, as well as (if applicable) an index into the Interrupt Stack Table. NMIs use a separate stack because they can be delivered at any time, including when the kernel is in the middle of switching stacks, meaning it is not safe to make any assumptions about the previous state of the kernel stack.

We can view the Windows Interrupt Descriptor Table with a kernel debugger.

![image](attachments/Pasted%20image%2020250329124722.png)

Here we can see interrupt vector 2 is associated with the NMI handler `KiNmiInterrupt`, as well as it uses a separate stack.

We can take a look at the IDT entry to see which index in the interrupt stack table is associated with NMIs.

![image](attachments/Pasted image 20250329130002.png)

The `IstIndex` has value `011`, which is 3.

When the CPU switches to the new stack, the old SS, RSP, RFLAGS, CS, and RIP are pushed onto the new stack before executing the handler. When the interrupt handler executes the `iretq` instruction (interrupt return), these values are popped off the stack and execution resumes.
On Windows this is the `MACHINE_FRAME`, sometimes referred to as the IRETQ frame.

```c
//0x28 bytes (sizeof) 
struct _MACHINE_FRAME { 
	ULONGLONG Rip; //0x0 
	USHORT SegCs; //0x8 
	USHORT Fill1[3]; //0xa 
	ULONG EFlags; //0x10 
	ULONG Fill2; //0x14 
	ULONGLONG Rsp; //0x18 
	USHORT SegSs; //0x20 
	USHORT Fill3[3]; //0x22 
};
```

Because the NMI callbacks run on these new stacks, anti-cheats and anti-rootkits can find the machine frame on the stack to read the old values of RIP and RSP.
## KiProcessNMI
Now it's time to do some reverse engineering. Our goal is to find out how the NMI callbacks are executed and if there is any way to execute code before they run. I'm using Windows 10 22H2 so if you're on a different version things may be slightly different.

Starting at `KiNmiInterrupt` from the IDT entry, there's quite a lot going on but nothing related to NMI callbacks. The only thing worth looking at is its call to `KxNmiInterrupt`.
Taking a look at `KxNmiInterrupt`, it seems to just be a wrapper around `KiProcessNMI`.

![image](attachments/Pasted image 20250329140957.png)

`KiProcessNMI` has some interesting things.

![image](attachments/Pasted image 20250329141043.png)

It starts off by moving some data into RAX and calling `_guard_dispatch_icall`, which is a function that basically just does `jmp rax`. The address it jumps to is loaded at runtime so we'll use a kernel debugger to see what it is.

![image](attachments/Pasted image 20250329142229.png)

The address stored at offset `0x3e8` in the [HAL private dispatch table](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/hal/hal_private_dispatch.htm) is moved into RAX, which corresponds to `HalPreprocessNmi`.
```c
VOID (*HalPreprocessNmi)(ULONG arg1);
```
We can also see it passes 0 into the first argument (ECX). We'll talk more about this function and the HAL private dispatch table later.

Looking further into `KiProcessNMI`, we find one more call to `HalPreprocessNmi` with argument 1 before a reference to `KiNmiCallbackListHead`.

![image](attachments/Pasted image 20250329143154.png)

It iterates through a linked list of callbacks, calling each one before moving on to the next.

Here's what makes up a callback list entry.
```c
typedef struct _KNMI_HANDLER_CALLBACK
{
    struct _KNMI_HANDLER_CALLBACK* Next;
    void(*Callback)();
    void* Context;
    void* Handle;
} KNMI_HANDLER_CALLBACK, *PKNMI_HANDLER_CALLBACK;
```

So before the NMI callbacks execute, there are two calls to `HalPreprocessNMI` which is called using the pointer for it stored in the HAL private dispatch table. By swapping the pointer in the table to our own function we can:
1. Swap values in the machine frame.
2. Swap the current thread in the KPRCB.
3. Append a restoration function to the end of the callback list to undo our changes before the NMI returns.

### HAL Private Dispatch Table
The HAL private dispatch table is a table of pointers to optional HAL (Hardware Abstraction Layer) functionality. Although the HAL overrides most of the pointers, the address to the table is exported to allow drivers to override them further. This is nice to know as it means we won't have any trouble with [PatchGuard](https://en.wikipedia.org/wiki/Kernel_Patch_Protection).

> This table and other HAL structures are usually monitored by anti-cheats and anti-rootkits. It's far easier to detect a manually mapped driver if these tables store pointers outside of valid regions than detecting execution with NMIs in the first place.
{: .prompt-warning }

Dealing with this issue isn't the focus of this post, so let's continue with the code.

## Swapping the Machine Frame
Let's start by initializing our hook. To get the exported address of the HAL private dispatch table, we can use `MmGetSystemRoutineAddress`.
```c++ 
NTSTATUS InitHook() {
    UNICODE_STRING target = RTL_CONSTANT_STRING(L"HalPrivateDispatchTable");
    PHAL_PRIVATE_DISPATCH hal_private_dispatch = (PHAL_PRIVATE_DISPATCH)MmGetSystemRoutineAddress(&target);
    if (!hal_private_dispatch) {
        LOG_ERROR("Failed to find HAL private dispatch table");
        return STATUS_RESOURCE_NAME_NOT_FOUND;
    }

    HalPreprocessNmiOriginal = hal_private_dispatch->HalPreprocessNmi;
    hal_private_dispatch->HalPreprocessNmi = HalPreprocessNmiHook;
    LOG_DEBUG("Hooked HalPreprocessNmi");

    return STATUS_SUCCESS;
}
```

Within `HalPreprocessNmiHook` we want to locate the machine frame. To do this, we first need to find the [Task State Segment (TSS)](https://wiki.osdev.org/Task_State_Segment), which stores the Interrupt Stack Table, and then locate the stack at index 3 of the table. The TSS is stored in the [KPCR](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/kpcr.htm). We can then modify the values in the machine frame to spoof the interrupted RIP and RSP.

Additionally, we want to find the NMI callback list and add our own callback to the end. The reason why we can't use `KeRegisterNmiCallback` is because that function acquires a lock on the callback list, which is not a safe operation to do at `HIGH_LEVEL` IRQL. The NMI callback list can be found by signature scanning for the instruction that references it in `KiProcessNMI`. I found this to be `48 8B 3D ? ? ? ? 41 8A F4`.
```c++
VOID HalPreprocessNmiHook(ULONG arg1) {
    HalPreprocessNmiOriginal(arg1);
    LOG_DEBUG("HalPreprocessNmi hook called");
    
    if (arg1 == 1) return;

    if (!nmi_list_head) {
        LOG_ERROR("Failed to find: Nmi list head");
        return;
    }

    // add our restore function to the back of the callback list
    callback_parent = nullptr;
    PKNMI_HANDLER_CALLBACK current_callback = nmi_list_head;
    while (current_callback) {
        callback_parent = current_callback;
        current_callback = current_callback->Next;
    }
    callback_parent->Next = &restore_callback;

    PKPCR kpcr = KeGetPcr();
    PKTSS64 tss = (PKTSS64)kpcr->TssBase;
    PMACHINE_FRAME machine_frame = (PMACHINE_FRAME)(tss->Ist[3] - sizeof(MACHINE_FRAME));

    ULONG processor_index = KeGetCurrentProcessorNumberEx(nullptr);
    nmi_core_infos[processor_index].prev_rip = machine_frame->Rip;
    nmi_core_infos[processor_index].prev_rsp = machine_frame->Rsp;

    machine_frame->Rip = 0x123;
    machine_frame->Rsp = 0x456;
}
```

Our restoration function simply finds the machine frame to swap back the values, then removes itself from the callback list.
```c++
BOOLEAN RestoreFrameCallback(PVOID context, BOOLEAN handled) {
    UNREFERENCED_PARAMETER(context);
    LOG_DEBUG("Restore frame callback called");
    
    PKPCR kpcr = KeGetPcr();
    PKTSS64 tss = (PKTSS64)kpcr->TssBase;
    PMACHINE_FRAME machine_frame = (PMACHINE_FRAME)(tss->Ist[3] - sizeof(MACHINE_FRAME));

    ULONG processor_index = KeGetCurrentProcessorNumberEx(nullptr);
    machine_frame->Rip = nmi_core_infos[processor_index].prev_rip;
    machine_frame->Rsp = nmi_core_infos[processor_index].prev_rsp;

    LOG_DEBUG("Swapped back machine frame");

    if (callback_parent) {
        callback_parent->Next = nullptr;
    }

    return handled;
}
```

We can test this by writing a separate driver that registers a callback with [KeRegisterNmiCallback](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisternmicallback) then launches NMIs to each core with `HalSendNMI`.

![image](attachments/nmi-123-rip.png)

On the left we see a stack trace generated by [RtlCaptureStackBackTrace](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturestackbacktrace) and on the right is the call stack from the kernel debugger. We can see that setting the previous RIP and RSP to 0x123 and 0x456 completely shuts down any attempt of tracing the original call stack when the NMI occurred.

We can take this one step further and spoof the interrupted thread as an entirely different thread and pair it with valid RIP and RSP values such that the stack trace is completely legitimate.

## Spoofing as an Idle Thread
There's a number of reasons why the processor's idle thread is a good choice of thread to spoof as.

- The idle thread runs more often than any other thread.
- You can find its KTHREAD structure within the hook directly from the KPRC.
- The thread makes minimal changes to the stack, making call stack spoofing reliable.
- Each processor is assigned its own idle thread.

Idle threads begin execution at `KiIdleLoop`.
In this loop many functions are called such as a power management function `PoIdle`, which further calls `HalProcessorIdle` to enter power saving mode.

Since there is only one level to the call stack when `PoIdle` is called, if we set the previous RIP to `PoIdle` and the previous RSP to the typical value of RSP on entry to `PoIdle`, we can spoof the callstack to follow back to `KiIdleLoop`.

Because `KiIdleLoop` does not make any drastic modifications to its stack, a return address pointing back to somewhere in `KiIdleLoop` will always remain in the same position on the stack, no matter what code is executing or where the stack pointer is. In fact we can set the previous RIP to any of the functions that are called by `KiIdleLoop` and this will still be the case, although there is no guarantee the return address is absolutely in the correct spot within `KiIdleLoop`.

By experimenting with sending NMIs to the processors on my laptop: it seems to be the case that the lower indexed cores return from `SwapContext`, whereas the mid to high indexed cores are from `PoIdle`. I suspect it might be possible to determine which of these the idle thread last executed within our `HalPreprocessNmiHook`, so we could craft the perfect call stack. With that said, I will only be spoofing the RIP as `PoIdle`. 

Using a kernel debugger we can place a breakpoint on `PoIdle` and look at the thread information.

![image](attachments/poidle.png)

We can see that the value of RSP is `0x38` under the inital stack when `PoIdle` is called, which is what we'll spoof our RSP as.

To put this all together, we'll first need to signature scan for `PoIdle`. I found this pattern to be `40 55 53 41 56`.

The hook doesn't need too much modification. As well as storing the previous RIP and RSP, we also store the previous `CurrentThread` and `NextThread` pointers, along with the previous `Running` field of the idle thread. Then we set the RIP to `PoIdle`, the RSP to `0x38` under the thread's initial stack, the current thread to the idle thread and mark it as running.

```c++
    PKPCR kpcr = KeGetPcr();
    PKPRCB kprcb = kpcr->CurrentPrcb;
    PKTSS64 tss = (PKTSS64)kpcr->TssBase;
    PMACHINE_FRAME machine_frame = (PMACHINE_FRAME)(tss->Ist[3] - sizeof(MACHINE_FRAME));

    ULONG processor_index = KeGetCurrentProcessorNumberEx(0);
    nmi_core_infos[processor_index].prev_rip = machine_frame->Rip;
    nmi_core_infos[processor_index].prev_rsp = machine_frame->Rsp;
    nmi_core_infos[processor_index].prev_current_thread = kprcb->CurrentThread;
    nmi_core_infos[processor_index].prev_next_thread = kprcb->NextThread;
    nmi_core_infos[processor_index].prev_running = kprcb->IdleThread->Running;

    /*
        We will spoof as the current core's idle system thread
        Through investigation with WinDbg: a valid RSP should be around 0x38 under the initial RSP
        which should work well if we pretend RIP was nt!PoIdle
    */
    
    machine_frame->Rip = PoIdle;
    machine_frame->Rsp = (ULONGLONG)((PUCHAR)kprcb->IdleThread->InitialStack - 0x38);
    kprcb->CurrentThread = kprcb->IdleThread;
    kprcb->NextThread = nullptr;
    kprcb->IdleThread->Running = true;
```

Of course we must also swap back the stored values in our restoration callback.

## Testing
Testing on a virtual machine:
![image](attachments/spoofed.png)

We've successfully spoofed our call stack as an idle thread. I don't have many cores available on the virtual machine so let's try it on real hardware.
![image](attachments/realtest.png)

Thank you for reading! Once again, the full source code can be found [here](https://github.com/lxkast/frame).