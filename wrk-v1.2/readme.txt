
Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of
the Windows Research Kernel Source Code License agreement
(see License.txt).  If you do not agree to the terms, do not use the code.

***

WRK v1.2

The Windows Research Kernel v1.2 contains the sources for the core of
the Windows (NTOS) kernel and a build environment for a kernel that will run on
    x86     (Windows Server 2003 Service Pack 1) and
    AMD64   (Windows XP x64 Professional)
A future version may also support booting WRK kernels on Windows XP x86 systems,
but the current kernels will fail to boot due to differences in some shared structures.

The NTOS kernel implements the basic OS functions
for processes, threads, virtual memory and cache managers, I/O management,
the registry, executive functions such as the kernel heap and synchronization,
the object manager, the local procedure call mechanism, the security reference
monitor, low-level CPU management (thread scheduling, Asynchronous and Deferred
Procedure calls, interrupt/trap handling, exceptions), etc.

The NT Hardware Abstraction Layer, file systems, network stacks, and device
drivers are implemented separately from NTOS and loaded into kernel mode
as dynamic libraries.  Sources for these dynamic components are not included
in the WRK, but some are available in various development kits published
by Microsoft, such as the Installable File System (IFS) Kit and the
Windows Driver Development Kit (DDK).

WRK v1.2 includes most of the NTOS kernel sources from the latest released
version of Windows, which supports the AMD64 architecture on the Desktop.
The kernel sources excluded from the kit are primarily in the areas of
plug-and-play, power management, the device verifier, kernel debugger
interface, and virtual dos machine.  The primary modifications to WRK
from the released kernel are related to cleanup and removal of server
support, such as code related to the Intel IA64.

***

Organization of the WRK sources

The file License.txt contains the license covering use of the WRK.

The public\ directory contains a number of include files shared among system
components.  base\ntos\ contains the NTOS sources.

The primary NTOS source components included in the WRK are organized as follows:

    cache\  - cache manager
    config\ - registry implementation
    dbgk\   - user-mode debugger support
    ex\     - executive functions (kernel heap, synchronization, time)
    fsrtl\  - file system run-time support
    io\     - I/O manager
    ke\     - scheduler, CPU management, low-level synchronization
    lpc\    - local procedure call implementation
    mm\     - virtual memory manager
    ob\     - kernel object manager
    ps\     - process/thread support
    se\     - security functions
    wmi\    - Windows Management Instrumentation

    inc\    - NTOS-only include files
    rtl\    - kernel run-time support
    init\   - kernel startup

***

Two of the best existing sources for documentation of the NTOS kernel are

    Microsoft Windows Internals, 4th Ed 2005, Mark Russinovich and David Solomon

    The Windows Curriculum Resource Kit (CRK)
    http://www.msdnaa.net/curriculum/pfv.aspx?ID=6191

Additional information about using Windows for teaching and research
in operating systems is available at

    http://www.microsoft.com/resources/sharedsource/Licensing/WindowsAcademic.mspx

Specific questions about use of the WRK, CRK, or ProjectOZ can be directed to

    compsci@microsoft.com

Questions about the kernel sources (or CRK or ProjectOZ) can be directed to
the MSDN academic forum groups (http://forums.microsoft.com/WindowsAcademic)

    Curriculum
        A discussion forum regarding development of operating systems curriculum
        based on the Windows kernel, including use of the Windows Curriculum
        Resource Kit, the Windows Research Kernel, and ProjectOZ.

    Kernel 
        Questions & Answers regarding the Windows Research Kernel,
        its architecture, source code and use in teaching and research.

    ProjectOZ
        Questions & Answers regarding use of ProjectOZ for teaching and
        research of operating systems topics.

***

Building/deploying a WRK kernel for x86 [or amd64]

    0. Copy the WRK into a directory, say %wrk%.  
    1. set arch=x86 [or amd64]
    2. path %wrk%\tools\%arch%;%path%
    3. cd %wrk%\base\ntos
    4. nmake -nologo %arch%=
        will produce kernel files in BUILD\EXE\%arch%
        [wrkx86.* or wrkx64.*]
    5. copy the kernel to %SystemRoot%\system32\
    6. if x86, find the Multi-processor version of hal.dll [see below]
    7. add a line to C:\boot.ini of the target system
        to boot this kernel and the MP hal [see below]
    8. reboot and select the boot option for the new kernel
    9. you will boot up on a kernel you built/linked yourself!
        [always keep the original boot.ini line and kernel/hal available so you
         can still boot your system if something fails with your WRK kernel modifications]
    10. set up a debugger [see below]

Multi-processor hal (x86 only, amd64 hals are all MP)
    All hals are renamed hal.dll, so you have to use the link command to
    see what type of hal hal.dll really is:
        link -dump -all hal.dll | findstr pdb
    The MP hals have an 'm' in the native name of the hal, e.g. halmacpi.dll
    You may already have an MP hal installed on UP systems, due to hyperthreading.
    If the hal isn't MP, you need to find the MP hal that corresponds to the current hal
    the target system does have, i.e. 
        halacpi.dll  -> halacpim.dll    ; ACPI PIC-based PC  [used by VirtualPC]
        halaacpi.dll -> halmacpi.dll    ; ACPI APIC-based PC
        halapic.dll  -> halmps.dll      ; MPS
    Look in the WRK WS03SP1HALS\x86 directory for the MP hal you need.

Boot.ini
    Edit boot.ini (you may have to use attrib -h -s -r first)
    Copy the line for the first operating system listed to the end of the file and edit it.
        [boot loader]
        timeout=30
        default=multi(0)disk(0)rdisk(0)partition(2)\WINDOWS
        [operating systems]
        multi(0)disk(0)rdisk(0)partition(2)\WINDOWS="Windows Server 2003, Standard"
        multi(0)disk(0)rdisk(0)partition(2)\WINDOWS="test" /kernel=wrkx86.exe /hal=halmacpi.dll
    Note that the filenames must be short (8.3) names.
    You can add additional options for debugging (as specified in the WinDbg/KD help).

Debugging WRK
    The WinDBG/KD debuggers will work with the WRK.  The documentation is pretty thorough, and
    includes information about how to debug across a serial port, locally (examining kernel 
    data from user-mode), and debugging kernels running on VirtualPC.

    Version 6.6.3.5 of the WinDBG/KD debuggers is available with the Curriculum Resource Kit
    Tools ("CurriculumResourceKit-CRK\CRKTools\Debugging Tools" directory on the CD).  
    The latest version of the Windows Debugging Tools can be downloaded from
    http://www.microsoft.com/whdc/devtools/debugging.
