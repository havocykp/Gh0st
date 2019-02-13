/*++ BUILD Version: 0010    // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    arc.h

Abstract:

    This header file defines the ARC system firmware interface and the
    NT structures that are dependent on ARC types.

--*/

#ifndef _ARC_
#define _ARC_

#include "profiles.h"

//
// Define ARC_STATUS type.
//

typedef ULONG ARC_STATUS;

//
// Define the firmware entry point numbers.
//

// begin_ntddk
//
// Define configuration routine types.
//
// Configuration information.
//
// end_ntddk

typedef enum _CONFIGURATION_CLASS {
    SystemClass,
    ProcessorClass,
    CacheClass,
    AdapterClass,
    ControllerClass,
    PeripheralClass,
    MemoryClass,
    MaximumClass
} CONFIGURATION_CLASS, *PCONFIGURATION_CLASS;

// begin_ntddk

typedef enum _CONFIGURATION_TYPE {
    ArcSystem,
    CentralProcessor,
    FloatingPointProcessor,
    PrimaryIcache,
    PrimaryDcache,
    SecondaryIcache,
    SecondaryDcache,
    SecondaryCache,
    EisaAdapter,
    TcAdapter,
    ScsiAdapter,
    DtiAdapter,
    MultiFunctionAdapter,
    DiskController,
    TapeController,
    CdromController,
    WormController,
    SerialController,
    NetworkController,
    DisplayController,
    ParallelController,
    PointerController,
    KeyboardController,
    AudioController,
    OtherController,
    DiskPeripheral,
    FloppyDiskPeripheral,
    TapePeripheral,
    ModemPeripheral,
    MonitorPeripheral,
    PrinterPeripheral,
    PointerPeripheral,
    KeyboardPeripheral,
    TerminalPeripheral,
    OtherPeripheral,
    LinePeripheral,
    NetworkPeripheral,
    SystemMemory,
    DockingInformation,
    RealModeIrqRoutingTable,
    RealModePCIEnumeration,
    MaximumType
} CONFIGURATION_TYPE, *PCONFIGURATION_TYPE;

// end_ntddk

typedef struct _CONFIGURATION_COMPONENT {
    CONFIGURATION_CLASS Class;
    CONFIGURATION_TYPE Type;
    DEVICE_FLAGS Flags;
    USHORT Version;
    USHORT Revision;
    ULONG Key;
    ULONG AffinityMask;
    ULONG ConfigurationDataLength;
    ULONG IdentifierLength;
    CHAR * FIRMWARE_PTR Identifier;
} CONFIGURATION_COMPONENT, * FIRMWARE_PTR PCONFIGURATION_COMPONENT;

//
// System information.
//

typedef struct _SYSTEM_ID {
    CHAR VendorId[8];
    CHAR ProductId[8];
} SYSTEM_ID, * FIRMWARE_PTR PSYSTEM_ID;

//
// Memory information.
//

typedef enum _MEMORY_TYPE {
    MemoryExceptionBlock,
    MemorySystemBlock,
    MemoryFree,
    MemoryBad,
    MemoryLoadedProgram,
    MemoryFirmwareTemporary,
    MemoryFirmwarePermanent,
    MemoryFreeContiguous,
    MemorySpecialMemory,
    MemoryMaximum
} MEMORY_TYPE;

typedef struct _MEMORY_DESCRIPTOR {
    MEMORY_TYPE MemoryType;
    ULONG BasePage;
    ULONG PageCount;
} MEMORY_DESCRIPTOR, * FIRMWARE_PTR PMEMORY_DESCRIPTOR;

//
// Define configuration data structure used in all systems.
//

typedef struct _CONFIGURATION_COMPONENT_DATA {
    struct _CONFIGURATION_COMPONENT_DATA *Parent;
    struct _CONFIGURATION_COMPONENT_DATA *Child;
    struct _CONFIGURATION_COMPONENT_DATA *Sibling;
    CONFIGURATION_COMPONENT ComponentEntry;
    PVOID ConfigurationData;
} CONFIGURATION_COMPONENT_DATA, *PCONFIGURATION_COMPONENT_DATA;

//
// Define generic display configuration data structure.
//

typedef struct _MONITOR_CONFIGURATION_DATA {
    USHORT Version;
    USHORT Revision;
    USHORT HorizontalResolution;
    USHORT HorizontalDisplayTime;
    USHORT HorizontalBackPorch;
    USHORT HorizontalFrontPorch;
    USHORT HorizontalSync;
    USHORT VerticalResolution;
    USHORT VerticalBackPorch;
    USHORT VerticalFrontPorch;
    USHORT VerticalSync;
    USHORT HorizontalScreenSize;
    USHORT VerticalScreenSize;
} MONITOR_CONFIGURATION_DATA, *PMONITOR_CONFIGURATION_DATA;

//
// Define memory allocation structures used in all systems.
//

typedef enum _TYPE_OF_MEMORY {
    LoaderExceptionBlock = MemoryExceptionBlock,            //  0
    LoaderSystemBlock = MemorySystemBlock,                  //  1
    LoaderFree = MemoryFree,                                //  2
    LoaderBad = MemoryBad,                                  //  3
    LoaderLoadedProgram = MemoryLoadedProgram,              //  4
    LoaderFirmwareTemporary = MemoryFirmwareTemporary,      //  5
    LoaderFirmwarePermanent = MemoryFirmwarePermanent,      //  6
    LoaderOsloaderHeap,                                     //  7
    LoaderOsloaderStack,                                    //  8
    LoaderSystemCode,                                       //  9
    LoaderHalCode,                                          //  a
    LoaderBootDriver,                                       //  b
    LoaderConsoleInDriver,                                  //  c
    LoaderConsoleOutDriver,                                 //  d
    LoaderStartupDpcStack,                                  //  e
    LoaderStartupKernelStack,                               //  f
    LoaderStartupPanicStack,                                // 10
    LoaderStartupPcrPage,                                   // 11
    LoaderStartupPdrPage,                                   // 12
    LoaderRegistryData,                                     // 13
    LoaderMemoryData,                                       // 14
    LoaderNlsData,                                          // 15
    LoaderSpecialMemory,                                    // 16
    LoaderBBTMemory,                                        // 17
    LoaderReserve,                                          // 18
    LoaderXIPRom,                                           // 19
    LoaderHALCachedMemory,                                  // 1a
    LoaderLargePageFiller,                                  // 1b
    LoaderMaximum                                           // 1c
} TYPE_OF_MEMORY;

typedef struct _MEMORY_ALLOCATION_DESCRIPTOR {
    LIST_ENTRY ListEntry;
    TYPE_OF_MEMORY MemoryType;
    ULONG BasePage;
    ULONG PageCount;
} MEMORY_ALLOCATION_DESCRIPTOR, *PMEMORY_ALLOCATION_DESCRIPTOR;


//
// Define loader parameter block structure.
//

typedef struct _NLS_DATA_BLOCK {
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
} NLS_DATA_BLOCK, *PNLS_DATA_BLOCK;

typedef struct _ARC_DISK_SIGNATURE {
    LIST_ENTRY ListEntry;
    ULONG   Signature;
    PCHAR   ArcName;
    ULONG   CheckSum;
    BOOLEAN ValidPartitionTable;
    BOOLEAN xInt13;
    BOOLEAN IsGpt;
    UCHAR Reserved;
    UCHAR GptSignature[16];
} ARC_DISK_SIGNATURE, *PARC_DISK_SIGNATURE;

typedef struct _ARC_DISK_INFORMATION {
    LIST_ENTRY DiskSignatures;
} ARC_DISK_INFORMATION, *PARC_DISK_INFORMATION;

typedef struct _I386_LOADER_BLOCK {

#if defined(_X86_) || defined(_AMD64_)

    PVOID CommonDataArea;
    ULONG MachineType;      // Temporary only
    ULONG VirtualBias;		// 当前内核基地址相对于2GB的偏移量

#else

    ULONG PlaceHolder;

#endif

} I386_LOADER_BLOCK, *PI386_LOADER_BLOCK;

typedef struct _LOADER_PARAMETER_EXTENSION {
    ULONG   Size; // set to sizeof (struct _LOADER_PARAMETER_EXTENSION)
    PROFILE_PARAMETER_BLOCK Profile;
    ULONG   MajorVersion;
    ULONG   MinorVersion;
    PVOID   InfFileImage;   // Inf used to identify "broken" machines.
    ULONG   InfFileSize;

    //
    // Pointer to the triage block, if present.
    //

    PVOID TriageDumpBlock;

    ULONG LoaderPagesSpanned;   // Virtual Memory spanned by the loader
                                // that MM cannot recover the VA for.
    struct _HEADLESS_LOADER_BLOCK *HeadlessLoaderBlock;

    struct _SMBIOS_TABLE_HEADER *SMBiosEPSHeader;

    PVOID   DrvDBImage;   // Database used to identify "broken" drivers.
    ULONG   DrvDBSize;

    // If booting from the Network (PXE) then we will
    // save the Network boot params in this loader block
    struct _NETWORK_LOADER_BLOCK *NetworkLoaderBlock;

#if defined(_X86_)

    //
    // Pointers to IRQL translation tables that reside in the HAL
    // and are exposed to the kernel for use in the "inlined IRQL"
    // build
    //

    PUCHAR HalpIRQLToTPR;
    PUCHAR HalpVectorToIRQL;

#endif

    //
    // Firmware Location
    //
    LIST_ENTRY  FirmwareDescriptorListHead;

    //
    // Pointer to the in-memory copy of override ACPI tables.
    // The override table file is a simple binary file with one or more ACPI tables laid
    // out one after another.
    //
    PVOID   AcpiTable;

    //
    // Size of override ACPI tables in bytes.
    //
    ULONG   AcpiTableSize;


} LOADER_PARAMETER_EXTENSION, *PLOADER_PARAMETER_EXTENSION;

struct _SETUP_LOADER_BLOCK;
struct _HEADLESS_LOADER_BLOCK;
struct _SMBIOS_TABLE_HEADER;

typedef struct _NETWORK_LOADER_BLOCK {

    // Binary contents of the entire DHCP Acknowledgment
    // packet received by PXE.
    PUCHAR DHCPServerACK;
    ULONG DHCPServerACKLength;

    // Binary contents of the entire BINL Reply
    // packet received by PXE.
    PUCHAR BootServerReplyPacket;
    ULONG BootServerReplyPacketLength;

} NETWORK_LOADER_BLOCK, * PNETWORK_LOADER_BLOCK;

typedef struct _LOADER_PARAMETER_BLOCK {
    LIST_ENTRY LoadOrderListHead;	// 加载的模块链表，每个元素都为
    								// KLDR_DATA_TABLE_ENTRY
    LIST_ENTRY MemoryDescriptorListHead;	// 内存描述符链表，每个元素都为
    										// MEMORY_ALLOCATION_DESCRIPTOR
    LIST_ENTRY BootDriverListHead;			// 引导驱动程序链表，每个元素都为
    										// BOOT_DRIVER_LIST_ENTRY
    ULONG_PTR KernelStack;					// 内核栈顶
    ULONG_PTR Prcb;							// 进程环境，指向一个进程控制块
    ULONG_PTR Process;						// 初始进程，EPROCESS
    ULONG_PTR Thread;						// 初始线程，ETHREAD
    ULONG RegistryLength;					// 系统储巢的长度
    PVOID RegistryBase;						// 系统储巢的基地址
    PCONFIGURATION_COMPONENT_DATA ConfigurationRoot;	// 配置树，包含ISA、磁盘
    													// 和ACPI的配置数据
    PCHAR ArcBootDeviceName;				// 引导分区的ARC名称
    PCHAR ArcHalDeviceName;					// 系统分区的ARC名称
    PCHAR NtBootPathName;					// OS目录的路径名称
    PCHAR NtHalPathName;					// OS加载器的路径名称
    PCHAR LoadOptions;						// 引导选项，来自boot.ini
    PNLS_DATA_BLOCK NlsData;				// 包含ANSI代码页、OEM代码页和Unicode码表
    PARC_DISK_INFORMATION ArcDiskInformation;		// 所有磁盘的签名结构
    PVOID OemFontFile;						// OEM字体文件
    struct _SETUP_LOADER_BLOCK *SetupLoaderBlock;	// 网络引导或文字模式安装引导
    PLOADER_PARAMETER_EXTENSION Extension;	// 扩展部分

    union {
        I386_LOADER_BLOCK I386;
        // ALPHA_LOADER_BLOCK Alpha;		
        // IA64_LOADER_BLOCK Ia64;
    } u;


} LOADER_PARAMETER_BLOCK, *PLOADER_PARAMETER_BLOCK;

#endif // _ARC_

