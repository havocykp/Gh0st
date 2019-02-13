# 1 "pebteb.h"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "pebteb.h"
# 75 "pebteb.h"
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union {
        BOOLEAN BitField;
        struct {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN SpareBits : 7;
         };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    struct _RTL_CRITICAL_SECTION* FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID SparePtr2;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG SpareUlong;
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PPVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;



    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;





    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
# 134 "pebteb.h"
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PPVOID ProcessHeaps;



    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    struct _RTL_CRITICAL_SECTION* LoaderLock;






    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];




    ULONG SessionId;




    ULARGE_INTEGER AppCompatFlags;




    ULARGE_INTEGER AppCompatFlagsUser;




    PVOID pShimData;




    PVOID AppCompatInfo;




    UNICODE_STRING CSDVersion;




    const struct _ACTIVATION_CONTEXT_DATA * ActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP * ProcessAssemblyStorageMap;
    const struct _ACTIVATION_CONTEXT_DATA * SystemDefaultActivationContextData;
    struct _ASSEMBLY_STORAGE_MAP * SystemAssemblyStorageMap;




    SIZE_T MinimumStackCommit;





    PPVOID FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;
} PEB, * PPEB;







typedef struct _ACTIVATION_CONTEXT_STACK {
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME * ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef const ACTIVATION_CONTEXT_STACK * PCACTIVATION_CONTEXT_STACK;



typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

typedef const TEB_ACTIVE_FRAME_CONTEXT *PCTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT_EX {
    TEB_ACTIVE_FRAME_CONTEXT BasicContext;
    PCSTR SourceLocation;
} TEB_ACTIVE_FRAME_CONTEXT_EX, *PTEB_ACTIVE_FRAME_CONTEXT_EX;

typedef const TEB_ACTIVE_FRAME_CONTEXT_EX *PCTEB_ACTIVE_FRAME_CONTEXT_EX;



typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PCTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

typedef const TEB_ACTIVE_FRAME *PCTEB_ACTIVE_FRAME;

typedef struct _TEB_ACTIVE_FRAME_EX {
    TEB_ACTIVE_FRAME BasicFrame;
    PVOID ExtensionIdentifier;
} TEB_ACTIVE_FRAME_EX, *PTEB_ACTIVE_FRAME_EX;

typedef const TEB_ACTIVE_FRAME_EX *PCTEB_ACTIVE_FRAME_EX;






typedef struct _TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID SystemReserved1[54];
    NTSTATUS ExceptionCode;

    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;

    UCHAR SpareBytes1[28];



    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];
    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    ULONG LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];
    PVOID DeallocationStack;
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorMode;
    PVOID Instrumentation[14];
    PVOID SubProcessTag;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;
    BOOLEAN InDbgPrint;
    BOOLEAN FreeStackOnTermination;
    BOOLEAN HasFiberData;
    BOOLEAN IdealProcessor;
    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    ULONG_PTR SparePointer1;
    ULONG_PTR SoftPatchPtr1;
    ULONG_PTR SoftPatchPtr2;
    PPVOID TlsExpansionSlots;





    PVOID DeallocationBStore;
    PVOID BStoreLimit;

    LCID ImpersonationLocale;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapVirtualAffinity;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;
    BOOLEAN SafeThunkCall;
    BOOLEAN BooleanSpare [3];

} TEB, *PTEB;
