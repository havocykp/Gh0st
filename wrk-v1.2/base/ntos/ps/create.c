/*++

Copyright (c) Microsoft Corporation. All rights reserved. 

You may only use this code if you agree to the terms of the Windows Research Kernel Source Code License agreement (see License.txt).
If you do not agree to the terms, do not use the code.


Module Name:

    create.c

Abstract:

    Process and Thread Creation.

--*/

#include "psp.h"

ULONG
PspUnhandledExceptionInSystemThread(
    IN PEXCEPTION_POINTERS ExceptionPointers
    );

#pragma alloc_text(PAGE, NtCreateThread)
#pragma alloc_text(PAGE, PsCreateSystemThread)
#pragma alloc_text(PAGE, PspCreateThread)
#pragma alloc_text(PAGE, NtCreateProcess)
#pragma alloc_text(PAGE, NtCreateProcessEx)
#pragma alloc_text(PAGE, PsCreateSystemProcess)
#pragma alloc_text(PAGE, PspCreateProcess)
#pragma alloc_text(PAGE, PsSetCreateProcessNotifyRoutine)
#pragma alloc_text(PAGE, PsSetCreateThreadNotifyRoutine)
#pragma alloc_text(PAGE, PsRemoveCreateThreadNotifyRoutine)
#pragma alloc_text(PAGE, PspUserThreadStartup)
#pragma alloc_text(PAGE, PsSetLoadImageNotifyRoutine)
#pragma alloc_text(PAGE, PsRemoveLoadImageNotifyRoutine)
#pragma alloc_text(PAGE, PsCallImageNotifyRoutines)
#pragma alloc_text(PAGE, PspUnhandledExceptionInSystemThread)
#pragma alloc_text(PAGE, PspSystemThreadStartup)
#pragma alloc_text(PAGE, PspImageNotifyTest)

extern UNICODE_STRING CmCSDVersionString;

#ifdef ALLOC_DATA_PRAGMA

#pragma data_seg("PAGEDATA")

#endif

LCID PsDefaultSystemLocaleId = 0;
LCID PsDefaultThreadLocaleId = 0;
LANGID PsDefaultUILanguageId = 0;
LANGID PsInstallUILanguageId = 0;

//
// The following two globals are present to make it easier to change
// working set sizes when debugging.
//

ULONG PsMinimumWorkingSet = 20;
ULONG PsMaximumWorkingSet = 45;

BOOLEAN PsImageNotifyEnabled = FALSE;

#ifdef ALLOC_DATA_PRAGMA

#pragma data_seg()

#endif

//
// Define the local storage for the process lock fast mutex.
//

NTSTATUS
NtCreateThread(
    __out PHANDLE ThreadHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE ProcessHandle,
    __out PCLIENT_ID ClientId,
    __in PCONTEXT ThreadContext,
    __in PINITIAL_TEB InitialTeb,
    __in BOOLEAN CreateSuspended
    )

/*++

Routine Description:

    This system service API creates and initializes a thread object.

Arguments:

    ThreadHandle - Returns the handle for the new thread.

    DesiredAccess - Supplies the desired access modes to the new thread.

    ObjectAttributes - Supplies the object attributes of the new thread.

    ProcessHandle - Supplies a handle to the process that the thread is being
                    created within.

    ClientId - Returns the CLIENT_ID of the new thread.

    ThreadContext - Supplies an initial context for the new thread.

    InitialTeb - Supplies the initial contents for the thread's TEB.

    CreateSuspended - Supplies a value that controls whether or not a
                      thread is created in a suspended state.

--*/

{
    NTSTATUS Status;
    INITIAL_TEB CapturedInitialTeb;

    PAGED_CODE();


    //
    // Probe all arguments
    //

    try {
        if (KeGetPreviousMode () != KernelMode) {
            ProbeForWriteHandle (ThreadHandle);

            if (ARGUMENT_PRESENT (ClientId)) {
                ProbeForWriteSmallStructure (ClientId, sizeof (CLIENT_ID), sizeof (ULONG));
            }

            if (ARGUMENT_PRESENT (ThreadContext) ) {
                ProbeForReadSmallStructure (ThreadContext, sizeof (CONTEXT), CONTEXT_ALIGN);
            } else {
                return STATUS_INVALID_PARAMETER;
            }
            ProbeForReadSmallStructure (InitialTeb, sizeof (InitialTeb->OldInitialTeb), sizeof (ULONG));
        }

        CapturedInitialTeb.OldInitialTeb = InitialTeb->OldInitialTeb;
        if (CapturedInitialTeb.OldInitialTeb.OldStackBase == NULL &&
            CapturedInitialTeb.OldInitialTeb.OldStackLimit == NULL) {
            //
            // Since the structure size here is less than 64k we don't need to reprobe
            //
            CapturedInitialTeb = *InitialTeb;
        }
    } except (ExSystemExceptionFilter ()) {
        return GetExceptionCode ();
    }

    Status = PspCreateThread (ThreadHandle,
                              DesiredAccess,
                              ObjectAttributes,
                              ProcessHandle,
                              NULL,
                              ClientId,
                              ThreadContext,
                              &CapturedInitialTeb,
                              CreateSuspended,
                              NULL,
                              NULL);

    return Status;
}

NTSTATUS
PsCreateSystemThread(
    __out PHANDLE ThreadHandle,
    __in ULONG DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in_opt  HANDLE ProcessHandle,
    __out_opt PCLIENT_ID ClientId,
    __in PKSTART_ROUTINE StartRoutine,
    __in_opt PVOID StartContext
    )

/*++

Routine Description:

    This routine creates and starts a system thread.

Arguments:

    ThreadHandle - Returns the handle for the new thread.

    DesiredAccess - Supplies the desired access modes to the new thread.

    ObjectAttributes - Supplies the object attributes of the new thread.

    ProcessHandle - Supplies a handle to the process that the thread is being
                    created within.  If this parameter is not specified, then
                    the initial system process is used.

    ClientId - Returns the CLIENT_ID of the new thread.

    StartRoutine - Supplies the address of the system thread start routine.

    StartContext - Supplies context for a system thread start routine.

--*/

{
    NTSTATUS Status;
    HANDLE SystemProcess;
    PEPROCESS ProcessPointer;

    PAGED_CODE();

    ProcessPointer = NULL;

    if (ARGUMENT_PRESENT (ProcessHandle)) {
        SystemProcess = ProcessHandle;
    } else {
        SystemProcess = NULL;
        ProcessPointer = PsInitialSystemProcess;
    }

    Status = PspCreateThread (ThreadHandle,
                              DesiredAccess,
                              ObjectAttributes,
                              SystemProcess,
                              ProcessPointer,
                              ClientId,
                              NULL,
                              NULL,
                              FALSE,
                              StartRoutine,
                              StartContext);

    return Status;
}

BOOLEAN PsUseImpersonationToken = FALSE;


NTSTATUS
PspCreateThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PEPROCESS ProcessPointer,
    OUT PCLIENT_ID ClientId OPTIONAL,
    IN PCONTEXT ThreadContext OPTIONAL,
    IN PINITIAL_TEB InitialTeb OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN PKSTART_ROUTINE StartRoutine OPTIONAL,
    IN PVOID StartContext
    )

/*++

Routine Description:

    This routine creates and initializes a thread object. It implements the
    foundation for NtCreateThread and for PsCreateSystemThread.

Arguments:

    ThreadHandle - Returns the handle for the new thread.

    DesiredAccess - Supplies the desired access modes to the new thread.

    ObjectAttributes - Supplies the object attributes of the new thread.

    ProcessHandle - Supplies a handle to the process that the thread is being
                    created within.

    ClientId - Returns the CLIENT_ID of the new thread.

    ThreadContext - Supplies a pointer to a context frame that represents the
                initial user-mode context for a user-mode thread. The absence
                of this parameter indicates that a system thread is being
                created.

    InitialTeb - Supplies the contents of certain fields for the new threads
                 TEB. This parameter is only examined if both a trap and
                 exception frame were specified.

    CreateSuspended - Supplies a value that controls whether or not a user-mode
                      thread is created in a suspended state.

    StartRoutine - Supplies the address of the system thread start routine.

    StartContext - Supplies context for a system thread start routine.

--*/

{

    HANDLE_TABLE_ENTRY CidEntry;
    NTSTATUS Status;
    PETHREAD Thread;
    PETHREAD CurrentThread;
    PEPROCESS Process;
    PTEB Teb;
    KPROCESSOR_MODE PreviousMode;
    HANDLE LocalThreadHandle;
    BOOLEAN AccessCheck;
    BOOLEAN MemoryAllocated;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    NTSTATUS accesst;
    LARGE_INTEGER CreateTime;
    ULONG OldActiveThreads;
    PEJOB Job;
    AUX_ACCESS_DATA AuxData;
    PACCESS_STATE AccessState;
    ACCESS_STATE LocalAccessState;

    PAGED_CODE();

	// 1. 获取当前线程对象
    CurrentThread = PsGetCurrentThread ();

	// 2. 获取模式
    if (StartRoutine != NULL) {
        PreviousMode = KernelMode;//内核模式
    } else {
		// 从当前线程的tcbp中获取模式
        PreviousMode = KeGetPreviousModeByThread (&CurrentThread->Tcb); // 用户模式
    }

    Teb = NULL;

    Thread = NULL;
    Process = NULL;

    if (ProcessHandle != NULL) {
        //
        // Process object reference count is biased by one for each thread.
        // This accounts for the pointer given to the kernel that remains
        // in effect until the thread terminates (and becomes signaled)
        //
		// 3. 根据进程句柄获取进程对象.
        Status = ObReferenceObjectByHandle (ProcessHandle,
                                            PROCESS_CREATE_THREAD,
                                            PsProcessType,
                                            PreviousMode,
                                            &Process,
                                            NULL);
    } else {
        if (StartRoutine != NULL) {
            ObReferenceObject (ProcessPointer);
            Process = ProcessPointer;
            Status = STATUS_SUCCESS;
        } else {
            Status = STATUS_INVALID_HANDLE;
        }
    }

    if (!NT_SUCCESS (Status)) {
        return Status;
    }

    //
    // If the previous mode is user and the target process is the system
    // process, then the operation cannot be performed.
    //
	// 如果模式是用户模式,且创建线程的进程是系统进程,则返回失败.
    if ((PreviousMode != KernelMode) && (Process == PsInitialSystemProcess)) {
        ObDereferenceObject (Process);
        return STATUS_INVALID_HANDLE;
    }
	// 4. 创建一个内核线程对象ETHREAD.并把整个ETHREAD结构清零
    Status = ObCreateObject (PreviousMode,
                             PsThreadType,  // 线程对象类型
                             ObjectAttributes,
                             PreviousMode,
                             NULL,
                             sizeof(ETHREAD),
                             0,
                             0,
                             &Thread);

    if (!NT_SUCCESS (Status)) {
        ObDereferenceObject (Process);
        return Status;
    }

    RtlZeroMemory (Thread, sizeof (ETHREAD));

    //
    // Initialize rundown protection for cross thread TEB refs etc.
    // 5. 锁住进程, 防止在创建线程时进程无故退出.
    ExInitializeRundownProtection (&Thread->RundownProtect);

    //
    // Assign this thread to the process so that from now on
    // we don't have to dereference in error paths.
    // 6.1 设置新线程的父进程对象.
    Thread->ThreadsProcess = Process;
	// 6.2 设置新线程的父进程pid.
    Thread->Cid.UniqueProcess = Process->UniqueProcessId;

    CidEntry.Object = Thread;
    CidEntry.GrantedAccess = 0;
	// 6.3 在CID全局句柄表中创建一个句柄, 并将得到的句柄作为新线程的id
    Thread->Cid.UniqueThread = ExCreateHandle (PspCidTable, &CidEntry);

    if (Thread->Cid.UniqueThread == NULL) {
        ObDereferenceObject (Thread);
        return (STATUS_INSUFFICIENT_RESOURCES);
    }

	//////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////
	// 7. 初始化一些字段.

    //
    // Initialize Mm
    //
    Thread->ReadClusterSize = MmReadClusterSize;

    //
    // Initialize LPC
    //
    KeInitializeSemaphore (&Thread->LpcReplySemaphore, 0L, 1L);
    InitializeListHead (&Thread->LpcReplyChain);

    //
    // Initialize Io
    //
    InitializeListHead (&Thread->IrpList);

    //
    // Initialize Registry
    //
    InitializeListHead (&Thread->PostBlockList);

    //
    // Initialize the thread lock
    //
    PspInitializeThreadLock (Thread);

    KeInitializeSpinLock (&Thread->ActiveTimerListLock);
    InitializeListHead (&Thread->ActiveTimerListHead);


    if (!ExAcquireRundownProtection (&Process->RundownProtect)) {
        ObDereferenceObject (Thread);
        return STATUS_PROCESS_IS_TERMINATING;
    }

	
    if (ARGUMENT_PRESENT (ThreadContext)) {

        //
        // User-mode thread. Create TEB etc
        // 8. 如果线程环境不为NULL,则创建用户模式的线程

		// 8.1 创建TEB
        Status = MmCreateTeb (Process, InitialTeb, &Thread->Cid, &Teb);
        if (!NT_SUCCESS (Status)) {
            ExReleaseRundownProtection (&Process->RundownProtect);
            ObDereferenceObject (Thread);
            return Status;
        }


        try {
            //
            // Initialize kernel thread object for user mode thread.
            // 8.2 将线程环境的RIP赋值给StartAddress,作为线程启动地址.
            Thread->StartAddress = (PVOID)CONTEXT_TO_PROGRAM_COUNTER(ThreadContext);

#if defined(_AMD64_)
			// 8.3 将rdx赋值给Win32StartAddress
            Thread->Win32StartAddress = (PVOID)ThreadContext->Rdx;

#elif defined(_X86_)
			// 或者将eax赋值给Win32StartAddress
            Thread->Win32StartAddress = (PVOID)ThreadContext->Eax;

#else

#error "no target architecture"

#endif

        } except (EXCEPTION_EXECUTE_HANDLER) {

            Status = GetExceptionCode();
        }

        if (NT_SUCCESS (Status)) {
			// 8.4 根据进程对象中的信息初始化新线程的一些属性,包括同步相关的各个字段,系统服务表,
			//     APC和定时器.
            Status = KeInitThread (&Thread->Tcb,
                                   NULL,
                                   PspUserThreadStartup,
                                   (PKSTART_ROUTINE)NULL,
                                   Thread->StartAddress,
                                   ThreadContext,
                                   Teb,
                                   &Process->Pcb);
       }


    } else {
		//8. 否则创建系统线程
        Teb = NULL;
        //
        // Set the system thread bit thats kept for all time
        //8.1 设置线程的一些标志位
        PS_SET_BITS (&Thread->CrossThreadFlags, PS_CROSS_THREAD_FLAGS_SYSTEM);

        //
        // Initialize kernel thread object for kernel mode thread.
        //
		//8.2 设置启动地址
        Thread->StartAddress = (PKSTART_ROUTINE) StartRoutine;
		//8.3 初始化新线程信息.
        Status = KeInitThread (&Thread->Tcb,
                               NULL,
                               PspSystemThreadStartup,
                               StartRoutine,
                               StartContext,
                               NULL,
                               NULL,
                               &Process->Pcb);
    }


    if (!NT_SUCCESS (Status)) {
        if (Teb != NULL) {
            MmDeleteTeb(Process, Teb);
        }
        ExReleaseRundownProtection (&Process->RundownProtect);
        ObDereferenceObject (Thread);
        return Status;
    }

    PspLockProcessExclusive (Process, CurrentThread);
    //
    // Process is exiting or has had delete process called
    // We check the calling threads termination status so we
    // abort any thread creates while ExitProcess is being called --
    // but the call is blocked only if the new thread would be created
    // in the terminating thread's process.
    //
    if ((Process->Flags&PS_PROCESS_FLAGS_PROCESS_DELETE) != 0 ||
        (((CurrentThread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_TERMINATED) != 0) &&
        (ThreadContext != NULL) &&
        (THREAD_TO_PROCESS(CurrentThread) == Process))) {

        PspUnlockProcessExclusive (Process, CurrentThread);

        KeUninitThread (&Thread->Tcb);

        if (Teb != NULL) {
            MmDeleteTeb(Process, Teb);
        }
        ExReleaseRundownProtection (&Process->RundownProtect);
        ObDereferenceObject(Thread);

        return STATUS_PROCESS_IS_TERMINATING;
    }

	//9. 将进程的活动线程自增
    OldActiveThreads = Process->ActiveThreads++;
	// 10. 将线程加入到进程的线程链表中.
    InsertTailList (&Process->ThreadListHead, &Thread->ThreadListEntry);

	// 初始化一些其它域: 线程调度相关的优先级,时限设置,处理器亲和性. 
    KeStartThread (&Thread->Tcb);

    PspUnlockProcessExclusive (Process, CurrentThread);

    ExReleaseRundownProtection (&Process->RundownProtect);

    //
    // Failures that occur after this point cause the thread to
    // go through PspExitThread
    //

	// 11. 如果是进程中的第一个线程, 则触发进程创建通知
    if (OldActiveThreads == 0) {
        PERFINFO_PROCESS_CREATE (Process);
		// 准备调用进程创建的通知函数
        if (PspCreateProcessNotifyRoutineCount != 0) {
            ULONG i;
            PEX_CALLBACK_ROUTINE_BLOCK CallBack;
            PCREATE_PROCESS_NOTIFY_ROUTINE Rtn;

            for (i=0; i<PSP_MAX_CREATE_PROCESS_NOTIFY; i++) {
                CallBack = ExReferenceCallBackBlock (&PspCreateProcessNotifyRoutine[i]);
                if (CallBack != NULL) {
					// 获取回调函数地址
                    Rtn = (PCREATE_PROCESS_NOTIFY_ROUTINE) ExGetCallBackBlockRoutine (CallBack);
					// 将进程的父进程id,新进程的id传入并调用通知函数
                    Rtn (Process->InheritedFromUniqueProcessId,
                         Process->UniqueProcessId,
                         TRUE);
                    ExDereferenceCallBackBlock (&PspCreateProcessNotifyRoutine[i],
                                                CallBack);
                }
            }
        }
    }

    //
    // If the process has a job with a completion port,
    // AND if the process is really considered to be in the Job, AND
    // the process has not reported, report in
    //
    // This should really be done in add process to job, but can't
    // in this path because the process's ID isn't assigned until this point
    // in time
    // 12. 如果进程在作业对象内, 则对作业对象进行处理.
    Job = Process->Job;
    if (Job != NULL && Job->CompletionPort &&
        !(Process->JobStatus & (PS_JOB_STATUS_NOT_REALLY_ACTIVE|PS_JOB_STATUS_NEW_PROCESS_REPORTED))) {

        PS_SET_BITS (&Process->JobStatus, PS_JOB_STATUS_NEW_PROCESS_REPORTED);

        KeEnterCriticalRegionThread (&CurrentThread->Tcb);
        ExAcquireResourceSharedLite (&Job->JobLock, TRUE);
        if (Job->CompletionPort != NULL) {
            IoSetIoCompletion (Job->CompletionPort,
                               Job->CompletionKey,
                               (PVOID)Process->UniqueProcessId,
                               STATUS_SUCCESS,
                               JOB_OBJECT_MSG_NEW_PROCESS,
                               FALSE);
        }
        ExReleaseResourceLite (&Job->JobLock);
        KeLeaveCriticalRegionThread (&CurrentThread->Tcb);
    }

    PERFINFO_THREAD_CREATE(Thread, InitialTeb);

    //
    // Notify registered callout routines of thread creation.
    //
	// 13. 调用线程创建通知函数
    if (PspCreateThreadNotifyRoutineCount != 0) {
        ULONG i;
        PEX_CALLBACK_ROUTINE_BLOCK CallBack;
        PCREATE_THREAD_NOTIFY_ROUTINE Rtn;

        for (i = 0; i < PSP_MAX_CREATE_THREAD_NOTIFY; i++) {
            CallBack = ExReferenceCallBackBlock (&PspCreateThreadNotifyRoutine[i]);
            if (CallBack != NULL) {
                Rtn = (PCREATE_THREAD_NOTIFY_ROUTINE) ExGetCallBackBlockRoutine (CallBack);
                Rtn (Thread->Cid.UniqueProcess,
                     Thread->Cid.UniqueThread,
                     TRUE);
                ExDereferenceCallBackBlock (&PspCreateThreadNotifyRoutine[i],
                                            CallBack);
            }
        }
    }


    //
    // Reference count of thread is biased once for itself and once for the handle if we create it.
    //
	// 14. 设置引用计数
    ObReferenceObjectEx (Thread, 2);
	// 15. 如果指定在创建时挂起线程
    if (CreateSuspended) {
        try {
            KeSuspendThread (&Thread->Tcb); // 挂起线程.
        } except ((GetExceptionCode () == STATUS_SUSPEND_COUNT_EXCEEDED)?
                     EXCEPTION_EXECUTE_HANDLER :
                     EXCEPTION_CONTINUE_SEARCH) {
        }
        //
        // If deletion was started after we suspended then wake up the thread
        //
        if (Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_TERMINATED) {
            KeForceResumeThread (&Thread->Tcb);
        }
    }

    AccessState = NULL;
    if (!PsUseImpersonationToken) {
        AccessState = &LocalAccessState;
		// 创建一个访问状态结构 AccessState
        Status = SeCreateAccessStateEx (NULL,
                                        ARGUMENT_PRESENT (ThreadContext)?PsGetCurrentProcessByThread (CurrentThread) : Process,
                                        AccessState,
                                        &AuxData,
                                        DesiredAccess,
                                        &PsThreadType->TypeInfo.GenericMapping);

        if (!NT_SUCCESS (Status)) {
            PS_SET_BITS (&Thread->CrossThreadFlags,
                         PS_CROSS_THREAD_FLAGS_DEADTHREAD);

            if (CreateSuspended) {
                (VOID) KeResumeThread (&Thread->Tcb);
            }
            KeReadyThread (&Thread->Tcb);
            ObDereferenceObjectEx (Thread, 2);

            return Status;
        }
    }
	// 16. 将新线程句柄插入到当前进程的句柄表中
    Status = ObInsertObject (Thread,
                             AccessState,
                             DesiredAccess,
                             0,
                             NULL,
                             &LocalThreadHandle);

    if (AccessState != NULL) {
        SeDeleteAccessState (AccessState);
    }
	// ObInsertObject调用如果不成功，则终止新线程
    if (!NT_SUCCESS (Status)) {

        //
        // The insert failed. Terminate the thread.
        //

        //
        // This trick is used so that Dbgk doesn't report
        // events for dead threads
        //

        PS_SET_BITS (&Thread->CrossThreadFlags,
                     PS_CROSS_THREAD_FLAGS_DEADTHREAD);

        if (CreateSuspended) {
            KeResumeThread (&Thread->Tcb);
        }
	// 否则，设置好输出参数，准备返回
    } else {

        try {

            *ThreadHandle = LocalThreadHandle;
            if (ARGUMENT_PRESENT (ClientId)) {
                *ClientId = Thread->Cid;
            }
        } except(EXCEPTION_EXECUTE_HANDLER) {

            PS_SET_BITS (&Thread->CrossThreadFlags,
                         PS_CROSS_THREAD_FLAGS_DEADTHREAD);

            if (CreateSuspended) {
                (VOID) KeResumeThread (&Thread->Tcb);
            }
            KeReadyThread (&Thread->Tcb);
            ObDereferenceObject (Thread);
            ObCloseHandle (LocalThreadHandle, PreviousMode);
            return GetExceptionCode();
        }
    }
	// 17. 设置线程创建时间
    KeQuerySystemTime(&CreateTime);
    ASSERT ((CreateTime.HighPart & 0xf0000000) == 0);
    PS_SET_THREAD_CREATE_TIME(Thread, CreateTime);


    if ((Thread->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_DEADTHREAD) == 0) {
        Status = ObGetObjectSecurity (Thread,
                                      &SecurityDescriptor,
                                      &MemoryAllocated);
        if (!NT_SUCCESS (Status)) {
            //
            // This trick us used so that Dbgk doesn't report
            // events for dead threads
            //
            PS_SET_BITS (&Thread->CrossThreadFlags,
                         PS_CROSS_THREAD_FLAGS_DEADTHREAD);

            if (CreateSuspended) {
                KeResumeThread(&Thread->Tcb);
            }
            KeReadyThread (&Thread->Tcb);
            ObDereferenceObject (Thread);
            ObCloseHandle (LocalThreadHandle, PreviousMode);
            return Status;
        }

        //
        // Compute the subject security context
        //

        SubjectContext.ProcessAuditId = Process;
        SubjectContext.PrimaryToken = PsReferencePrimaryToken(Process);
        SubjectContext.ClientToken = NULL;

        AccessCheck = SeAccessCheck (SecurityDescriptor,
                                     &SubjectContext,
                                     FALSE,
                                     MAXIMUM_ALLOWED,
                                     0,
                                     NULL,
                                     &PsThreadType->TypeInfo.GenericMapping,
                                     PreviousMode,
                                     &Thread->GrantedAccess,
                                     &accesst);

        PsDereferencePrimaryTokenEx (Process, SubjectContext.PrimaryToken);

        ObReleaseObjectSecurity (SecurityDescriptor,
                                 MemoryAllocated);

        if (!AccessCheck) {
            Thread->GrantedAccess = 0;
        }

        Thread->GrantedAccess |= (THREAD_TERMINATE | THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION);

    } else {
        Thread->GrantedAccess = THREAD_ALL_ACCESS;
    }
	// 使新线程进入"就绪"状态，准备马上执行
	// 若此时进程尚未在内存中，则新线程的状态为"转移"，以等待换入内存后再执行
    KeReadyThread (&Thread->Tcb);
	// 引用计数减1，当前操作完成。返回
    ObDereferenceObject (Thread);

    return Status;
}

NTSTATUS
NtCreateProcess(
    __out PHANDLE ProcessHandle, // 输出参数，如果创建成功，则包含所创建的进程的句柄
    __in ACCESS_MASK DesiredAccess, // 包含对新进程的访问权限
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes, // 可选的指针参数，指定了进程对象的属性
    __in HANDLE ParentProcess, // 父进程的句柄，这是一个必需参数，不能为NULL
    						   // 并且调用者必须对该进程具有 PROCESS_CREATE_PROCESS访问权限
    __in BOOLEAN InheritObjectTable,
    __in_opt HANDLE SectionHandle, // 可选的句柄，指向一个内存区对象，代表该进程的映像文件
    __in_opt HANDLE DebugPort, // 可选句柄，指向一个端口对象，如果此句柄参数不为NULL，则此端口
    						   // 被赋为新进程的调试端口，否则，新进程没有调试端口
    __in_opt HANDLE ExceptionPort // 可选的句柄，指向一个端口对象，如果此句柄参数不为NULL，则
    							  // 此带你看被赋为新进程的异常端口，否则，新进程没有异常端口
    )
{
    ULONG Flags = 0;

    if ((ULONG_PTR)SectionHandle & 1) {
        Flags |= PROCESS_CREATE_FLAGS_BREAKAWAY;
    }

    if ((ULONG_PTR) DebugPort & 1) {
        Flags |= PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT;
    }

    if (InheritObjectTable) {
        Flags |= PROCESS_CREATE_FLAGS_INHERIT_HANDLES;
    }

    return NtCreateProcessEx (ProcessHandle,
                              DesiredAccess,
                              ObjectAttributes OPTIONAL,
                              ParentProcess,
                              Flags,
                              SectionHandle,
                              DebugPort,
                              ExceptionPort,
                              0);
}

NTSTATUS
NtCreateProcessEx(
    __out PHANDLE ProcessHandle,
    __in ACCESS_MASK DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in HANDLE ParentProcess,
    __in ULONG Flags,
    __in_opt HANDLE SectionHandle,
    __in_opt HANDLE DebugPort,
    __in_opt HANDLE ExceptionPort,
    __in ULONG JobMemberLevel
    )

/*++

Routine Description:

    This routine creates a process object.

Arguments:

    ProcessHandle - Returns the handle for the new process.

    DesiredAccess - Supplies the desired access modes to the new process.

    ObjectAttributes - Supplies the object attributes of the new process.
    .
    .
    .

--*/

{
    NTSTATUS Status;

    PAGED_CODE();

    if (KeGetPreviousMode() != KernelMode) {

        //
        // Probe all arguments
        //

        try {
            ProbeForWriteHandle (ProcessHandle);
        } except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode ();
        }
    }

    if (ARGUMENT_PRESENT (ParentProcess)) {
        Status = PspCreateProcess (ProcessHandle,
                                   DesiredAccess,
                                   ObjectAttributes,
                                   ParentProcess,
                                   Flags,
                                   SectionHandle,
                                   DebugPort,
                                   ExceptionPort,
                                   JobMemberLevel);
    } else {
        Status = STATUS_INVALID_PARAMETER;
    }

    return Status;
}


NTSTATUS
PsCreateSystemProcess(
    __out PHANDLE ProcessHandle,
    __in ULONG DesiredAccess,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes
    )

/*++

Routine Description:

    This routine creates a system process object. A system process
    has an address space that is initialized to an empty address space
    that maps the system.

    The process inherits its access token and other attributes from the
    initial system process. The process is created with an empty handle table.

Arguments:

    ProcessHandle - Returns the handle for the new process.

    DesiredAccess - Supplies the desired access modes to the new process.

    ObjectAttributes - Supplies the object attributes of the new process.

--*/

{
    NTSTATUS Status;

    PAGED_CODE();

    Status = PspCreateProcess (ProcessHandle,
                               DesiredAccess,
                               ObjectAttributes,
                               PspInitialSystemProcessHandle,
                               0,
                               NULL,
                               NULL,
                               NULL,
                               0);

    return Status;
}

NTSTATUS
PspCreateProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess OPTIONAL,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN ULONG JobMemberLevel
    )

/*++

Routine Description:

    This routine creates and initializes a process object.  It implements the
    foundation for NtCreateProcess and for system initialization process
    creation.

Arguments:

    ProcessHandle - Returns the handle for the new process.

    DesiredAccess - Supplies the desired access modes to the new process.

    ObjectAttributes - Supplies the object attributes of the new process.

    ParentProcess - Supplies a handle to the process' parent process.  If this
                    parameter is not specified, then the process has no parent
                    and is created using the system address space.

    Flags         - Process creation flags

    SectionHandle - Supplies a handle to a section object to be used to create
                    the process' address space.  If this parameter is not
                    specified, then the address space is simply a clone of the
                    parent process' address space.

    DebugPort - Supplies a handle to a port object that will be used as the
                process' debug port.

    ExceptionPort - Supplies a handle to a port object that will be used as the
                    process' exception port.

    JobMemberLevel - Level for a create process in a jobset

--*/

{

    NTSTATUS Status;
    PEPROCESS Process;
    PEPROCESS CurrentProcess;
    PEPROCESS Parent;
    PETHREAD CurrentThread;
    KAFFINITY Affinity;
    KPRIORITY BasePriority;
    PVOID SectionObject;
    PVOID ExceptionPortObject;
    PVOID DebugPortObject;
    ULONG WorkingSetMinimum, WorkingSetMaximum;
    HANDLE LocalProcessHandle;
    KPROCESSOR_MODE PreviousMode;
    INITIAL_PEB InitialPeb;
    BOOLEAN CreatePeb;
    ULONG_PTR DirectoryTableBase[2];
    BOOLEAN AccessCheck;
    BOOLEAN MemoryAllocated;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    NTSTATUS accesst;
    NTSTATUS SavedStatus;
    ULONG ImageFileNameSize;
    HANDLE_TABLE_ENTRY CidEntry;
    PEJOB Job;
    PPEB Peb;
    AUX_ACCESS_DATA AuxData;
    PACCESS_STATE AccessState;
    ACCESS_STATE LocalAccessState;
    BOOLEAN UseLargePages;
    SCHAR QuantumReset;
#if defined(_WIN64)
    INITIAL_PEB32 InitialPeb32;
#endif

    PAGED_CODE();

    CurrentThread = PsGetCurrentThread ();
    PreviousMode = KeGetPreviousModeByThread(&CurrentThread->Tcb);
    CurrentProcess = PsGetCurrentProcessByThread (CurrentThread);

    CreatePeb = FALSE;
    UseLargePages = FALSE;
    DirectoryTableBase[0] = 0;
    DirectoryTableBase[1] = 0;
    Peb = NULL;
    
    //
    // Reject bogus create parameters for future expansion
    //
    if (Flags&~PROCESS_CREATE_FLAGS_LEGAL_MASK) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Parent
    //

    if (ARGUMENT_PRESENT (ParentProcess)) {
        Status = ObReferenceObjectByHandle (ParentProcess,
                                            PROCESS_CREATE_PROCESS,
                                            PsProcessType,
                                            PreviousMode,
                                            &Parent,
                                            NULL);
        if (!NT_SUCCESS (Status)) {
            return Status;
        }

        if (JobMemberLevel != 0 && Parent->Job == NULL) {
            ObDereferenceObject (Parent);
            return STATUS_INVALID_PARAMETER;
        }

        Affinity = Parent->Pcb.Affinity;
        WorkingSetMinimum = PsMinimumWorkingSet;
        WorkingSetMaximum = PsMaximumWorkingSet;


    } else {

        Parent = NULL;
        Affinity = KeActiveProcessors;
        WorkingSetMinimum = PsMinimumWorkingSet;
        WorkingSetMaximum = PsMaximumWorkingSet;
    }

    //
    // Create the process object
    //
    Status = ObCreateObject (PreviousMode,
                             PsProcessType,
                             ObjectAttributes,
                             PreviousMode,
                             NULL,
                             sizeof (EPROCESS),
                             0,
                             0,
                             &Process);

    if (!NT_SUCCESS (Status)) {
        goto exit_and_deref_parent;
    }

    //
    // The process object is created set to NULL. Errors
    // That occur after this step cause the process delete
    // routine to be entered.
    //
    // Teardown actions that occur in the process delete routine
    // do not need to be performed inline.
    //

    RtlZeroMemory (Process, sizeof(EPROCESS));
    ExInitializeRundownProtection (&Process->RundownProtect);
    PspInitializeProcessLock (Process);
    InitializeListHead (&Process->ThreadListHead);

#if defined(_WIN64)

    if (Flags & PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE) {
        PS_SET_BITS (&Process->Flags, PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE);
    }

#endif

    PspInheritQuota (Process, Parent);
    ObInheritDeviceMap (Process, Parent);
    if (Parent != NULL) {
        Process->DefaultHardErrorProcessing = Parent->DefaultHardErrorProcessing;
        Process->InheritedFromUniqueProcessId = Parent->UniqueProcessId;

    } else {
        Process->DefaultHardErrorProcessing = PROCESS_HARDERROR_DEFAULT;
        Process->InheritedFromUniqueProcessId = NULL;
    }

    //
    // Section
    //

    if (ARGUMENT_PRESENT (SectionHandle)) {
        Status = ObReferenceObjectByHandle (SectionHandle,
                                            SECTION_MAP_EXECUTE,
                                            MmSectionObjectType,
                                            PreviousMode,
                                            &SectionObject,
                                            NULL);
        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }

    } else {
        SectionObject = NULL;
        if (Parent != PsInitialSystemProcess) {

            //
            // Fetch the section pointer from the parent process
            // as we will be cloning. Since the section pointer
            // is removed at last thread exit we need to protect against
            // process exit here to be safe.
            //

            if (ExAcquireRundownProtection (&Parent->RundownProtect)) {
                SectionObject = Parent->SectionObject;
                if (SectionObject != NULL) {
                    ObReferenceObject (SectionObject);
                }

                ExReleaseRundownProtection (&Parent->RundownProtect);
            }

            if (SectionObject == NULL) {
                Status = STATUS_PROCESS_IS_TERMINATING;
                goto exit_and_deref;
            }
        }
    }

    Process->SectionObject = SectionObject;

    //
    // DebugPort
    //

    if (ARGUMENT_PRESENT (DebugPort)) {
        Status = ObReferenceObjectByHandle (DebugPort,
                                            DEBUG_PROCESS_ASSIGN,
                                            DbgkDebugObjectType,
                                            PreviousMode,
                                            &DebugPortObject,
                                            NULL);

        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }

        Process->DebugPort = DebugPortObject;
        if (Flags&PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT) {
            PS_SET_BITS (&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT);
        }

    } else {
        if (Parent != NULL) {
            DbgkCopyProcessDebugPort (Process, Parent);
        }
    }

    //
    // ExceptionPort
    //

    if (ARGUMENT_PRESENT (ExceptionPort)) {
        Status = ObReferenceObjectByHandle (ExceptionPort,
                                            0,
                                            LpcPortObjectType,
                                            PreviousMode,
                                            &ExceptionPortObject,
                                            NULL);

        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }

        Process->ExceptionPort = ExceptionPortObject;
    }

    Process->ExitStatus = STATUS_PENDING;

    //
    // Clone parent's object table.
    // If no parent (booting) then use the current object table created in
    // ObInitSystem.
    //

    if (Parent != NULL) {

        //
        // Calculate address space
        //
        //      If Parent == PspInitialSystem
        //

        if (!MmCreateProcessAddressSpace (WorkingSetMinimum,
                                          Process,
                                          &DirectoryTableBase[0])) {

            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit_and_deref;
        }

    } else {
        Process->ObjectTable = CurrentProcess->ObjectTable;

        //
        // Initialize the Working Set Mutex and address creation mutex
        // for this "hand built" process.
        // Normally, the call to MmInitializeAddressSpace initializes the
        // working set mutex, however, in this case, we have already initialized
        // the address space and we are now creating a second process using
        // the address space of the idle thread.
        //

        Status = MmInitializeHandBuiltProcess (Process, &DirectoryTableBase[0]);
        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }
    }

    PS_SET_BITS (&Process->Flags, PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE);
    Process->Vm.MaximumWorkingSetSize = WorkingSetMaximum;
    KeInitializeProcess (&Process->Pcb,
                         NORMAL_BASE_PRIORITY,
                         Affinity,
                         &DirectoryTableBase[0],
                         (BOOLEAN)(Process->DefaultHardErrorProcessing & PROCESS_HARDERROR_ALIGNMENT_BIT));

    //
    //  Initialize the security fields of the process
    //  The parent may be null exactly once (during system init).
    //  Thereafter, a parent is always required so that we have a
    //  security context to duplicate for the new process.
    //

    Status = PspInitializeProcessSecurity (Parent, Process);
    if (!NT_SUCCESS (Status)) {
        goto exit_and_deref;
    }

    Process->PriorityClass = PROCESS_PRIORITY_CLASS_NORMAL;
    if (Parent != NULL) {
        if (Parent->PriorityClass == PROCESS_PRIORITY_CLASS_IDLE ||
            Parent->PriorityClass == PROCESS_PRIORITY_CLASS_BELOW_NORMAL) {
            Process->PriorityClass = Parent->PriorityClass;
        }

        //
        // if address space creation worked, then when going through
        // delete, we will attach. Of course, attaching means that the kprocess
        // must be initialized, so we delay the object stuff till here.
        //

        Status = ObInitProcess ((Flags&PROCESS_CREATE_FLAGS_INHERIT_HANDLES) ? Parent : NULL,
                                Process);

        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }

    } else {
        Status = MmInitializeHandBuiltProcess2 (Process);
        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }
    }

    Status = STATUS_SUCCESS;
    SavedStatus = STATUS_SUCCESS;

    //
    // Initialize the process address space
    // The address space has four possibilities
    //
    //      1 - Boot Process. Address space is initialized during
    //          MmInit. Parent is not specified.
    //
    //      2 - System Process. Address space is a virgin address
    //          space that only maps system space. Process is same
    //          as PspInitialSystemProcess.
    //
    //      3 - User Process (Cloned Address Space). Address space
    //          is cloned from the specified process.
    //
    //      4 - User Process (New Image Address Space). Address space
    //          is initialized so that it maps the specified section.
    //

    if (SectionHandle != NULL) {

        //
        // User Process (New Image Address Space). Don't specify Process to
        // clone, just SectionObject.
        //
        // Passing in the 4th parameter as below lets the EPROCESS struct contain its image file name, provided that
        // appropriate audit settings are enabled.  Memory is allocated inside of MmInitializeProcessAddressSpace
        // and pointed to by ImageFileName, so that must be freed in the process deletion routine (PspDeleteProcess())
        //

        Status = MmInitializeProcessAddressSpace (Process,
                                                  NULL,
                                                  SectionObject,
                                                  &Flags,
                                                  &(Process->SeAuditProcessCreationInfo.ImageFileName));

        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }

        //
        // In order to support relocating executables, the proper status
        // (STATUS_IMAGE_NOT_AT_BASE) must be returned, so save it here.
        //

        SavedStatus = Status;
        CreatePeb = TRUE;
        UseLargePages = ((Flags & PROCESS_CREATE_FLAGS_LARGE_PAGES) != 0 ? TRUE : FALSE);

    } else if (Parent != NULL) {
        if (Parent != PsInitialSystemProcess) {
            Process->SectionBaseAddress = Parent->SectionBaseAddress;

            //
            // User Process ( Cloned Address Space ).  Don't specify section to
            // map, just Process to clone.
            //

            Status = MmInitializeProcessAddressSpace (Process,
                                                      Parent,
                                                      NULL,
                                                      &Flags,
                                                      NULL);

            if (!NT_SUCCESS (Status)) {
                goto exit_and_deref;
            }

            CreatePeb = TRUE;
            UseLargePages = ((Flags & PROCESS_CREATE_FLAGS_LARGE_PAGES) != 0 ? TRUE : FALSE);
            
            //
            // A cloned process isn't started from an image file, so we give it the name
            // of the process of which it is a clone, provided the original has a name.
            //

            if (Parent->SeAuditProcessCreationInfo.ImageFileName != NULL) {
                ImageFileNameSize = sizeof(OBJECT_NAME_INFORMATION) +
                                    Parent->SeAuditProcessCreationInfo.ImageFileName->Name.MaximumLength;

                Process->SeAuditProcessCreationInfo.ImageFileName =
                    ExAllocatePoolWithTag (PagedPool,
                                           ImageFileNameSize,
                                           'aPeS');

                if (Process->SeAuditProcessCreationInfo.ImageFileName != NULL) {
                    RtlCopyMemory (Process->SeAuditProcessCreationInfo.ImageFileName,
                                   Parent->SeAuditProcessCreationInfo.ImageFileName,
                                   ImageFileNameSize);

                    //
                    // The UNICODE_STRING in the process is self contained, so calculate the
                    // offset for the buffer.
                    //

                    Process->SeAuditProcessCreationInfo.ImageFileName->Name.Buffer =
                        (PUSHORT)(((PUCHAR) Process->SeAuditProcessCreationInfo.ImageFileName) +
                        sizeof(UNICODE_STRING));

                } else {
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto exit_and_deref;
                }
            }

        } else {

            //
            // System Process.  Don't specify Process to clone or section to map
            //

            Flags &= ~PROCESS_CREATE_FLAGS_ALL_LARGE_PAGE_FLAGS;
            Status = MmInitializeProcessAddressSpace (Process,
                                                      NULL,
                                                      NULL,
                                                      &Flags,
                                                      NULL);

            if (!NT_SUCCESS (Status)) {
                goto exit_and_deref;
            }

            //
            // In case the image file name of this system process is ever queried, we give
            // a zero length UNICODE_STRING.
            //

            Process->SeAuditProcessCreationInfo.ImageFileName =
                ExAllocatePoolWithTag (PagedPool,
                                       sizeof(OBJECT_NAME_INFORMATION),
                                       'aPeS');

            if (Process->SeAuditProcessCreationInfo.ImageFileName != NULL) {
                RtlZeroMemory (Process->SeAuditProcessCreationInfo.ImageFileName,
                               sizeof(OBJECT_NAME_INFORMATION));
            } else {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto exit_and_deref;
            }
        }
    }

    //
    // Create the process ID
    //

    CidEntry.Object = Process;
    CidEntry.GrantedAccess = 0;
    Process->UniqueProcessId = ExCreateHandle (PspCidTable, &CidEntry);
    if (Process->UniqueProcessId == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit_and_deref;
    }

    ExSetHandleTableOwner (Process->ObjectTable, Process->UniqueProcessId);

    //
    // Audit the process creation.
    //

    if (SeDetailedAuditingWithToken (NULL)) {
        SeAuditProcessCreation (Process);
    }

    //
    // See if the parent has a job. If so reference the job
    // and add the process in.
    //

    if (Parent) {
        Job = Parent->Job;
        if (Job != NULL && !(Job->LimitFlags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) {
            if (Flags&PROCESS_CREATE_FLAGS_BREAKAWAY) {
                if (!(Job->LimitFlags & JOB_OBJECT_LIMIT_BREAKAWAY_OK)) {
                    Status = STATUS_ACCESS_DENIED;

                } else {
                    Status = STATUS_SUCCESS;
                }

            } else {
                Status = PspGetJobFromSet (Job, JobMemberLevel, &Process->Job);
                if (NT_SUCCESS (Status)) {
                    PACCESS_TOKEN Token, NewToken;
                    Job = Process->Job;
                    Status = PspAddProcessToJob (Job, Process);

                    //
                    // Duplicate a new process token if one is specified for the job
                    //

                    Token = Job->Token;
                    if (Token != NULL) {
                        Status = SeSubProcessToken (Token,
                                                    &NewToken,
                                                    FALSE,
                                                    Job->SessionId);

                        if (!NT_SUCCESS (Status)) {
                            goto exit_and_deref;
                        }

                        SeAssignPrimaryToken (Process, NewToken);    
                        ObDereferenceObject (NewToken);                    
                    }
                }
            }

            if (!NT_SUCCESS (Status)) {
                goto exit_and_deref;
            }
        }
    }

    if (Parent && CreatePeb) {

        //
        // For processes created w/ a section,
        // a new "virgin" PEB is created. Otherwise,
        // for forked processes, uses inherited PEB
        // with an updated mutant.
        //

        RtlZeroMemory (&InitialPeb, FIELD_OFFSET(INITIAL_PEB, Mutant));

        InitialPeb.Mutant = (HANDLE)(-1);
        InitialPeb.ImageUsesLargePages = (BOOLEAN) UseLargePages;
            
        if (SectionHandle != NULL) {
            Status = MmCreatePeb (Process, &InitialPeb, &Process->Peb);
            if (!NT_SUCCESS (Status)) {
                Process->Peb = NULL;
                goto exit_and_deref;
            }

            Peb =  Process->Peb;

        } else {
            SIZE_T BytesCopied;

            InitialPeb.InheritedAddressSpace = TRUE;
            Process->Peb = Parent->Peb;
            MmCopyVirtualMemory (CurrentProcess,
                                 &InitialPeb,
                                 Process,
                                 Process->Peb,
                                 sizeof (INITIAL_PEB),
                                 KernelMode,
                                 &BytesCopied);

#if defined(_WIN64)
            if (Process->Wow64Process != NULL) {
                
                RtlZeroMemory (&InitialPeb32, FIELD_OFFSET(INITIAL_PEB32, Mutant));
                InitialPeb32.Mutant = -1;
                InitialPeb32.InheritedAddressSpace = TRUE;
                InitialPeb32.ImageUsesLargePages = (BOOLEAN) UseLargePages;

                MmCopyVirtualMemory (CurrentProcess,
                                     &InitialPeb32,
                                     Process,
                                     Process->Wow64Process->Wow64,
                                     sizeof (INITIAL_PEB32),
                                     KernelMode,
                                     &BytesCopied);
            }
#endif

        }
    }

    Peb = Process->Peb;

    //
    // Add the process to the global list of processes.
    //

    PspLockProcessList (CurrentThread);
    InsertTailList (&PsActiveProcessHead, &Process->ActiveProcessLinks);
    PspUnlockProcessList (CurrentThread);
    AccessState = NULL;
    if (!PsUseImpersonationToken) {
        AccessState = &LocalAccessState;
        Status = SeCreateAccessStateEx (NULL,
                                        (Parent == NULL || Parent != PsInitialSystemProcess)?
                                           PsGetCurrentProcessByThread (CurrentThread) :
                                           PsInitialSystemProcess,
                                        AccessState,
                                        &AuxData,
                                        DesiredAccess,
                                        &PsProcessType->TypeInfo.GenericMapping);
        if (!NT_SUCCESS (Status)) {
            goto exit_and_deref;
        }
    }

    //
    // Insert the object. Once we do this is reachable from the outside world via
    // open by name. Open by ID is still disabled. Since its reachable
    // somebody might create a thread in the process and cause
    // rundown.
    //

    Status = ObInsertObject (Process,
                             AccessState,
                             DesiredAccess,
                             1,     // bias the refcnt by one for future process manipulations
                             NULL,
                             &LocalProcessHandle);

    if (AccessState != NULL) {
        SeDeleteAccessState (AccessState);
    }

    if (!NT_SUCCESS (Status)) {
        goto exit_and_deref_parent;
    }

    //
    // Compute the base priority and quantum reset values for the process and
    // set the memory priority.
    //

    ASSERT(IsListEmpty(&Process->ThreadListHead) == TRUE);

    BasePriority = PspComputeQuantumAndPriority(Process,
                                                PsProcessPriorityBackground,
                                                &QuantumReset);

    Process->Pcb.BasePriority = (SCHAR)BasePriority;
    Process->Pcb.QuantumReset = QuantumReset;

    //
    // As soon as a handle to the process is accessible, allow the process to
    // be deleted.
    //

    Process->GrantedAccess = PROCESS_TERMINATE;
    if (Parent && Parent != PsInitialSystemProcess) {
        Status = ObGetObjectSecurity (Process,
                                      &SecurityDescriptor,
                                      &MemoryAllocated);

        if (!NT_SUCCESS (Status)) {
            ObCloseHandle (LocalProcessHandle, PreviousMode);
            goto exit_and_deref;
        }

        //
        // Compute the subject security context
        //

        SubjectContext.ProcessAuditId = Process;
        SubjectContext.PrimaryToken = PsReferencePrimaryToken(Process);
        SubjectContext.ClientToken = NULL;
        AccessCheck = SeAccessCheck (SecurityDescriptor,
                                     &SubjectContext,
                                     FALSE,
                                     MAXIMUM_ALLOWED,
                                     0,
                                     NULL,
                                     &PsProcessType->TypeInfo.GenericMapping,
                                     PreviousMode,
                                     &Process->GrantedAccess,
                                     &accesst);

        PsDereferencePrimaryTokenEx (Process, SubjectContext.PrimaryToken);
        ObReleaseObjectSecurity (SecurityDescriptor,
                                 MemoryAllocated);

        if (!AccessCheck) {
            Process->GrantedAccess = 0;
        }

        //
        // It does not make any sense to create a process that can not
        // do anything to itself.
        // Note: Changes to this set of bits should be reflected in psquery.c
        // code, in PspSetPrimaryToken.
        //

        Process->GrantedAccess |= (PROCESS_VM_OPERATION |
                                   PROCESS_VM_READ |
                                   PROCESS_VM_WRITE |
                                   PROCESS_QUERY_INFORMATION |
                                   PROCESS_TERMINATE |
                                   PROCESS_CREATE_THREAD |
                                   PROCESS_DUP_HANDLE |
                                   PROCESS_CREATE_PROCESS |
                                   PROCESS_SET_INFORMATION |
                                   STANDARD_RIGHTS_ALL |
                                   PROCESS_SET_QUOTA);

    } else {
        Process->GrantedAccess = PROCESS_ALL_ACCESS;
    }

    KeQuerySystemTime (&Process->CreateTime);
    try {
        if (Peb != NULL && CurrentThread->Tcb.Teb != NULL) {
            ((PTEB)(CurrentThread->Tcb.Teb))->NtTib.ArbitraryUserPointer = Peb;
        }

        *ProcessHandle = LocalProcessHandle;

    } except (EXCEPTION_EXECUTE_HANDLER) {
        NOTHING;
    }

    if (SavedStatus != STATUS_SUCCESS) {
        Status = SavedStatus;
    }

exit_and_deref:
    ObDereferenceObject (Process);

exit_and_deref_parent:
    if (Parent != NULL) {
        ObDereferenceObject (Parent);
    }

    return Status;
}

NTSTATUS
PsSetCreateProcessNotifyRoutine(
    __in PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
    __in BOOLEAN Remove
    )

/*++

Routine Description:

    This function allows an installable file system to hook into process
    creation and deletion to track those events against their own internal
    data structures.

Arguments:

    NotifyRoutine - Supplies the address of a routine which is called at
        process creation and deletion. The routine is passed the unique Id
        of the created or deleted process and the parent process if it was
        created with the inherit handles option. If it was created without
        the inherit handle options, then the parent process Id will be NULL.
        The third parameter passed to the notify routine is TRUE if the process
        is being created and FALSE if it is being deleted.

        The callout for creation happens just after the first thread in the
        process has been created. The callout for deletion happens after the
        last thread in a process has terminated and the address space is about
        to be deleted. It is possible to get a deletion call without a creation
        call if the pathological case where a process is created and deleted
        without a thread ever being created.

    Remove - FALSE specifies to install the callout and TRUE specifies to
        remove the callout that mat

Return Value:

    STATUS_SUCCESS if successful, and STATUS_INVALID_PARAMETER if not.

--*/

{

    ULONG i;
    PEX_CALLBACK_ROUTINE_BLOCK CallBack;

    PAGED_CODE();

    if (Remove) {
        for (i = 0; i < PSP_MAX_CREATE_PROCESS_NOTIFY; i++) {

            //
            // Reference the callback so we can check its routine address.
            //
            CallBack = ExReferenceCallBackBlock (&PspCreateProcessNotifyRoutine[i]);

            if (CallBack != NULL) {
                //
                // See if the routine matches our target
                //
                if ((PCREATE_PROCESS_NOTIFY_ROUTINE) ExGetCallBackBlockRoutine (CallBack) == NotifyRoutine) {

                    if (ExCompareExchangeCallBack (&PspCreateProcessNotifyRoutine[i],
                                                   NULL,
                                                   CallBack)) {

                        InterlockedDecrement ((PLONG) &PspCreateProcessNotifyRoutineCount);

                        ExDereferenceCallBackBlock (&PspCreateProcessNotifyRoutine[i],
                                                    CallBack);

                        //
                        // Wait for any active callbacks to finish and free the block.
                        //
                        ExWaitForCallBacks (CallBack);
                    
                        ExFreeCallBack (CallBack);

                        return STATUS_SUCCESS;
                    }
                }
                ExDereferenceCallBackBlock (&PspCreateProcessNotifyRoutine[i],
                                            CallBack);
            }
        }

        return STATUS_PROCEDURE_NOT_FOUND;
    } else {
        //
        // Allocate a new callback block.
        // 
        CallBack = ExAllocateCallBack ((PEX_CALLBACK_FUNCTION) NotifyRoutine, NULL);
        if (CallBack == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        for (i = 0; i < PSP_MAX_CREATE_PROCESS_NOTIFY; i++) {
            //
            // Try and swap a null entry for the new block.
            //
            if (ExCompareExchangeCallBack (&PspCreateProcessNotifyRoutine[i],
                                           CallBack,
                                           NULL)) {
                InterlockedIncrement ((PLONG) &PspCreateProcessNotifyRoutineCount);
                return STATUS_SUCCESS;
            }
        }
        //
        // No slots left. Free the block and return.
        //
        ExFreeCallBack (CallBack);
        return STATUS_INVALID_PARAMETER;
    }

}

NTSTATUS
PsSetCreateThreadNotifyRoutine(
    __in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
    )

/*++

Routine Description:

    This function allows an installable file system to hook into thread
    creation and deletion to track those events against their own internal
    data structures.

Arguments:

    NotifyRoutine - Supplies the address of the routine which is called at
        thread creation and deletion. The routine is passed the unique Id
        of the created or deleted thread and the unique Id of the containing
        process. The third parameter passed to the notify routine is TRUE if
        the thread is being created and FALSE if it is being deleted.

Return Value:

    STATUS_SUCCESS if successful, and STATUS_INSUFFICIENT_RESOURCES if not.

--*/

{

    ULONG i;
    PEX_CALLBACK_ROUTINE_BLOCK CallBack;

    PAGED_CODE();

    //
    // Allocate a new callback block.
    // 
    CallBack = ExAllocateCallBack ((PEX_CALLBACK_FUNCTION) NotifyRoutine, NULL);
    if (CallBack == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < PSP_MAX_CREATE_THREAD_NOTIFY; i += 1) {
        //
        // Try and swap a null entry for the new block.
        //
        if (ExCompareExchangeCallBack (&PspCreateThreadNotifyRoutine[i],
                                       CallBack,
                                       NULL)) {
            InterlockedIncrement ((PLONG) &PspCreateThreadNotifyRoutineCount);
            return STATUS_SUCCESS;
        }
    }
    //
    // No slots left. Free the block and return.
    //
    ExFreeCallBack (CallBack);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
PsRemoveCreateThreadNotifyRoutine (
    __in PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
    )
/*++

Routine Description:

    This function allows an installable file system to unhook from thread
    creation and deletion.

Arguments:

    NotifyRoutine - Supplies the address of the routine which was previously
                    registered with PsSetCreateThreadNotifyRoutine

Return Value:

    STATUS_SUCCESS if successful, and STATUS_PROCEDURE_NOT_FOUND if not.

--*/
{
    ULONG i;
    PEX_CALLBACK_ROUTINE_BLOCK CallBack;

    PAGED_CODE();

    for (i = 0; i < PSP_MAX_CREATE_THREAD_NOTIFY; i += 1) {

        //
        // Reference the callback so we can check its routine address.
        //
        CallBack = ExReferenceCallBackBlock (&PspCreateThreadNotifyRoutine[i]);

        if (CallBack != NULL) {
            //
            // See if the routine matches our target
            //
            if ((PCREATE_THREAD_NOTIFY_ROUTINE) ExGetCallBackBlockRoutine (CallBack) == NotifyRoutine) {

                if (ExCompareExchangeCallBack (&PspCreateThreadNotifyRoutine[i],
                                               NULL,
                                               CallBack)) {

                    InterlockedDecrement ((PLONG) &PspCreateThreadNotifyRoutineCount);

                    ExDereferenceCallBackBlock (&PspCreateThreadNotifyRoutine[i],
                                                CallBack);

                    //
                    // Wait for any active callbacks to finish and free the block.
                    //
                    ExWaitForCallBacks (CallBack);
                    
                    ExFreeCallBack (CallBack);

                    return STATUS_SUCCESS;
                }
            }
            ExDereferenceCallBackBlock (&PspCreateThreadNotifyRoutine[i],
                                        CallBack);
        }
    }

    return STATUS_PROCEDURE_NOT_FOUND;
}

VOID
PspUserThreadStartup(
    IN PKSTART_ROUTINE StartRoutine,
    IN PVOID StartContext
    )

/*++

Routine Description:

    This function is called by the kernel to start a user-mode thread.

Arguments:

    StartRoutine - Ignored.

    StartContext - Supplies the initial pc value for the thread.

Return Value:

    None.

--*/

{
    PETHREAD Thread;
    PEPROCESS Process;
    PTEB Teb;
    ULONG OldFlags;
    BOOLEAN KillThread;
    KIRQL OldIrql;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(StartRoutine);

    KeLowerIrql (PASSIVE_LEVEL);
	// 获得当前线程和进程对象
    Thread = PsGetCurrentThread ();
    Process = PsGetCurrentProcessByThread (Thread);

    //
    // All threads start with an APC at LdrInitializeThunk
    //

    //
    // See if we need to terminate early because of a error in the create path
    //
    // 是否由于创建过程中出错而需要终止本线程
    KillThread = FALSE;
    if ((Thread->CrossThreadFlags & PS_CROSS_THREAD_FLAGS_DEADTHREAD) != 0) {
        KillThread = TRUE;
    }

    //
    // Note: Initializing the TEB here is just to satisfy the compiler.
    //

    Teb = NtCurrentTeb ();

    if (!KillThread) {
        try {
            Teb->CurrentLocale = MmGetSessionLocaleId ();
            Teb->IdealProcessor = Thread->Tcb.IdealProcessor;
        } except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    //
    // If the create worked then notify the debugger.
    //
    // 如果需要，通知调试器
    if ((Thread->CrossThreadFlags&
         (PS_CROSS_THREAD_FLAGS_DEADTHREAD|PS_CROSS_THREAD_FLAGS_HIDEFROMDBG)) == 0) {
        DbgkCreateThread (Thread, StartContext);
    }

    //
    // If something went wrong then terminate the thread
    //
    if (KillThread) {
        PspTerminateThreadByPointer (Thread,
                                     STATUS_THREAD_IS_TERMINATING,
                                     TRUE);
    } else {

        if (CCPF_IS_PREFETCHER_ENABLED()) {

            //
            // If this is the first thread we are starting up in this process,
            // prefetch the pages likely to be used when initializing the 
            // application into the system cache.
            //
			// 如果这是进程中的第一个线程，则判断系统是否支持应用程序预取的特性，如果是，则
			// 通知缓存管理器预取可执行映像文件的页面
			// 所谓应用程序预取，是指将该进程上一次启动的前10s内引用到的页面直接读入到内存中
            if ((Process->Flags & PS_PROCESS_FLAGS_LAUNCH_PREFETCHED) == 0) {

                OldFlags = PS_TEST_SET_BITS(&Process->Flags, PS_PROCESS_FLAGS_LAUNCH_PREFETCHED);

                if ((OldFlags & PS_PROCESS_FLAGS_LAUNCH_PREFETCHED) == 0) {

                    if (Process->SectionObject) {

                        //
                        // Notify cache manager of this application launch.
                        //

                        CcPfBeginAppLaunch(Process, Process->SectionObject);
                    }
                }
            }
        }

        //
        // Queue the initial APC to the thread
        //
		// 把一个用户模式APC插入到线程的用户APC队列中
        KeRaiseIrql (APC_LEVEL, &OldIrql);

        KiInitializeUserApc (PspGetBaseExceptionFrame (Thread),
                             PspGetBaseTrapFrame (Thread),
                             PspSystemDll.LoaderInitRoutine,
                             NULL,
                             PspSystemDll.DllBase,
                             NULL);

        KeLowerIrql (PASSIVE_LEVEL);
    }

    //
    // Fill in the system wide cookie if its zero
    //
    // 填充系统范围的一个Cookie值
    while (1) {
        ULONG Cookie;
        LARGE_INTEGER Time;
        PKPRCB Prcb;

        Cookie = SharedUserData->Cookie;
        if (Cookie != 0) {
            return;
        } else {
            KeQuerySystemTime (&Time);
            Prcb = KeGetCurrentPrcb ();
            Cookie = Time.LowPart ^ Time.HighPart ^ Prcb->InterruptTime ^ Prcb->MmPageFaultCount ^ (ULONG)(ULONG_PTR)&Time;
            InterlockedCompareExchange ((PLONG)&SharedUserData->Cookie, Cookie, 0);
        }
    }

}



ULONG
PspUnhandledExceptionInSystemThread(
    IN PEXCEPTION_POINTERS ExceptionPointers
    )
{
    KdPrint(("PS: Unhandled Kernel Mode Exception Pointers = 0x%p\n", ExceptionPointers));
    KdPrint(("Code %x Addr %p Info0 %p Info1 %p Info2 %p Info3 %p\n",
        ExceptionPointers->ExceptionRecord->ExceptionCode,
        (ULONG_PTR)ExceptionPointers->ExceptionRecord->ExceptionAddress,
        ExceptionPointers->ExceptionRecord->ExceptionInformation[0],
        ExceptionPointers->ExceptionRecord->ExceptionInformation[1],
        ExceptionPointers->ExceptionRecord->ExceptionInformation[2],
        ExceptionPointers->ExceptionRecord->ExceptionInformation[3]
        ));

    KeBugCheckEx(
        SYSTEM_THREAD_EXCEPTION_NOT_HANDLED,
        ExceptionPointers->ExceptionRecord->ExceptionCode,
        (ULONG_PTR)ExceptionPointers->ExceptionRecord->ExceptionAddress,
        (ULONG_PTR)ExceptionPointers->ExceptionRecord,
        (ULONG_PTR)ExceptionPointers->ContextRecord);

//    return EXCEPTION_EXECUTE_HANDLER;
}

// PspUnhandledExceptionInSystemThread doesn't return, and the compiler
// sometimes gives 'unreachable code' warnings as a result.
#pragma warning(push)
#pragma warning(disable:4702)

VOID
PspSystemThreadStartup(
    IN PKSTART_ROUTINE StartRoutine,
    IN PVOID StartContext
    )

/*++

Routine Description:

    This function is called by the kernel to start a system thread.

Arguments:

    StartRoutine - Supplies the address of the system threads entry point.

    StartContext - Supplies a context value for the system thread.

Return Value:

    None.

--*/

{
    PETHREAD Thread;

    KeLowerIrql(0);

    Thread = PsGetCurrentThread ();

    try {
        if ((Thread->CrossThreadFlags&(PS_CROSS_THREAD_FLAGS_TERMINATED|PS_CROSS_THREAD_FLAGS_DEADTHREAD)) == 0) {
            (StartRoutine)(StartContext);
        }
    } except (PspUnhandledExceptionInSystemThread(GetExceptionInformation())) {
        KeBugCheck(KMODE_EXCEPTION_NOT_HANDLED);
    }
    PspTerminateThreadByPointer (Thread, STATUS_SUCCESS, TRUE);
}

#pragma warning(pop)



HANDLE
PsGetCurrentProcessId( VOID )
{
    return PsGetCurrentThread()->Cid.UniqueProcess;
}

HANDLE
PsGetCurrentThreadId( VOID )
{
    return PsGetCurrentThread()->Cid.UniqueThread;
}

BOOLEAN
PsGetVersion(
    __out_opt PULONG MajorVersion,
    __out_opt PULONG MinorVersion,
    __out_opt PULONG BuildNumber,
    __out_opt PUNICODE_STRING CSDVersion
    )
{
    if (ARGUMENT_PRESENT(MajorVersion)) {
        *MajorVersion = NtMajorVersion;
    }

    if (ARGUMENT_PRESENT(MinorVersion)) {
        *MinorVersion = NtMinorVersion;
    }

    if (ARGUMENT_PRESENT(BuildNumber)) {
        *BuildNumber = NtBuildNumber & 0x3FFF;
    }

    if (ARGUMENT_PRESENT(CSDVersion)) {
        *CSDVersion = CmCSDVersionString;
    }
    return (BOOLEAN)((NtBuildNumber >> 28) == 0xC);
}

NTSTATUS
PsSetLoadImageNotifyRoutine(
    __in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    )

/*++

Routine Description:

    This function allows a device driver to get notified for
    image loads. The notify is issued for both kernel and user
    mode image loads system-wide.

Arguments:

    NotifyRoutine - Supplies the address of a routine which is called at
        image load. The routine is passed information describing the
        image being loaded.

        The callout for creation happens just after the image is loaded
        into memory but before executiona of the image.

Return Value:

    STATUS_SUCCESS if successful, and STATUS_INVALID_PARAMETER if not.

--*/

{
    ULONG i;
    PEX_CALLBACK_ROUTINE_BLOCK CallBack;

    PAGED_CODE();

    //
    // Allocate a new callback block.
    // 
    CallBack = ExAllocateCallBack ((PEX_CALLBACK_FUNCTION) NotifyRoutine, NULL);
    if (CallBack == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < PSP_MAX_LOAD_IMAGE_NOTIFY; i++) {
        //
        // Try and swap a null entry for the new block.
        //
        if (ExCompareExchangeCallBack (&PspLoadImageNotifyRoutine[i],
                                       CallBack,
                                       NULL)) {
            InterlockedIncrement ((PLONG) &PspLoadImageNotifyRoutineCount);
            PsImageNotifyEnabled = TRUE;
            return STATUS_SUCCESS;
        }
    }
    //
    // No slots left. Free the block and return.
    //
    ExFreeCallBack (CallBack);
    return STATUS_INSUFFICIENT_RESOURCES;
}

NTSTATUS
PsRemoveLoadImageNotifyRoutine(
    __in PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
    )
/*++

Routine Description:

    This function allows an installable file system to unhook from image
    load notification.

Arguments:

    NotifyRoutine - Supplies the address of the routine which was previously
                    registered with PsSetLoadImageNotifyRoutine

Return Value:

    STATUS_SUCCESS if successful, and STATUS_PROCEDURE_NOT_FOUND if not.

--*/
{
    ULONG i;
    PEX_CALLBACK_ROUTINE_BLOCK CallBack;

    PAGED_CODE();

    for (i = 0; i < PSP_MAX_LOAD_IMAGE_NOTIFY; i++) {

        //
        // Reference the callback so we can check its routine address.
        //
        CallBack = ExReferenceCallBackBlock (&PspLoadImageNotifyRoutine[i]);

        if (CallBack != NULL) {
            //
            // See if the routine matches our target
            //
            if ((PLOAD_IMAGE_NOTIFY_ROUTINE) ExGetCallBackBlockRoutine (CallBack) == NotifyRoutine) {

                if (ExCompareExchangeCallBack (&PspLoadImageNotifyRoutine[i],
                                               NULL,
                                               CallBack)) {

                    InterlockedDecrement ((PLONG) &PspLoadImageNotifyRoutineCount);

                    ExDereferenceCallBackBlock (&PspLoadImageNotifyRoutine[i],
                                                CallBack);

                    //
                    // Wait for any active callbacks to finish and free the block.
                    //
                    ExWaitForCallBacks (CallBack);
                    
                    ExFreeCallBack (CallBack);

                    return STATUS_SUCCESS;
                }
            }
            ExDereferenceCallBackBlock (&PspLoadImageNotifyRoutine[i],
                                        CallBack);
        }
    }

    return STATUS_PROCEDURE_NOT_FOUND;
}

VOID
PsCallImageNotifyRoutines(
    IN PUNICODE_STRING FullImageName,
    IN HANDLE ProcessId,                // pid into which image is being mapped
    IN PIMAGE_INFO ImageInfo
    )
/*++

Routine Description:

    This function actually calls the registered image notify functions (on behalf)
    of mapview.c and sysload.c

Arguments:

    FullImageName - The name of the image being loaded

    ProcessId - The process that the image is being loaded into (0 for driver loads)

    ImageInfo - Various flags for the image

Return Value:

    None.

--*/

{
    ULONG i;
    PEX_CALLBACK_ROUTINE_BLOCK CallBack;
    PLOAD_IMAGE_NOTIFY_ROUTINE Rtn;

    PAGED_CODE();

    if (PsImageNotifyEnabled) {
        for (i=0; i < PSP_MAX_LOAD_IMAGE_NOTIFY; i++) {
            CallBack = ExReferenceCallBackBlock (&PspLoadImageNotifyRoutine[i]);
            if (CallBack != NULL) {
                Rtn = (PLOAD_IMAGE_NOTIFY_ROUTINE) ExGetCallBackBlockRoutine (CallBack);
                Rtn (FullImageName,
                     ProcessId,
                     ImageInfo);
                ExDereferenceCallBackBlock (&PspLoadImageNotifyRoutine[i], CallBack);
            }
        }
    }
}

VOID
PspImageNotifyTest(
    IN PUNICODE_STRING FullImageName,
    IN HANDLE ProcessId,
    IN PIMAGE_INFO ImageInfo
    )
/*++

Routine Description:

    This function is registered as a image notify routine on checked systems to test the interface.

Arguments:

    FullImageName - The name of the image being loaded

    ProcessId - The process that the image is being loaded into (0 for driver loads)

    ImageInfo - Various flags for the image

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER (FullImageName);
    UNREFERENCED_PARAMETER (ProcessId);
    UNREFERENCED_PARAMETER (ImageInfo);
    return;
}

