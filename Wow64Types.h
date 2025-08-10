#ifndef __WOW64TYPES_H__
#define __WOW64TYPES_H__

#include <Windows.h>

#pragma pack( push, 8 )
typedef struct _CONTEXT64
{
    ULONGLONG P1Home;                                                     
    ULONGLONG P2Home;                                                     
    ULONGLONG P3Home;                                                     
    ULONGLONG P4Home;                                                     
    ULONGLONG P5Home;                                                     
    ULONGLONG P6Home;                                                     
    ULONG     ContextFlags;                                                   
    ULONG     MxCsr;                                                          
    USHORT    SegCs;                                                         
    USHORT    SegDs;                                                         
    USHORT    SegEs;                                                         
    USHORT    SegFs;                                                         
    USHORT    SegGs;                                                         
    USHORT    SegSs;                                                         
    ULONG     EFlags;                                                         
    ULONGLONG Dr0;                                                        
    ULONGLONG Dr1;                                                        
    ULONGLONG Dr2;                                                        
    ULONGLONG Dr3;                                                        
    ULONGLONG Dr6;                                                        
    ULONGLONG Dr7;                                                        
    ULONGLONG Rax;                                                        
    ULONGLONG Rcx;                                                        
    ULONGLONG Rdx;                                                        
    ULONGLONG Rbx;                                                        
    ULONGLONG Rsp;                                                        
    ULONGLONG Rbp;                                                        
    ULONGLONG Rsi;                                                        
    ULONGLONG Rdi;                                                        
    ULONGLONG R8;                                                         
    ULONGLONG R9;                                                         
    ULONGLONG R10;                                                        
    ULONGLONG R11;                                                        
    ULONGLONG R12;                                                        
    ULONGLONG R13;                                                        
    ULONGLONG R14;                                                        
    ULONGLONG R15;                                                        
    ULONGLONG Rip;                                                        
    union
    {
        struct _XSAVE_FORMAT FltSave;                                      
        struct
        {
            struct _M128A Header[2];                                       
            struct _M128A Legacy[8];                                       
            struct _M128A Xmm0;                                            
            struct _M128A Xmm1;                                            
            struct _M128A Xmm2;                                            
            struct _M128A Xmm3;                                            
            struct _M128A Xmm4;                                            
            struct _M128A Xmm5;                                            
            struct _M128A Xmm6;                                            
            struct _M128A Xmm7;                                            
            struct _M128A Xmm8;                                            
            struct _M128A Xmm9;                                            
            struct _M128A Xmm10;                                           
            struct _M128A Xmm11;                                           
            struct _M128A Xmm12;                                           
            struct _M128A Xmm13;                                           
            struct _M128A Xmm14;                                           
            struct _M128A Xmm15;                                           
        };
    };
    struct _M128A VectorRegister[26];                                      
    ULONGLONG     VectorControl;                                               
    ULONGLONG     DebugControl;                                                
    ULONGLONG     LastBranchToRip;                                             
    ULONGLONG     LastBranchFromRip;                                           
    ULONGLONG     LastExceptionToRip;                                          
    ULONGLONG     LastExceptionFromRip;                                        
}CONTEXT64, *PCONTEXT64; 
static_assert( sizeof( _CONTEXT64 ) == 0x4D0, "Size of _CONTEXT64 does not match the assertion" );

typedef struct _CLIENT_ID64
{
    ULONGLONG UniqueProcess;
    ULONGLONG UniqueThread;
}CLIENT_ID64, *PCLIENT_ID64;
static_assert( sizeof( _CLIENT_ID64 ) == 0x10, "Size of _CLIENT_ID64 does not match the assertion" );

typedef struct _ACTIVATION_CONTEXT_STACK64
{
    ULONGLONG ActiveFrame;
    struct LIST_ENTRY64 FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
}ACTIVATION_CONTEXT_STACK64, *PACTIVATION_CONTEXT_STACK64;
static_assert( sizeof( _ACTIVATION_CONTEXT_STACK64 ) == 0x28, "Size of _ACTIVATION_CONTEXT_STACK64 does not match the assertion" );

typedef struct _STRING64
{
    USHORT    Length;
    USHORT    MaximumLength;
    ULONGLONG Buffer;
}STRING64, *PSTRING64; 
static_assert( sizeof( _STRING64 ) == 0x10, "Size of _STRING64 does not match the assertion" );

typedef struct _GDI_TEB_BATCH64
{
    ULONG     Offset              : 30;
    ULONG     InProcessing        : 1;
    ULONG     HasRenderingCommand : 1;
    ULONGLONG HDC;
    ULONG     Buffer[ 310 ];
}; 
static_assert( sizeof( _GDI_TEB_BATCH64 ) == 0x4E8, "Size of _GDI_TEB_BATCH64 does not match the assertion" );

typedef struct _PEB_LDR_DATA64
{
    ULONG               Length;                         
    UCHAR               Initialized;                    
    ULONGLONG           SsHandle;                       
    struct LIST_ENTRY64 InLoadOrderModuleList;          
    struct LIST_ENTRY64 InMemoryOrderModuleList;        
    struct LIST_ENTRY64 InInitializationOrderModuleList;
    ULONGLONG           EntryInProgress;
    UCHAR               ShutdownInProgress;             
    ULONGLONG           ShutdownThreadId;
}PEB_LDR_DATA64, *PPEB_LDR_DATA64;
static_assert( sizeof( _PEB_LDR_DATA64 ) == 0x58, "Size of _PEB_LDR_DATA64 does not match the assertion" );

typedef struct _PEB64
{
    UCHAR InheritedAddressSpace;                                          
    UCHAR ReadImageFileExecOptions;                                       
    UCHAR BeingDebugged;                                                  
    union
    {
        UCHAR BitField;                                                   
        struct
        {
            UCHAR ImageUsesLargePages:1;                                  
            UCHAR IsProtectedProcess:1;                                   
            UCHAR IsImageDynamicallyRelocated:1;                          
            UCHAR SkipPatchingUser32Forwarders:1;                         
            UCHAR IsPackagedProcess:1;                                    
            UCHAR IsAppContainer:1;                                       
            UCHAR IsProtectedProcessLight:1;                              
            UCHAR IsLongPathAwareProcess:1;                               
        };
    };
    UCHAR     Padding0[4];                                                    
    ULONGLONG Mutant;                                                     
    ULONGLONG ImageBaseAddress;                                           
    ULONGLONG Ldr;                                                        
    ULONGLONG ProcessParameters;                                          
    ULONGLONG SubSystemData;                                              
    ULONGLONG ProcessHeap;                                                
    ULONGLONG FastPebLock;                                                
    ULONGLONG AtlThunkSListPtr;                                           
    ULONGLONG IFEOKey;                                                    
    union
    {
        ULONG CrossProcessFlags;                                          
        struct
        {
            ULONG ProcessInJob:1;                                         
            ULONG ProcessInitializing:1;                                  
            ULONG ProcessUsingVEH:1;                                      
            ULONG ProcessUsingVCH:1;                                      
            ULONG ProcessUsingFTH:1;                                      
            ULONG ProcessPreviouslyThrottled:1;                           
            ULONG ProcessCurrentlyThrottled:1;                            
            ULONG ProcessImagesHotPatched:1;                              
            ULONG ReservedBits0:24;                                       
        };
    };
    UCHAR Padding1[4];                                                    
    union
    {
        ULONGLONG KernelCallbackTable;                                    
        ULONGLONG UserSharedInfoPtr;                                      
    };
    ULONG                 SystemReserved;                                                 
    ULONG                 AtlThunkSListPtr32;                                             
    ULONGLONG             ApiSetMap;                                                  
    ULONG                 TlsExpansionCounter;                                            
    UCHAR                 Padding2[4];                                                    
    ULONGLONG             TlsBitmap;                                                  
    ULONG                 TlsBitmapBits[2];                                               
    ULONGLONG             ReadOnlySharedMemoryBase;                                   
    ULONGLONG             SharedData;                                                 
    ULONGLONG             ReadOnlyStaticServerData;                                   
    ULONGLONG             AnsiCodePageData;                                           
    ULONGLONG             OemCodePageData;                                            
    ULONGLONG             UnicodeCaseTableData;                                       
    ULONG                 NumberOfProcessors;                                             
    ULONG                 NtGlobalFlag;                                                   
    union _LARGE_INTEGER  CriticalSectionTimeout;                          
    ULONGLONG             HeapSegmentReserve;                                         
    ULONGLONG             HeapSegmentCommit;                                          
    ULONGLONG             HeapDeCommitTotalFreeThreshold;                             
    ULONGLONG             HeapDeCommitFreeBlockThreshold;                             
    ULONG                 NumberOfHeaps;                                                  
    ULONG                 MaximumNumberOfHeaps;                                           
    ULONGLONG             ProcessHeaps;                                               
    ULONGLONG             GdiSharedHandleTable;                                       
    ULONGLONG             ProcessStarterHelper;                                       
    ULONG                 GdiDCAttributeList;                                             
    UCHAR                 Padding3[4];                                                    
    ULONGLONG             LoaderLock;                                                 
    ULONG                 OSMajorVersion;                                                 
    ULONG                 OSMinorVersion;                                                 
    USHORT                OSBuildNumber;                                                 
    USHORT                OSCSDVersion;                                                  
    ULONG                 OSPlatformId;                                                   
    ULONG                 ImageSubsystem;                                                 
    ULONG                 ImageSubsystemMajorVersion;                                     
    ULONG                 ImageSubsystemMinorVersion;                                     
    UCHAR                 Padding4[4];                                                    
    ULONGLONG             ActiveProcessAffinityMask;                                  
    ULONG                 GdiHandleBuffer[60];                                            
    ULONGLONG             PostProcessInitRoutine;                                     
    ULONGLONG             TlsExpansionBitmap;                                         
    ULONG                 TlsExpansionBitmapBits[32];                                     
    ULONG                 SessionId;                                                      
    UCHAR                 Padding5[4];                                                    
    union _ULARGE_INTEGER AppCompatFlags;                                 
    union _ULARGE_INTEGER AppCompatFlagsUser;                             
    ULONGLONG             pShimData;                                                  
    ULONGLONG             AppCompatInfo;                                              
    struct _STRING64      CSDVersion;                                          
    ULONGLONG             ActivationContextData;                                      
    ULONGLONG             ProcessAssemblyStorageMap;                                  
    ULONGLONG             SystemDefaultActivationContextData;                         
    ULONGLONG             SystemAssemblyStorageMap;                                   
    ULONGLONG             MinimumStackCommit;                                         
    ULONGLONG             SparePointers[2];                                           
    ULONGLONG             PatchLoaderData;                                            
    ULONGLONG             ChpeV2ProcessInfo;                                          
    ULONG                 AppModelFeatureState;                                           
    ULONG                 SpareUlongs[2];                                                 
    USHORT                ActiveCodePage;                                                
    USHORT                OemCodePage;                                                   
    USHORT                UseCaseMapping;                                                
    USHORT                UnusedNlsField;                                                
    ULONGLONG             WerRegistrationData;                                        
    ULONGLONG             WerShipAssertPtr;                                           
    ULONGLONG             EcCodeBitMap;                                               
    ULONGLONG             pImageHeaderHash;                                           
    union
    {
        ULONG TracingFlags;                                               
        struct
        {
            ULONG HeapTracingEnabled:1;                                   
            ULONG CritSecTracingEnabled:1;                                
            ULONG LibLoaderTracingEnabled:1;                              
            ULONG SpareTracingBits:29;                                    
        };
    };
    UCHAR               Padding6[4];                                                    
    ULONGLONG           CsrServerReadOnlySharedMemoryBase;                          
    ULONGLONG           TppWorkerpListLock;                                         
    struct LIST_ENTRY64 TppWorkerpList;                                   
    ULONGLONG           WaitOnAddressHashTable[128];                                
    ULONGLONG           TelemetryCoverageHeader;                                    
    ULONG               CloudFileFlags;                                                 
    ULONG               CloudFileDiagFlags;                                             
    CHAR                PlaceholderCompatibilityMode;                                    
    CHAR                PlaceholderCompatibilityModeReserved[7];                         
    ULONGLONG           LeapSecondData;                                             
    union
    {
        ULONG LeapSecondFlags;                                            
        struct
        {
            ULONG SixtySecondEnabled:1;                                   
            ULONG Reserved:31;                                            
        };
    };
    ULONG NtGlobalFlag2;                                                  
    ULONGLONG ExtendedFeatureDisableMask;                                 
}PEB64, *PPEB64; 
static_assert( sizeof( _PEB64 ) == 0x7D0, "Size of _PEB64 does not match the assertion" );

#define TEB64_SIZE 0x1878
typedef struct _TEB64
{
    struct _NT_TIB64                   NtTib;
    ULONGLONG                          EnvironmentPointer;                                          
    struct _CLIENT_ID64                ClientId;                                          
    ULONGLONG                          ActiveRpcHandle;                                             
    ULONGLONG                          ThreadLocalStoragePointer;                                   
    ULONGLONG                          ProcessEnvironmentBlock;                                     
    ULONG                              LastErrorValue;                                                  
    ULONG                              CountOfOwnedCriticalSections;                                    
    ULONGLONG                          CsrClientThread;                                             
    ULONGLONG                          Win32ThreadInfo;                                             
    ULONG                              User32Reserved[26];                                              
    ULONG                              UserReserved[5];                                                 
    ULONGLONG                          WOW32Reserved;                                               
    ULONG                              CurrentLocale;                                                   
    ULONG                              FpSoftwareStatusRegister;                                        
    ULONGLONG                          ReservedForDebuggerInstrumentation[16];                      
    ULONGLONG                          SystemReserved1[25];                                         
    ULONGLONG                          HeapFlsData;                                                 
    ULONGLONG                          RngState[4];                                                 
    CHAR                               PlaceholderCompatibilityMode;                                     
    UCHAR                              PlaceholderHydrationAlwaysExplicit;                              
    CHAR                               PlaceholderReserved[10];                                          
    ULONG                              ProxiedProcessId;                                                
    struct _ACTIVATION_CONTEXT_STACK64 _ActivationStack;                   
    UCHAR                              WorkingOnBehalfTicket[8];                                        
    LONG                               ExceptionCode;                                                    
    UCHAR                              Padding0[4];                                                     
    ULONGLONG                          ActivationContextStackPointer;                               
    ULONGLONG                          InstrumentationCallbackSp;                                   
    ULONGLONG                          InstrumentationCallbackPreviousPc;                           
    ULONGLONG                          InstrumentationCallbackPreviousSp;                           
    ULONG                              TxFsContext;                                                     
    UCHAR                              InstrumentationCallbackDisabled;                                 
    UCHAR                              UnalignedLoadStoreExceptions;                                    
    UCHAR                              Padding1[2];                                                     
    struct _GDI_TEB_BATCH64            GdiTebBatch;                                   
    struct _CLIENT_ID64                RealClientId;                                      
    ULONGLONG                          GdiCachedProcessHandle;                                      
    ULONG                              GdiClientPID;                                                    
    ULONG                              GdiClientTID;                                                    
    ULONGLONG                          GdiThreadLocalInfo;                                          
    ULONGLONG                          Win32ClientInfo[62];                                         
    ULONGLONG                          glDispatchTable[233];                                        
    ULONGLONG                          glReserved1[29];                                             
    ULONGLONG                          glReserved2;                                                 
    ULONGLONG                          glSectionInfo;                                               
    ULONGLONG                          glSection;                                                   
    ULONGLONG                          glTable;                                                     
    ULONGLONG                          glCurrentRC;                                                 
    ULONGLONG                          glContext;                                                   
    ULONG                              LastStatusValue;                                                 
    UCHAR                              Padding2[4];                                                     
    struct _STRING64                   StaticUnicodeString;                                  
    WCHAR                              StaticUnicodeBuffer[261];                                        
    UCHAR                              Padding3[6];                                                     
    ULONGLONG                          DeallocationStack;                                           
    ULONGLONG                          TlsSlots[64];                                                
    struct LIST_ENTRY64                TlsLinks;                                          
    ULONGLONG                          Vdm;                                                         
    ULONGLONG                          ReservedForNtRpc;                                            
    ULONGLONG                          DbgSsReserved[2];                                            
    ULONG                              HardErrorMode;                                                   
    UCHAR                              Padding4[4];                                                     
    ULONGLONG                          Instrumentation[11];                                         
    struct _GUID                       ActivityId;                                               
    ULONGLONG                          SubProcessTag;                                               
    ULONGLONG                          PerflibData;                                                 
    ULONGLONG                          EtwTraceData;                                                
    ULONGLONG                          WinSockData;                                                 
    ULONG                              GdiBatchCount;                                                   
    union                                                                  
    {                                                                      
        struct _PROCESSOR_NUMBER CurrentIdealProcessor;                    
        ULONG                    IdealProcessorValue;                                         
        struct                                                             
        {                                                                  
            UCHAR ReservedPad0;                                            
            UCHAR ReservedPad1;                                            
            UCHAR ReservedPad2;                                            
            UCHAR IdealProcessor;                                          
        };                                                                 
    };                                                                     
    ULONG     GuaranteedStackBytes;                                            
    UCHAR     Padding5[4];                                                     
    ULONGLONG ReservedForPerf;                                             
    ULONGLONG ReservedForOle;                                              
    ULONG     WaitingOnLoaderLock;                                             
    UCHAR     Padding6[4];                                                     
    ULONGLONG SavedPriorityState;                                          
    ULONGLONG ReservedForCodeCoverage;                                     
    ULONGLONG ThreadPoolData;                                              
    ULONGLONG TlsExpansionSlots;                                           
    ULONGLONG ChpeV2CpuAreaInfo;                                           
    ULONGLONG Unused;                                                      
    ULONG     MuiGeneration;                                                   
    ULONG     IsImpersonating;                                                 
    ULONGLONG NlsCache;                                                    
    ULONGLONG pShimData;                                                   
    ULONG     HeapData;                                                        
    UCHAR     Padding7[4];                                                     
    ULONGLONG CurrentTransactionHandle;                                    
    ULONGLONG ActiveFrame;                                                 
    ULONGLONG FlsData;                                                     
    ULONGLONG PreferredLanguages;                                          
    ULONGLONG UserPrefLanguages;                                           
    ULONGLONG MergedPrefLanguages;                                         
    ULONG     MuiImpersonation;                                                
    union                                                                  
    {                                                                      
        volatile USHORT CrossTebFlags;                                     
        USHORT          SpareCrossTebBits : 16;                                      
    };                                                                     
    union                                                                  
    {                                                                      
        USHORT SameTebFlags;                                               
        struct                                                             
        {                                                                  
            USHORT SafeThunkCall:1;                                        
            USHORT InDebugPrint:1;                                         
            USHORT HasFiberData:1;                                         
            USHORT SkipThreadAttach:1;                                     
            USHORT WerInShipAssertCode:1;                                  
            USHORT RanProcessInit:1;                                       
            USHORT ClonedThread:1;                                         
            USHORT SuppressDebugMsg:1;                                     
            USHORT DisableUserStackWalk:1;                                 
            USHORT RtlExceptionAttached:1;                                 
            USHORT InitialThread:1;                                        
            USHORT SessionAware:1;                                         
            USHORT LoadOwner:1;                                            
            USHORT LoaderWorker:1;                                         
            USHORT SkipLoaderInit:1;                                       
            USHORT SkipFileAPIBrokering:1;                                 
        };                                                                 
    };                                                                     
    ULONGLONG                TxnScopeEnterCallback;                                       
    ULONGLONG                TxnScopeExitCallback;                                        
    ULONGLONG                TxnScopeContext;                                             
    ULONG                    LockCount;                                                       
    LONG                     WowTebOffset;                                                     
    ULONGLONG                ResourceRetValue;                                            
    ULONGLONG                ReservedForWdf;                                              
    ULONGLONG                ReservedForCrt;                                              
    struct _GUID             EffectiveContainerId;                                     
    ULONGLONG                LastSleepCounter;                                            
    ULONG                    SpinCallCount;                                                   
    UCHAR                    Padding8[4];                                                     
    ULONGLONG                ExtendedFeatureDisableMask;                                  
    ULONGLONG                SchedulerSharedDataSlot;                                     
    ULONGLONG                HeapWalkContext;                                             
    struct _GROUP_AFFINITY64 PrimaryGroupAffinity;
    ULONG                    Rcu[2];                                                          
}TEB64, *PTEB64; 
static_assert( sizeof( _TEB64 ) == 0x1878, "Size of _TEB64 does not match the assertion" );
#pragma pack( pop )

#endif