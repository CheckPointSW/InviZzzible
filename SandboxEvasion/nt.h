#ifndef _NT_SE_H
#define _NT_SE_H

#include <WinSock2.h>
#include <Windows.h>

// Privileges

#define SE_MIN_WELL_KNOWN_PRIVILEGE (2L)
#define SE_CREATE_TOKEN_PRIVILEGE (2L)
#define SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3L)
#define SE_LOCK_MEMORY_PRIVILEGE (4L)
#define SE_INCREASE_QUOTA_PRIVILEGE (5L)
#define SE_MACHINE_ACCOUNT_PRIVILEGE (6L)
#define SE_TCB_PRIVILEGE (7L)
#define SE_SECURITY_PRIVILEGE (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE (9L)
#define SE_LOAD_DRIVER_PRIVILEGE (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE (11L)
#define SE_SYSTEMTIME_PRIVILEGE (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE (16L)
#define SE_BACKUP_PRIVILEGE (17L)
#define SE_RESTORE_PRIVILEGE (18L)
#define SE_SHUTDOWN_PRIVILEGE (19L)
#define SE_DEBUG_PRIVILEGE (20L)
#define SE_AUDIT_PRIVILEGE (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE (24L)
#define SE_UNDOCK_PRIVILEGE (25L)
#define SE_SYNC_AGENT_PRIVILEGE (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE (28L)
#define SE_IMPERSONATE_PRIVILEGE (29L)
#define SE_CREATE_GLOBAL_PRIVILEGE (30L)
#define SE_TRUSTED_CREDMAN_ACCESS_PRIVILEGE (31L)
#define SE_RELABEL_PRIVILEGE (32L)
#define SE_INC_WORKING_SET_PRIVILEGE (33L)
#define SE_TIME_ZONE_PRIVILEGE (34L)
#define SE_CREATE_SYMBOLIC_LINK_PRIVILEGE (35L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE SE_CREATE_SYMBOLIC_LINK_PRIVILEGE

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define DIRECTORY_CREATE_OBJECT         (0x0004)
#define DIRECTORY_CREATE_SUBDIRECTORY   (0x0008)
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef PROCESSOR_FEATURE_MAX
#define PROCESSOR_FEATURE_MAX 64
#endif

// enums

#ifndef _MEMORY_INFORMATION_CLASS
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;
#endif

#ifndef _SYSTEM_INFORMATION_CLASS
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformationObsolete = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	SystemThreadPriorityClientIdInformation = 82,
	SystemProcessorIdleCycleTimeInformation = 83,
	SystemVerifierCancellationInformation = 84,
	SystemProcessorPowerInformationEx = 85,
	SystemRefTraceInformation = 86,
	SystemSpecialPoolInformation = 87,
	SystemProcessIdInformation = 88,
	SystemErrorPortInformation = 89,
	SystemBootEnvironmentInformation = 90,
	SystemHypervisorInformation = 91,
	SystemVerifierInformationEx = 92,
	SystemTimeZoneInformation = 93,
	SystemImageFileExecutionOptionsInformation = 94,
	SystemCoverageInformation = 95,
	SystemPrefetchPatchInformation = 96,
	SystemVerifierFaultsInformation = 97,
	SystemSystemPartitionInformation = 98,
	SystemSystemDiskInformation = 99,
	SystemProcessorPerformanceDistribution = 100,
	SystemNumaProximityNodeInformation = 101,
	SystemDynamicTimeZoneInformation = 102,
	SystemCodeIntegrityInformation = 103,
	SystemProcessorMicrocodeUpdateInformation = 104,
	SystemProcessorBrandString = 105,
	SystemVirtualAddressInformation = 106,
	SystemLogicalProcessorAndGroupInformation = 107,
	SystemProcessorCycleTimeInformation = 108,
	SystemStoreInformation = 109,
	SystemRegistryAppendString = 110,
	SystemAitSamplingValue = 111,
	SystemVhdBootInformation = 112,
	SystemCpuQuotaInformation = 113,
	SystemNativeBasicInformation = 114,
	SystemErrorPortTimeouts = 115,
	SystemLowPriorityIoInformation = 116,
	SystemBootEntropyInformation = 117,
	SystemVerifierCountersInformation = 118,
	SystemPagedPoolInformationEx = 119,
	SystemSystemPtesInformationEx = 120,
	SystemNodeDistanceInformation = 121,
	SystemAcpiAuditInformation = 122,
	SystemBasicPerformanceInformation = 123,
	SystemQueryPerformanceCounterInformation = 124,
	SystemSessionBigPoolInformation = 125,
	SystemBootGraphicsInformation = 126,
	SystemScrubPhysicalMemoryInformation = 127,
	SystemBadPageInformation = 128,
	SystemProcessorProfileControlArea = 129,
	SystemCombinePhysicalMemoryInformation = 130,
	SystemEntropyInterruptTimingInformation = 131,
	SystemConsoleInformation = 132,
	SystemPlatformBinaryInformation = 133,
	SystemPolicyInformation = 134,
	SystemHypervisorProcessorCountInformation = 135,
	SystemDeviceDataInformation = 136,
	SystemDeviceDataEnumerationInformation = 137,
	SystemMemoryTopologyInformation = 138,
	SystemMemoryChannelInformation = 139,
	SystemBootLogoInformation = 140,
	SystemProcessorPerformanceInformationEx = 141,
	SystemSpare0 = 142,
	SystemSecureBootPolicyInformation = 143,
	SystemPageFileInformationEx = 144,
	SystemSecureBootInformation = 145,
	SystemEntropyInterruptTimingRawInformation = 146,
	SystemPortableWorkspaceEfiLauncherInformation = 147,
	SystemFullProcessInformation = 148,
	SystemKernelDebuggerInformationEx = 149,
	SystemBootMetadataInformation = 150,
	SystemSoftRebootInformation = 151,
	SystemElamCertificateInformation = 152,
	SystemOfflineDumpConfigInformation = 153,
	SystemProcessorFeaturesInformation = 154,
	SystemRegistryReconciliationInformation = 155,
	SystemEdidInformation = 156,
	MaxSystemInfoClass = 157
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
#endif

// structures

#ifndef _OBJECT_DIRECTORY_INFORMATION
typedef struct _OBJECT_DIRECTORY_INFORMATION {
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;
#endif

#ifndef _MEMORY_REGION_INFORMATION
typedef struct _MEMORY_REGION_INFORMATION {
	PVOID AllocationBase;
	ULONG AllocationProtect;
	ULONG RegionType;
	SIZE_T RegionSize;
} MEMORY_REGION_INFORMATION, *PMEMORY_REGION_INFORMATION;
#endif

#ifndef _OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
#endif

#ifndef _CLIENT_ID
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;
#endif

#ifndef _SYSTEM_FIRMWARE_TABLE_ACTION
typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
	SystemFirmwareTable_Enumerate,
	SystemFirmwareTable_Get
} SYSTEM_FIRMWARE_TABLE_ACTION, *PSYSTEM_FIRMWARE_TABLE_ACTION;
#endif

#ifndef _SYSTEM_FIRMWARE_TABLE_INFORMATION
typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
	ULONG ProviderSignature;
	SYSTEM_FIRMWARE_TABLE_ACTION Action;
	ULONG TableID;
	ULONG TableBufferLength;
	UCHAR TableBuffer[ANYSIZE_ARRAY];
} SYSTEM_FIRMWARE_TABLE_INFORMATION, *PSYSTEM_FIRMWARE_TABLE_INFORMATION;
#endif

#ifndef _NT_PRODUCT_TYPE
typedef enum _NT_PRODUCT_TYPE
{
	NtProductWinNt = 1,
	NtProductLanManNt = 2,
	NtProductServer = 3
} NT_PRODUCT_TYPE;
#endif

#ifndef _KSYSTEM_TIME
typedef struct _KSYSTEM_TIME
{
	ULONG LowPart;
	LONG High1Time;
	LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;
#endif

#ifndef _ALTERNATIVE_ARCHITECTURE_TYPE
typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
	StandardDesign,                 // None == 0 == standard design
	NEC98x86,                       // NEC PC98xx series on X86
	EndAlternatives                 // past end of known alternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;
#endif

#ifndef _KUSER_SHARED_DATA
typedef struct _KUSER_SHARED_DATA {
	//
	// Current low 32-bit of tick count and tick count multiplier.
	//
	// N.B. The tick count is updated each time the clock ticks.
	//
	ULONG TickCountLowDeprecated;
	ULONG TickCountMultiplier;
	//
	// Current 64-bit interrupt time in 100ns units.
	//
	volatile KSYSTEM_TIME InterruptTime;
	//
	// Current 64-bit system time in 100ns units.
	//
	volatile KSYSTEM_TIME SystemTime;
	//
	// Current 64-bit time zone bias.
	//
	volatile KSYSTEM_TIME TimeZoneBias;
	//
	// Support image magic number range for the host system.
	//
	// N.B. This is an inclusive range.
	//
	USHORT ImageNumberLow;
	USHORT ImageNumberHigh;
	//
	// Copy of system root in unicode.
	//
	WCHAR NtSystemRoot[260];
	//
	// Maximum stack trace depth if tracing enabled.
	//
	ULONG MaxStackTraceDepth;
	//
	// Crypto exponent value.
	//
	ULONG CryptoExponent;
	//
	// Time zone ID.
	//
	ULONG TimeZoneId;
	ULONG LargePageMinimum;
	//
	// This value controls the AIT Sampling rate.
	//
	ULONG AitSamplingValue;
	//
	// This value controls switchback processing.
	//
	ULONG AppCompatFlag;
	//
	// Current Kernel Root RNG state seed version
	//
	ULONGLONG RNGSeedVersion;
	//
	// This value controls assertion failure handling.
	//
	ULONG GlobalValidationRunlevel;
	volatile LONG TimeZoneBiasStamp;
	//
	// Reserved (available for reuse).
	//
	ULONG Reserved2;
	//
	// Product type.
	//
	NT_PRODUCT_TYPE NtProductType;
	BOOLEAN ProductTypeIsValid;
	BOOLEAN Reserved0[1];
	USHORT NativeProcessorArchitecture;
	//
	// The NT Version.
	//
	// N. B. Note that each process sees a version from its PEB, but if the
	//       process is running with an altered view of the system version,
	//       the following two fields are used to correctly identify the
	//       version
	//
	ULONG NtMajorVersion;
	ULONG NtMinorVersion;
	//
	// Processor features.
	//
	BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
	//
	// Reserved fields - do not use.
	//
	ULONG Reserved1;
	ULONG Reserved3;
	//
	// Time slippage while in debugger.
	//
	volatile ULONG TimeSlip;
	//
	// Alternative system architecture, e.g., NEC PC98xx on x86.
	//
	ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
	//
	// Four bytes of padding here -- offsets 0x2c4, 0x2c5, 0x2c6, 0x2c7
	//
	ULONG AltArchitecturePad[1];
	//
	// If the system is an evaluation unit, the following field contains the
	// date and time that the evaluation unit expires. A value of 0 indicates
	// that there is no expiration. A non-zero value is the UTC absolute time
	// that the system expires.
	//
	LARGE_INTEGER SystemExpirationDate;
	//
	// Suite support.
	//
	ULONG SuiteMask;
	//
	// TRUE if a kernel debugger is connected/enabled.
	//
	BOOLEAN KdDebuggerEnabled;
	//
	// Mitigation policies.
	//
	union
	{
		UCHAR MitigationPolicies;
		struct
		{
			UCHAR NXSupportPolicy : 2;
			UCHAR SEHValidationPolicy : 2;
			UCHAR CurDirDevicesSkippedForDlls : 2;
			UCHAR Reserved : 2;
		};
	};
	//
	// Two bytes of padding here -- offsets 0x2d6, 0x2d7
	//
	UCHAR Reserved6[2];
	//
	// Current console session Id. Always zero on non-TS systems.
	//
	volatile ULONG ActiveConsoleId;
	//
	// Force-dismounts cause handles to become invalid. Rather than always
	// probe handles, a serial number of dismounts is maintained that clients
	// can use to see if they need to probe handles.
	//
	volatile ULONG DismountCount;
	//
	// This field indicates the status of the 64-bit COM+ package on the
	// system. It indicates whether the Itermediate Language (IL) COM+
	// images need to use the 64-bit COM+ runtime or the 32-bit COM+ runtime.
	//
	ULONG ComPlusPackage;
	//
	// Time in tick count for system-wide last user input across all terminal
	// sessions. For MP performance, it is not updated all the time (e.g. once
	// a minute per session). It is used for idle detection.
	//
	ULONG LastSystemRITEventTickCount;
	//
	// Number of physical pages in the system. This can dynamically change as
	// physical memory can be added or removed from a running system.
	//
	ULONG NumberOfPhysicalPages;
	//
	// True if the system was booted in safe boot mode.
	//
	BOOLEAN SafeBootMode;
	//
	// Reserved (available for reuse).
	//
	UCHAR Reserved12[3];
	//
	// This is a packed bitfield that contains various flags concerning
	// the system state. They must be manipulated using interlocked
	// operations.
	//
	union {
		ULONG SharedDataFlags;
		struct {
			//
			// The following bit fields are for the debugger only. Do not use.
			// Use the bit definitions instead.
			//
			ULONG DbgErrorPortPresent : 1;
			ULONG DbgElevationEnabled : 1;
			ULONG DbgVirtEnabled : 1;
			ULONG DbgInstallerDetectEnabled : 1;
			ULONG DbgLkgEnabled : 1;
			ULONG DbgDynProcessorEnabled : 1;
			ULONG DbgConsoleBrokerEnabled : 1;
			ULONG DbgSecureBootEnabled : 1;
			ULONG SpareBits : 24;
		} DUMMYSTRUCTNAME2;
	} DUMMYUNIONNAME2;
	ULONG DataFlagsPad[1];
	//
	// Depending on the processor, the code for fast system call will differ,
	// Stub code is provided pointers below to access the appropriate code.
	//
	// N.B. The following field is only used on 32-bit systems.
	//
	ULONGLONG TestRetInstruction;
	LONGLONG QpcFrequency;
	//
	// Reserved, available for reuse.
	//
	ULONGLONG SystemCallPad[3];
	//
	// The 64-bit tick count.
	//
	union {
		volatile KSYSTEM_TIME TickCount;
		volatile ULONG64 TickCountQuad;
		struct {
			ULONG ReservedTickCountOverlay[3];
			ULONG TickCountPad[1];
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME3;
	//
	// Cookie for encoding pointers system wide.
	//
	ULONG Cookie;
	ULONG CookiePad[1];
	//
	// Client id of the process having the focus in the current
	// active console session id.
	//
	LONGLONG ConsoleSessionForegroundProcessId;
	//
	// N.B. The following data is used to implement the precise time
	//      services. It is aligned on a 64-byte cache-line boundary and
	//      arranged in the order of typical accesses.
	//
	// Placeholder for the (internal) time update lock.
	//
	ULONGLONG TimeUpdateLock;
	//
	// The performance counter value used to establish the current system time.
	//
	ULONGLONG BaselineSystemTimeQpc;
	//
	// The performance counter value used to compute the last interrupt time.
	//
	ULONGLONG BaselineInterruptTimeQpc;
	//
	// The scaled number of system time seconds represented by a single
	// performance count (this value may vary to achieve time synchronization).
	//
	ULONGLONG QpcSystemTimeIncrement;
	//
	// The scaled number of interrupt time seconds represented by a single
	// performance count (this value is constant after the system is booted).
	//
	ULONGLONG QpcInterruptTimeIncrement;
	//
	// An appropriately rounded 32-bit version of the scaled performance counter
	// system time increment.
	//
	ULONG QpcSystemTimeIncrement32;
	//
	// An appropriately rounded 32-bit version of the scaled performance counter
	// interrupt time increment.
	//
	ULONG QpcInterruptTimeIncrement32;
	//
	// The scaling shift count applied to the performance counter system time
	// increment.
	//
	UCHAR QpcSystemTimeIncrementShift;
	//
	// The scaling shift count applied to the performance counter interrupt time
	// increment.
	//
	UCHAR QpcInterruptTimeIncrementShift;
	//
	// The count of unparked processors.
	//
	USHORT UnparkedProcessorCount;
	//
	// Reserved (available for reuse).
	//

	UCHAR Reserved8[12];
	//
	// The following field is used for ETW user mode global logging
	// (UMGL).
	//
	USHORT UserModeGlobalLogger[16];
	//
	// Settings that can enable the use of Image File Execution Options
	// from HKCU in addition to the original HKLM.
	//
	ULONG ImageFileExecutionOptions;
	//
	// Generation of the kernel structure holding system language information
	//
	ULONG LangGenerationCount;
	//
	// Reserved (available for reuse).
	//
	ULONGLONG Reserved4;
	//
	// Current 64-bit interrupt time bias in 100ns units.
	//
	volatile ULONGLONG InterruptTimeBias;
	//
	// Current 64-bit performance counter bias, in performance counter units
	// before the shift is applied.
	//
	volatile ULONGLONG QpcBias;
	//
	// Number of active processors and groups.
	//
	ULONG ActiveProcessorCount;
	volatile UCHAR ActiveGroupCount;
	//
	// Reserved (available for re-use).
	//
	UCHAR Reserved9;
	union {
		USHORT QpcData;
		struct {
			//
			// A boolean indicating whether performance counter queries
			// can read the counter directly (bypassing the system call).
			//
			volatile BOOLEAN QpcBypassEnabled;
			//
			// Shift applied to the raw counter value to derive the
			// QPC count.
			//
			UCHAR QpcShift;
		};
	};
	LARGE_INTEGER TimeZoneBiasEffectiveStart;
	LARGE_INTEGER TimeZoneBiasEffectiveEnd;
	//
	// Extended processor state configuration
	//
	XSTATE_CONFIGURATION XState;
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;
#endif

// functions

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

//
// Valid values for the Attributes field
//

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_KERNEL_HANDLE       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK  0x00000400L
#define OBJ_VALID_ATTRIBUTES    0x000007F2L

#endif

NTSTATUS NTAPI NtOpenProcess(
	_Out_		PHANDLE ProcessHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_		POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	PCLIENT_ID ClientId
	);

NTSTATUS NTAPI RtlGetVersion(
	_Inout_	PRTL_OSVERSIONINFOW lpVersionInformation
	);

NTSTATUS WINAPI NtQuerySystemInformation(
	_In_       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_    PVOID SystemInformation,
	_In_       ULONG SystemInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

NTSTATUS NTAPI NtQueryVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_ PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);

NTSTATUS NTAPI NtReadVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
	);

ULONG NTAPI CsrGetProcessId(
	);

NTSTATUS NTAPI NtClose(
	_In_ HANDLE Handle
	);

NTSTATUS NTAPI NtOpenProcessToken(
	_In_	HANDLE ProcessHandle,
	_In_	ACCESS_MASK DesiredAccess,
	_Out_	PHANDLE TokenHandle
	);

NTSTATUS NTAPI NtAdjustPrivilegesToken(
	_In_		HANDLE TokenHandle,
	_In_		BOOLEAN DisableAllPrivileges,
	_In_opt_	PTOKEN_PRIVILEGES NewState,
	_In_opt_	ULONG BufferLength,
	_Out_opt_	PTOKEN_PRIVILEGES PreviousState,
	_Out_opt_	PULONG ReturnLength
	);

#endif // !_NT_H

