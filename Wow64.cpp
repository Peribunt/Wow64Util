#include "Wow64.h"

#if defined _WIN32 && !_WIN64

#pragma warning( push )
#pragma warning( disable : 6101 )

#define WOW64API __declspec( noinline, naked )
#define WOW64_MAX_VECTORED_HANDLERS 128

#define Wow64AcquireSpinlock( _ ) while( _InterlockedExchange8( &_, TRUE ) == TRUE ) \
                                    _mm_pause( )
#define Wow64ReleaseSpinlock( _ ) _InterlockedExchange8( &_, FALSE )

//
// Our vectored exception handler list
//
PWOW64_VECTORED_EXCEPTION_HANDLER g_Wow64VectoredExceptionHandlers[ WOW64_MAX_VECTORED_HANDLERS ];

//
// Wow64InfoPtr for instrumentation callbacks from the wow64 layer
//
UINT64 g_Wow64InfoPtr             = NULL;

//
// Wow64PrepareForException for the 64-bit KiUserExceptionDispatcher hook
//
UINT64 g_Wow64PrepareForException = NULL;

//
// A pointer to our function hook handler shellcode
//
LPVOID g_Wow64HookHandlers        = NULL;

//
// Spinlock for VEH list functions
//
CHAR g_Wow64VEHListLock           = FALSE;

//
// Spinlock for hook list functions
//
CHAR g_Wow64HookListLock          = FALSE;

//
// 64-bit NtProtectVirtualMemory pointer
//
UINT64 NtProtectVirtualMemory64   = NULL;

//
// 64-bit NtContinue pointer
//
UINT64 NtContinue64               = NULL;

UINT8 Wow64HookTransition_Data[ ]
{
    //
    // Preserve RAX in our TEB storage location so we can preserve flags as early as possible
    //
    0x65, 0x48, 0x89, 0x04, 0x25, 0xD8, 0x02, 0x00, 0x00, // mov qword ptr gs:0x2D8, rax
    0x9C,                                                 // pushfq
    0x58,                                                 // pop rax

    //
    // Ensure the stack pointer is aligned properly
    //
    0x65, 0x48, 0x89, 0x24, 0x25, 0xE0, 0x02, 0x00, 0x00, // mov qword ptr gs:0x2E0, rsp
    0x48, 0x83, 0xE4, 0xF0,                               // and rsp, 0xFFFFFFFFFFFFFFF0

    //
    // sub rsp, 0x1000
    //
    0x48, 0x81, 0xEC, 0x00, 0x10, 0x00, 0x00,

    //
    // Free up space on the stack for the 64-bit context
    //
    0x48, 0x81, 0xEC, 0xD0, 0x04, 0x00, 0x00,             // sub rsp, 0x4D0(sizeof(CONTEXT64))

    //
    // Store EFLAGS
    // 
    0x89, 0x44, 0x24, 0x44,                               // mov dword ptr[rsp+0x44], eax

    //
    // Store volatile registers
    //
    0x65, 0x48, 0x8B, 0x04, 0x25, 0xD8, 0x02, 0x00, 0x00, // mov rax, mov qword ptr gs:0x2D8
    0x48, 0x89, 0x44, 0x24, 0x78,                         // mov qword ptr[rsp+0x78], rax
    0x48, 0x89, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0x80], rcx
    0x48, 0x89, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0x88], rdx
    0x4C, 0x89, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xB8], r8
    0x4C, 0x89, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xC0], r9

    //
    // Store non-volatile registers
    //
    0x4C, 0x89, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xC8], r10
    0x4C, 0x89, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xD0], r11
    0x48, 0x89, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0x90], rbx
    0x48, 0x89, 0xAC, 0x24, 0xA0, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xA0], rbp
    0x48, 0x89, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xA8], rsi
    0x48, 0x89, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xB0], rdi
    0x4C, 0x89, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xD8], r12
    0x4C, 0x89, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xE0], r13
    0x4C, 0x89, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xE8], r14
    0x4C, 0x89, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xF0], r15

    //
    // Store stack pointer
    //
    0x65, 0x48, 0x8B, 0x04, 0x25, 0xE0, 0x02, 0x00, 0x00, // mov rax, qword ptr gs:0x2E0
    0x48, 0x83, 0xC0, 0x08,                               // add rax, 8
    0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0x98], rax

    //
    // Store RIP
    //
    0x48, 0x8B, 0x40, 0xF8,                               // mov rax, qword ptr[rax-0x8]
    0x48, 0x83, 0xE8, 0x06,                               // sub rax, 6
    0x48, 0x89, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00,       // mov qword ptr[rsp+0xF8], rax

    //
    // Store MXCSR
    //
    0x0F, 0xAE, 0x5C, 0x24, 0x34,                         // stmxcsr dword ptr[rsp+0x34]

    //
    // Store x87 FPU, MMX, and SSE State
    //
    0x0F, 0xAE, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00,       // fxsave [rsp+0x100]

    //
    // Transition to 32-bit
    //
    0xE8, 0x00, 0x00, 0x00, 0x00,                         // call $+5       
    0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,       // mov dword ptr[rsp+0x04], 0x23
    0x83, 0x04, 0x24, 0x0D,                               // add qword ptr[rsp], 0x0D
    0xCB,                                                 // retf

    0x8D, 0x0C, 0x24,
    0x51,
    0xB9, 0x00, 0x00, 0x00, 0x00, 
    0xFF, 0xD1,
    0x83, 0xC4, 0x04,

    //
    // Transition to 64-bit
    //
    0x6A, 0x33,                                           // push 0x33                 
    0xE8, 0x00, 0x00, 0x00, 0x00,                         // call $+5
    0x83, 0x04, 0x24, 0x05,                               // add dword ptr[esp], 5
    0xCB,                                                 // retf

    //
    // Restore 64-bit context
    //
    0x48, 0x8B, 0x84, 0x24, 0xF8, 0x00, 0x00, 0x00,       // mov rax, qword ptr[rsp+0xF8]
    0x65, 0x48, 0x89, 0x04, 0x25, 0xD8, 0x02, 0x00, 0x00, // mov qword ptr gs:0x2D8, rax
    0x48, 0x8B, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,       // mov rax, qword ptr[rsp+0x98]
    0x65, 0x48, 0x89, 0x04, 0x25, 0xE0, 0x02, 0x00, 0x00, // mov qword ptr gs:0x2E0, rax
    0x0F, 0xAE, 0x54, 0x24, 0x34,                         // ldmxcsr dword ptr[rsp+0x34]
    0x0F, 0xAE, 0x8C, 0x24, 0x00, 0x01, 0x00, 0x00,       // fxrstor [rsp+0x100]
    0x48, 0x31, 0xC0,                                     // xor rax, rax
    0x8B, 0x44, 0x24, 0x44,                               // mov eax, dword ptr[rsp+0x44]
    0x50,                                                 // push rax
    0x9D,                                                 // popfq
    0x48, 0x8B, 0x44, 0x24, 0x78,                         // mov rax, qword ptr[rsp+0x78]
    0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,       // mov rcx, qword ptr[rsp+0x80]
    0x48, 0x8B, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,       // mov rdx, qword ptr[rsp+0x88]
    0x4C, 0x8B, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,       // mov r8,  qword ptr[rsp+0xB8]
    0x4C, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,       // mov r9,  qword ptr[rsp+0xC0]
    0x4C, 0x8B, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,       // mov r10, qword ptr[rsp+0xC8]
    0x4C, 0x8B, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,       // mov r11, qword ptr[rsp+0xD0]
    0x48, 0x8B, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,       // mov rbx, qword ptr[rsp+0x90]
    0x48, 0x8B, 0xAC, 0x24, 0xA0, 0x00, 0x00, 0x00,       // mov rbp, qword ptr[rsp+0xA0]
    0x48, 0x8B, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,       // mov rsi, qword ptr[rsp+0xA8]
    0x48, 0x8B, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,       // mov rdi, qword ptr[rsp+0xB0]
    0x4C, 0x8B, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,       // mov r12, qword ptr[rsp+0xD8]
    0x4C, 0x8B, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,       // mov r13, qword ptr[rsp+0xE0]
    0x4C, 0x8B, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,       // mov r14, qword ptr[rsp+0xE8]
    0x4C, 0x8B, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,       // mov r15, qword ptr[rsp+0xF0]
    0x65, 0x48, 0x8B, 0x24, 0x25, 0xE0, 0x02, 0x00, 0x00, // mov rsp, qword ptr gs:0x2E0
    0x65, 0xFF, 0x24, 0x25, 0xD8, 0x02, 0x00, 0x00        // jmp qword ptr gs:0x2D8
};

#pragma pack( push, 1 )
typedef struct _WOW64_HOOK_TRANSITION
{
    UINT8  Padding01    [ 0xF1 ];
    LPVOID HandlerFunction;
    UINT8  Padding02    [ 0xF0 ];
    UINT64 Target;
    UINT8  OriginalBytes[ 0x13 ];
}WOW64_HOOK_TRANSITION, * PWOW64_HOOK_TRANSITION;
static_assert( sizeof( _WOW64_HOOK_TRANSITION ) == 512, "Size of _WOW64_HOOK_TRANSITION does not match the assertion!" );
#pragma pack( pop )

//
// I know what I'm doing, stop 'optimizing' you cretin.
//
#pragma optimize( "", off )
VOID
WOW64API
Wow64CopyMemory( 
    _Out_ UINT64 Destination, 
    _In_  UINT64 Source, 
    _In_  UINT64 Length 
    )
{
    __asm
    {
        //
        // Preserve nonvolatile registers
        //
        push edi
        push esi

        //
        // Exit 32-bit mode
        //
        Wow64Exit32( );

        //
        // mov rdi, qword ptr[rsp+0x0C]
        //
        db( 0x48 ) db( 0x8B ) db( 0x7C ) db( 0x24 ) db( 0x0C )
        //
        // mov rsi, qword ptr[rsp+0x14]
        //
        db( 0x48 ) db( 0x8B ) db( 0x74 ) db( 0x24 ) db( 0x14 )
        //
        // mov rcx, qword ptr[rsp+0x1C]
        //
        db( 0x48 ) db( 0x8B ) db( 0x4C ) db( 0x24 ) db( 0x1C )

        rep movsb

        //
        // Re-enter 32-bit mode
        //
        Wow64Enter32( );

        //
        // Restore nonvolatile registers
        //
        pop  esi
        pop  edi
        ret
    }
}

BOOLEAN
WOW64API
Wow64CompareMemory( 
    _In_ UINT64 Source1, 
    _In_ UINT64 Source2,
    _In_ UINT64 Length
    )
{
    __asm
    {
        xor eax, eax

        //
        // Preserve nonvolatile registers
        //
        push edi
        push esi

        //
        // Exit 32-bit mode
        //
        Wow64Exit32( );

        //
        // mov rdi, qword ptr[rsp+0x0C]
        //
        db( 0x48 ) db( 0x8B ) db( 0x7C ) db( 0x24 ) db( 0x0C )
        //
        // mov rsi, qword ptr[rsp+0x14]
        //
        db( 0x48 ) db( 0x8B ) db( 0x74 ) db( 0x24 ) db( 0x14 )
        //
        // mov rcx, qword ptr[rsp+0x1C]
        //
        db( 0x48 ) db( 0x8B ) db( 0x4C ) db( 0x24 ) db( 0x1C )

        rep cmpsb
        jz  match
        mov al, 1
    match:

        //
        // Re-enter 32-bit mode
        //
        Wow64Enter32( );

        //
        // Restore nonvolatile registers
        //
        pop  esi
        pop  edi
        ret
    }
}

UINT64
WOW64API
Wow64ReadGsQword( 
    _In_ UINT32 Offset 
    )
{
    __asm
    {
        mov eax, dword ptr[ esp + 0x04 ]

        Wow64Exit32( );

        //
        // mov rax, qword ptr gs:eax
        //
        db( 0x65 ) db( 0x67 ) db( 0x48 ) db( 0x8B ) db( 0x00 )

        //
        // mov rdx, rax
        //
        db( 0x48 ) db( 0x89 ) db( 0xC2 )

        //
        // shr rdx, 32
        //
        db( 0x48 ) db( 0xC1 ) db( 0xEA ) db( 0x20 )

        Wow64Enter32( );

        ret
    }
}

UINT32
WOW64API
Wow64ReadGsDword( 
    _In_ UINT32 Offset 
    )
{
    __asm
    {
        mov edx, dword ptr[ esp + 0x04 ]

        Wow64Exit32( );

        //
        // xor rax, rax
        //
        db( 0x48 ) db( 0x31 ) db( 0xC0 )

        //
        // mov eax, dword ptr gs:edx
        //
        db( 0x65 ) db( 0x67 ) db( 0x8B ) db( 0x02 )

        Wow64Enter32( );

        ret
    }
}

UINT16
WOW64API
Wow64ReadGsWord( 
    _In_ UINT32 Offset 
    )
{
    __asm
    {
        mov edx, dword ptr[ esp + 0x04 ]

        Wow64Exit32( );

        //
        // xor rax, rax
        //
        db( 0x48 ) db( 0x31 ) db( 0xC0 )

        //
        // mov ax, dword ptr gs:edx
        //
        db( 0x65 ) db( 0x67 ) db( 0x66 ) db( 0x8B ) db( 0x02 )

        Wow64Enter32( );

        ret
    }
}

UINT8
WOW64API
Wow64ReadGsByte( 
    _In_ UINT32 Offset 
    )
{
    __asm
    {
        mov edx, dword ptr[ esp + 0x04 ]

        Wow64Exit32( );

        //
        // xor rax, rax
        //
        db( 0x48 ) db( 0x31 ) db( 0xC0 )

        //
        // mov al, byte ptr gs:edx
        //
        db( 0x65 ) db( 0x67 ) db( 0x8A ) db( 0x02 )

        Wow64Enter32( );

        ret
    }
}

UINT64
WOW64API
Wow64CallProcedureRaw(
    _In_ UINT64  TargetProcedure,
    ...
    )
{
    __asm
    {
        //
        // Store the return address in TEB32->LastErrorValue
        //
        mov eax, dword ptr[esp]
        mov dword ptr fs:0x1504, eax

        //
        // Increment over our 32-bit return address
        //
        add esp, 4

        Wow64Exit32( );

        //
        // Store argument 'TargetProcedure' in rax
        //
        db( 0x58 )                                  // pop rax

        //
        // Pop the first four arguments into rcx, rdx, r8 and r9
        //
        db( 0x59 )                                  // pop rcx
        db( 0x5A )                                  // pop rdx
        db( 0x41 ) db( 0x58 )                       // pop r8
        db( 0x41 ) db( 0x59 )                       // pop r9

        //
        // Reserve 0x20 bytes of stack space in case the function takes more arguments
        //
        db( 0x48 ) db( 0x83 ) db( 0xEC ) db( 0x20 ) // sub rsp, 0x20

        //
        // Call target procedure
        //
        db( 0xFF ) db( 0xD0 )                       // call rax

        Wow64Enter32( );

        //
        // Realign stack
        //
        sub esp, 8

        //
        // Return to caller
        //
        jmp dword ptr fs:0x1504
    }
}
#pragma optimize( "", on )

UINT64
Wow64GetInfoPtr( 
    VOID 
    )
{
    UINT64 Wow64Dll     = Wow64GetModuleHandleA( "wow64.dll" ),
	       Wow64InfoPtr = NULL;
	CHAR   FuncData[ 0x200 ]{ };
	PUINT8 CurData = ( PUINT8 )&FuncData;

	if ( Wow64Dll == NULL ) {
		return NULL;
	}

	UINT64 Wow64LdrpInitialize = Wow64GetProcAddress( Wow64Dll, "Wow64LdrpInitialize" );

	if ( Wow64LdrpInitialize == NULL ) {
		return NULL;
	}
	
	//
	// Copy some data to look through
	//
	Wow64CopyMemory( ( UINT64 )&FuncData, Wow64LdrpInitialize, sizeof( FuncData ) );

    //
    // We are looking for the first instruction within Wow64LdrpInitialize that uses a RIP relative store to memory
    // 
    //     mov cs:Wow64InfoPtr, gpr
    //
	for ( UINT32 i = 0; i < sizeof( FuncData ); i++ )
	{        
		//
		// Search for a mov instruction (REX.W + 0x89)
		//
		if ( *( UINT16* )( CurData ) == 0x8948 && 
		//
		// Search for a [RIP+disp32] modr/m
		//
		   ( *( UINT8* )( CurData + 2 ) & 0b111 )      == 0b101 &&
		   ( *( UINT8* )( CurData + 2 ) & 0b11000000 ) == 0 )
		{
			UINT64 CurrentInstruction = Wow64LdrpInitialize + i;

			//
			// Resolve the RIP relative location
			//
			Wow64InfoPtr = CurrentInstruction + 7 + *( INT32* )( CurData + 3 );

			Wow64InfoPtr = Wow64ReadData< UINT64 >( Wow64InfoPtr );

			break;
		}

		CurData++;
	}

    return Wow64InfoPtr;
}

BOOLEAN
Wow64RegisterInstrumentationCallback( 
    _In_ LPVOID InstrumentationCallback 
    )
{
    UINT64 InfoPtr = Wow64GetInfoPtr( );

    if ( InfoPtr == NULL ) {
        return FALSE;
    }

    *( LPVOID* )( InfoPtr + 8 ) = InstrumentationCallback;

    return TRUE;
}

UINT64
__wow64_fnv1a_w( 
    _In_ LPCWSTR String 
    )
{
    UINT64 Hash = 0xCBF29CE484222325;

    while ( *String )
    {
        WCHAR Char = ( *String > L'A' && *String < L'Z' ) ? ( *String - L'A' + L'a' ) : *String;

        Hash = Hash ^ ( UINT8 )( Char & 0xFF );
        Hash = Hash * 0x100000001B3;

        Hash = Hash ^ ( UINT8 )( ( Char >> 8 ) & 0xFF );
        Hash = Hash * 0x100000001B3;

        String++;
    }

    return Hash;
}

DECLSPEC_NOINLINE
UINT64
Wow64GetModuleHandleW( 
    _In_ LPCWSTR ModuleName 
    )
{
    WCHAR DllNameBuffer[ MAX_PATH + 1 ]{ };
    
    UINT64 ModuleNameHash = __wow64_fnv1a_w( ModuleName );

    //
    // TEB->ProcessEnvironmentBlock
    //
    UINT64 PEBPointer = Wow64ReadGsQword( 0x60 );

    //
    // PEB->Ldr
    //
    UINT64 LdrPointer = Wow64ReadData( PEBPointer + FIELD_OFFSET( PEB64, Ldr ) );

    //
    // Ldr->InLoadOrderModuleList->Flink
    //
    UINT64 FirstEntry   = LdrPointer + FIELD_OFFSET( PEB_LDR_DATA64, InLoadOrderModuleList );
    UINT64 CurrentEntry = Wow64ReadData( FirstEntry );

    while ( CurrentEntry != FirstEntry )
    {
        UINT16 DllNameLength  = Wow64ReadData<UINT16>( CurrentEntry + 0x58 );
        UINT64 DllNamePointer = Wow64ReadData( CurrentEntry + 0x60 );

        if ( DllNamePointer == NULL )
            continue;

        RtlZeroMemory( DllNameBuffer, sizeof( DllNameBuffer ) );

        Wow64CopyMemory( ( UINT64 )DllNameBuffer, DllNamePointer, min( DllNameLength, MAX_PATH ) );

        if ( __wow64_fnv1a_w( DllNameBuffer ) == ModuleNameHash )
        {
            //
            // CurrentEntry->DllBase
            //
            return Wow64ReadData( CurrentEntry + 0x30 );
        }

        //
        // Advance to the next entry
        //
        CurrentEntry = Wow64ReadData( CurrentEntry );
    }

    return NULL;
}

DECLSPEC_NOINLINE
UINT64
Wow64GetProcAddress( 
    _In_ UINT64 Module, 
    _In_ LPCSTR ProcedureName 
    )
{
    CHAR ProcNameBuffer[ MAX_PATH + 1 ]{ };

    IMAGE_DOS_HEADER DosHeader = Wow64ReadData< IMAGE_DOS_HEADER >( Module );

    if ( DosHeader.e_magic != IMAGE_DOS_SIGNATURE ) 
    {
        return NULL;
    }

    IMAGE_NT_HEADERS64 NtHeaders = Wow64ReadData< IMAGE_NT_HEADERS64 >( Module + DosHeader.e_lfanew );

    if ( NtHeaders.Signature            != IMAGE_NT_SIGNATURE || 
         NtHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ) 
    {
        return NULL;
    }

    IMAGE_EXPORT_DIRECTORY ExportDir = Wow64ReadData< IMAGE_EXPORT_DIRECTORY >( 
        Module + 
        NtHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress 
        );

    for ( UINT32 i = 0; i < ExportDir.NumberOfFunctions; i++ )
    {
        UINT16 OrdinalRVA  = Wow64ReadData< UINT16 >( Module + ExportDir.AddressOfNameOrdinals + ( i * 2 ) );
        UINT32 FunctionRVA = Wow64ReadData< UINT32 >( Module + ExportDir.AddressOfFunctions    + ( OrdinalRVA * 4 ) );
        UINT32 NameRVA     = Wow64ReadData< UINT32 >( Module + ExportDir.AddressOfNames        + ( i * 4 ) );

        if ( Wow64CompareMemory( Module + NameRVA, ( UINT64 )ProcedureName, lstrlenA( ProcedureName ) ) == 0 )
        {
            return Module + FunctionRVA;
        }
    }

    return NULL;
}

UINT64
Wow64GetModuleHandleA( 
    _In_ LPCSTR ModuleName 
    )
{
    WCHAR ModuleNameW[ MAX_PATH ]{ };
    
    //
    // Convert module name to wide character string
    //
    MultiByteToWideChar( CP_ACP, 0, ModuleName, lstrlenA( ModuleName ), ModuleNameW, MAX_PATH );

    return Wow64GetModuleHandleW( ModuleNameW );
}

BOOLEAN
Wow64GetImageNtHeaders( 
    _In_  UINT64              ModuleBase,
    _Out_ PIMAGE_NT_HEADERS64 NtHeaders
    )
{
    IMAGE_DOS_HEADER DosHeader = Wow64ReadData< IMAGE_DOS_HEADER >( ModuleBase );

    if ( DosHeader.e_magic != IMAGE_DOS_SIGNATURE )
    {
        return FALSE;
    }

    Wow64CopyMemory( ( UINT64 )NtHeaders, ModuleBase + DosHeader.e_lfanew, sizeof( IMAGE_NT_HEADERS64 ) );

    if ( NtHeaders->Signature != IMAGE_NT_SIGNATURE )
    {
        return FALSE;
    }

    return TRUE;
}

NTSTATUS
Wow64ProtectVirtualMemory( 
    _In_      UINT64 Address, 
    _In_      SIZE_T Length, 
    _In_      DWORD  NewProtect, 
    _Out_opt_ PDWORD OldProtect
    )
{
    if ( NtProtectVirtualMemory64 == NULL )
    {
        //
        // Resolve NtProtectVirtualMemory from the 64-bit ntdll
        //
        NtProtectVirtualMemory64 = Wow64GetProcAddress( Wow64GetModuleHandleW( L"NTDLL.DLL" ), "NtProtectVirtualMemory" );
    }

    DWORD    dwOldProtect = NULL;
    UINT64   BaseAddress  = Address,
             RegionLength = Length;
    NTSTATUS Result       = Wow64CallProcedure<NTSTATUS>( NtProtectVirtualMemory64, -1, &BaseAddress, &RegionLength, NewProtect, &dwOldProtect );

    if ( OldProtect != NULL )
    {
        *OldProtect = dwOldProtect;
    }

    return Result;
}

VOID 
Wow64InstallHook_PrepareCallInstruction( 
    _In_ UINT64 Target,
    _In_ LPVOID TransitionHandler,
    _In_ LPVOID CallInstruction,
    _In_ SIZE_T CallLength,
    _In_ SIZE_T CallRVAOffset
    )
{
    SYSTEM_INFO SystemInfo{};

    GetSystemInfo( &SystemInfo );

    //
    // Align the target address down to the nearest allocation granularity.
    //
    UINT64 TargetAddress = ( UINT64 ) Target & ~( ( UINT64 )SystemInfo.dwAllocationGranularity - 1ull );
    DWORD  Protect1      = PAGE_EXECUTE_READWRITE,
           Protect2      = Protect1;

    //
    // Locate function padding large enough to house our absolute address
    //
    while ( Wow64ReadData< UINT64 >( TargetAddress ) != 0xCCCCCCCCCCCCCCCC )
    {
        //
        // Increment the address
        //
        TargetAddress++;
    }

    //
    // Configure the relative address for the call instruction
    //
    INT32 CallRVA = ( INT32 )( TargetAddress - ( Target + CallLength ) );
    *( INT32* )( ( UINT8* )CallInstruction + CallRVAOffset ) = CallRVA;

    //
    // Adjust protection state
    //
    Wow64ProtectVirtualMemory( TargetAddress, sizeof( UINT64 ), Protect1, &Protect1 );
    Wow64ProtectVirtualMemory( Target,        sizeof( UINT64 ), Protect2, &Protect2 );

    //
    // Store the absolute address to the handler function in the padding
    //
    Wow64WriteData< UINT64 >( TargetAddress, ( UINT64 )TransitionHandler );
    Wow64CopyMemory( Target, ( UINT64 )CallInstruction, CallLength );

    //
    // Restore protection state
    //
    Wow64ProtectVirtualMemory( Target,        sizeof( UINT64 ), Protect2, &Protect2 );
    Wow64ProtectVirtualMemory( TargetAddress, sizeof( UINT64 ), Protect1, &Protect1 );
}

BOOLEAN
Wow64InstallHook(
    _In_ UINT64               Target,
    _In_ PWOW64_FUNCTION_HOOK Handler
    )
{
    Wow64AcquireSpinlock( g_Wow64HookListLock );

#define WOW64_MAX_HOOK_HANDLERS 128

    UINT8 CallQwordPtrRip00Dest[ ] =
    {
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    if ( g_Wow64HookHandlers == NULL )
    {
        //
        // Allocate enough space for 128 hooks
        //
        g_Wow64HookHandlers = VirtualAlloc( 
            NULL, 
            sizeof( Wow64HookTransition_Data ) * WOW64_MAX_HOOK_HANDLERS,
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_EXECUTE_READWRITE 
            );
    }

    if ( g_Wow64HookHandlers == NULL ) 
    {
        Wow64ReleaseSpinlock( g_Wow64HookListLock );
        __fastfail( 0 );
    }

    PWOW64_HOOK_TRANSITION CurrentHookHandler = ( PWOW64_HOOK_TRANSITION )g_Wow64HookHandlers;
    BOOLEAN                HasSpace           = FALSE;

    for ( UINT32 i = 0; i < WOW64_MAX_HOOK_HANDLERS; i++ )
    {
        if ( CurrentHookHandler->HandlerFunction == NULL )
        {
            HasSpace = TRUE;
            break;
        }

        CurrentHookHandler++;
    }

    if ( HasSpace == FALSE )
    {
        Wow64ReleaseSpinlock( g_Wow64HookListLock );
        return FALSE;
    }

    //
    // Prepare the hook handler data
    //
    RtlCopyMemory( CurrentHookHandler, Wow64HookTransition_Data, sizeof( Wow64HookTransition_Data ) );

    CurrentHookHandler->HandlerFunction = Handler;
    CurrentHookHandler->Target          = Target;

    Wow64CopyMemory( ( UINT64 )CurrentHookHandler->OriginalBytes, ( UINT64 )Target, sizeof( CurrentHookHandler->OriginalBytes ) );

    //
    // Configure and apply call instruction
    //
    Wow64InstallHook_PrepareCallInstruction( Target, CurrentHookHandler, CallQwordPtrRip00Dest, 6, 2 );

    Wow64ReleaseSpinlock( g_Wow64HookListLock );

    return TRUE;
}

VOID
Wow64RemoveHook( 
    _In_ PWOW64_FUNCTION_HOOK Handler 
    )
{
    if ( g_Wow64HookHandlers == NULL )
        return;

    Wow64AcquireSpinlock( g_Wow64HookListLock );

    PWOW64_HOOK_TRANSITION CurrentHookHandler = ( PWOW64_HOOK_TRANSITION )g_Wow64HookHandlers;
    BOOLEAN                Located            = FALSE;

    for ( UINT32 i = 0; i < WOW64_MAX_HOOK_HANDLERS; i++ )
    {
        if ( CurrentHookHandler->HandlerFunction == Handler )
        {
            Located = TRUE;
            break;
        }

        CurrentHookHandler++;
    }

    if ( Located == FALSE )
        return;

    UINT64 Target  = CurrentHookHandler->Target;
    DWORD  Protect = PAGE_EXECUTE_READWRITE;

    //
    // Restore the original bytes at the target function
    //
    Wow64ProtectVirtualMemory( Target, 0x1000, Protect, &Protect );
    Wow64CopyMemory( Target, ( UINT64 )CurrentHookHandler->OriginalBytes, sizeof( CurrentHookHandler->OriginalBytes ) );
    Wow64ProtectVirtualMemory( Target, 0x1000, Protect, &Protect );

    //
    // Invalidate the shellcode, so that it can be reused by Wow64InstallHook
    //
    CurrentHookHandler->HandlerFunction = NULL;

    Wow64ReleaseSpinlock( g_Wow64HookListLock );
}

VOID
Wow64HandleKiUserExceptionDispatcher( 
    _In_ PCONTEXT64 Context 
    )
{
    PCONTEXT64          ExceptionContext = ( PCONTEXT64          )( Context->Rsp         );
    PEXCEPTION_RECORD64 ExceptionRecord  = ( PEXCEPTION_RECORD64 )( Context->Rsp + 0x4F0 );

    for ( UINT32 i = 0; i < WOW64_MAX_VECTORED_HANDLERS; i++ )
    {
        PWOW64_VECTORED_EXCEPTION_HANDLER CurrentHandler = g_Wow64VectoredExceptionHandlers[ i ];
        
        if ( CurrentHandler == NULL )
            continue;

        LONG Result = CurrentHandler( ExceptionContext, ExceptionRecord );

        if ( Result == EXCEPTION_CONTINUE_EXECUTION )
        {
            Context->Rcx = ( UINT64 )ExceptionContext;
            Context->Rdx = FALSE;
            Context->Rip = NtContinue64;

            return;
        }
    }

    //
    // Simulate the 'cld' instruction
    //
    Context->EFlags &= ~( 1 << 10 );

    //
    // Simulate the 'mov rax, cs:Wow64PrepareForException' instructon
    //
    Context->Rax = g_Wow64PrepareForException;

    //
    // Increment by the length of the instructions we just simulated
    //
    Context->Rip += 8;
}

BOOLEAN
Wow64RemoveVectoredExceptionHandler( 
    _In_ PWOW64_VECTORED_EXCEPTION_HANDLER VectoredHandler 
    )
{
    Wow64AcquireSpinlock( g_Wow64VEHListLock );

    BOOLEAN Result = FALSE;

    for ( UINT32 i = 0; i < WOW64_MAX_VECTORED_HANDLERS; i++ )
    {
        if ( g_Wow64VectoredExceptionHandlers[ i ] == VectoredHandler )
        { 
             g_Wow64VectoredExceptionHandlers[ i ] = NULL;
             Result = TRUE;
             break;
        }
    }

    Wow64ReleaseSpinlock( g_Wow64VEHListLock );

    return Result;
}

BOOLEAN
Wow64AddVectoredExceptionHandler(
    _In_ PWOW64_VECTORED_EXCEPTION_HANDLER VectoredHandler 
    )
{
    Wow64AcquireSpinlock( g_Wow64VEHListLock );

    BOOLEAN Result = FALSE;

    if ( g_Wow64PrepareForException == NULL )
    {
        UINT64 Wow64Dll = Wow64GetModuleHandleA( "WOW64.DLL" ),
               NtDll    = Wow64GetModuleHandleA( "NTDLL.DLL" );

        //
        // Resolve Wow64PrepareForException for our KiUserExceptionDispatcher hook
        //
        g_Wow64PrepareForException = Wow64GetProcAddress( Wow64Dll, "Wow64PrepareForException" );

        //
        // Resolve NtContinue
        // 
        NtContinue64 = Wow64GetProcAddress( NtDll, "NtContinue" );

        if ( g_Wow64PrepareForException == NULL || NtContinue64 == NULL )
        {
            return Result;
        }

        //
        // Redirect ntdll!KiUserExceptionDispatcher to our handler
        //
        Result = Wow64InstallHook( 
            Wow64GetProcAddress( NtDll, "KiUserExceptionDispatcher" ), 
            Wow64HandleKiUserExceptionDispatcher 
            );

        if ( Result == FALSE )
        {
            return Result;
        }

        //
        // Initialize the VEH list
        //
        RtlZeroMemory( g_Wow64VectoredExceptionHandlers, sizeof( g_Wow64VectoredExceptionHandlers ) );
    }

    for ( UINT32 i = 0; i < WOW64_MAX_VECTORED_HANDLERS; i++ )
    {
        if ( g_Wow64VectoredExceptionHandlers[ i ] == NULL )
        { 
             g_Wow64VectoredExceptionHandlers[ i ] = VectoredHandler;
             Result = TRUE;
             break;
        }
    }

    Wow64ReleaseSpinlock( g_Wow64VEHListLock );

    return FALSE;
}

#pragma warning( pop )
#endif