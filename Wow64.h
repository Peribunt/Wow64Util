#ifndef __WOW64_H__
#define __WOW64_H__

#pragma warning( push )
#pragma warning( disable : 6506 )

//
// This header is only relevant in 32-bit mode
//
#if defined _WIN32 && !_WIN64

#include <Windows.h>
#include "Wow64Types.h"

#define db( _ ) __asm _emit( ##_ )

/*
* Exit 32-bit mode by switching to the CS segment selector that points to a descriptor with long mode enabled
* 
* 0x00: push 0x33
* 0x01: call $+5
* 0x06: add  dword ptr[esp], 5
* 0x0A: retf
*/
#define Wow64Exit32( )                                     \
    db( 0x6A ) db( 0x33 )                                  \
    db( 0xE8 ) db( 0x00 ) db( 0x00 ) db( 0x00 ) db( 0x00 ) \
    db( 0x83 ) db( 0x04 ) db( 0x24 ) db( 0x05 )            \
    db( 0xCB )                                                 

/*
* Enter 32-bit mode by switching back to the 32-bit CS segment selector
* 
* 0x00: call $+5
* 0x05: mov  dword ptr[rsp+0x04], 0x23
* 0x0D: add  dword ptr[rsp], 13
* 0x11: retf
*/
#define Wow64Enter32( )                                                                     \
    db( 0xE8 ) db( 0x00 ) db( 0x00 ) db( 0x00 ) db( 0x00 )                                  \
    db( 0xC7 ) db( 0x44 ) db( 0x24 ) db( 0x04 ) db( 0x23 ) db( 0x00 ) db( 0x00 ) db( 0x00 ) \
    db( 0x83 ) db( 0x04 ) db( 0x24 ) db( 0x0D )                                             \
    db( 0xCB )                                                                                     

/**
 * @brief Pointer to a 64-bit function hook handler
 */
typedef VOID( CDECL* PWOW64_FUNCTION_HOOK )(
    _Inout_ PCONTEXT64 Context
    );

/**
 * @brief Pointer to a 64-bit exception handler
 */
typedef LONG( CDECL* PWOW64_VECTORED_EXCEPTION_HANDLER )(
	_In_ PCONTEXT64          ContextRecord,
	_In_ PEXCEPTION_RECORD64 ExceptionRecord
	);

/**
 * @brief Intercept 64-bit code, capture it's context, and forward it to a handler function
 * 
 *        --- HOW TO USE ---
 *        The handler function operates similarly to an exception handler. When the detour is reached,
 *        it will capture the 64-bit context and forward this context to it.
 *        The 64-bit context structure is meant to be used for all adjustments made to the 64-bit context,
 *        and will be restored upon the return of the handler function.
 * 
 *        Wow64InstallHook will overwrite 14 bytes(the size of the absolute call) at the target location.
 *        The instructions that get destroyed by this will have to be replicated within your handler function.
 *        You are also responsible for pointing CONTEXT64->RIP to the correct location within the handler
 * 
 * @param [in]  Target: The target address at which to install the hook
 * @param [in] Handler: A pointer to a handler function that will receive a CONTEXT64 structure.
 *                      When this function returns the contents of the CONTEXT64 structure will be applied to the 64-bit context. *
 * 
 * @return TRUE if the function succeeds in installing the hook
 * @return FALSE if the function does not succeed in installing the hook
 */
BOOLEAN
Wow64InstallHook( 
    _In_ UINT64               Target, 
    _In_ PWOW64_FUNCTION_HOOK Handler 
    );

/**
 * @brief Remove a previously installed hook
 * 
 * @param [in] Handler: A pointer to the handler function responsible for handling the hook to remove
 */
VOID
Wow64RemoveHook( 
    _In_ PWOW64_FUNCTION_HOOK Handler 
    );

/**
 * @brief Perform a memcpy in 64-bit mode, allowing unrestricted access to the full 64-bit address space
 * 
 * @param [out] Destination: Address of the destination that the source data will be copied to
 * @param [in]       Source: Address of the source data to copy
 * @param [in]       Length: The length of the data to copy
 */
VOID
Wow64CopyMemory( 
    _Out_ UINT64 Destination,
    _In_  UINT64 Source,
    _In_  UINT64 Length
    );

/**
 * @brief Perform a memory comparison in 64-bit mode, allowing unrestricted access to the full 64-bit address space
 * 
 * @param [in] Source1: The data to compare against Source2
 * @param [in] Source2: The data to compare against Source1
 * @param [in]  Length: The length of the data to compare
 * 
 * @return NULL if the compared data is equal
 * @return Nonzero if the compared data is not equal
 */
BOOLEAN
Wow64CompareMemory( 
    _In_ UINT64 Source1, 
    _In_ UINT64 Source2,
    _In_ UINT64 Length
    );

/**
 * @brief Read a datum of a given type at a specified address 
 * 
 * @tparam _TYPE_: The type of the datum
 * 
 * @param [in] Source: The address from which to read the datum
 * 
 * @return The datum read from the specified address
 */
template< typename _TYPE_ = UINT64 >
FORCEINLINE
_TYPE_
Wow64ReadData( 
    _In_ UINT64 Source 
    )
{
    _TYPE_ Result;

    Wow64CopyMemory( ( UINT64 )&Result, Source, sizeof( _TYPE_ ) );

    return Result;
}

/**
 * @brief Write a datum of a given type to a specified address
 *
 * @tparam _TYPE_: The type of the datum
 *
 * @param [in] Source: The address at which to write the datum
 *
 * @return The original datum from the specified address
 */
template< typename _TYPE_ = UINT64 >
FORCEINLINE
_TYPE_
Wow64WriteData(
    _In_ UINT64 Destination, 
    _In_ _TYPE_ Data 
    )
{
    _TYPE_ Result = Wow64ReadData<_TYPE_>( Destination );

    Wow64CopyMemory( Destination, ( UINT64 )&Data, sizeof( _TYPE_ ) );

    return Result;
}

UINT64
Wow64CallProcedureRaw(
    _In_ UINT64  TargetProcedure,
    ...
    );

/**
 * @brief Call a 64-bit procedure(assuming Windows ABI)
 * 
 * @param [in] TargetProcedure: The address of the target procedure
 * @param [in]            Args: The argumentf of the target procedure
 */
#pragma optimize( "", off )
template<typename... _VA_ARGS_>
DECLSPEC_NOINLINE
UINT64
Wow64CallProcedure( 
    _In_ UINT64  TargetProcedure,
    _VA_ARGS_... Args
    )
{
    __asm 
    {
        mov dword ptr fs:0x1500, esp
        and esp, 0xFFFFFFF0
    }

    UINT64 Result = Wow64CallProcedureRaw( TargetProcedure, ( UINT64 )Args... );

    __asm
    {
        mov esp, dword ptr fs:0x1500
    }
    
    return Result;
}
#pragma optimize( "", on )

/**
 * @brief Obtain a 64-bit module base address by its file name 
 * 
 * @param [in] ModuleName: The file name of the target module
 * 
 * @return The base address of the target module if the function succeeds
 * @return NULL if the function fails
 */
UINT64
Wow64GetModuleHandleW( 
    _In_ LPCWSTR ModuleName 
    );

/**
 * @brief Obtain a 64-bit module base address by its file name 
 * 
 * @param [in] ModuleName: The file name of the target module
 * 
 * @return The base address of the target module if the function succeeds
 * @return NULL if the function fails to locate the target module
 */
UINT64
Wow64GetModuleHandleA( 
    _In_ LPCSTR ModuleName 
    );

/**
 * @brief Obtain the image NT headers of a 64-bit module by its base address
 * 
 * @param [in]  ModuleBase: The base address of the target module
 * @param [out]  NtHeaders: Pointer to space for the NT headers of the target module
 * 
 * @return Nonzero if the function succeeds
 * @return NULL if the function fails
 */
BOOLEAN
Wow64GetImageNtHeaders( 
    _In_  UINT64              ModuleBase,
    _Out_ PIMAGE_NT_HEADERS64 NtHeaders
    );

/**
 * @brief Locate a procedure by name in a specified executable
 * 
 * @param [in]        Module: The base address to the executable in which to locate the procedure
 * @param [in] ProcedureName: The exported name of the procedure
 * 
 * @return The address to the procedure if the function succeeds
 * @return NULL if the function fails to locate the target procedure
 */
UINT64
Wow64GetProcAddress( 
    _In_ UINT64 Module, 
    _In_ LPCSTR ProcedureName 
    );

/**
 * @brief Call NtProtectVirtualMemory in 64-bit mode
 * 
 * @param [in]               Address: The target address at which to apply the new protection
 * @param [in]                Length: The size of the region at which to apply the new protection
 * @param [in]            NewProtect: The new protection to apply
 * @param [out, optional] OldProtect: A pointer to a DWORD in which the old protections will be stored
 * 
 * @return The NTSTATUS result from the NtProtectVirtualMemory call
 */
NTSTATUS
Wow64ProtectVirtualMemory( 
    _In_      UINT64 Address, 
    _In_      SIZE_T Length, 
    _In_      DWORD  NewProtect, 
    _Out_opt_ PDWORD OldProtect = NULL
    );

/**
 * @brief Register an instrumentation callback using wow64.dll's 'Wow64InfoPtr'
 * 
 * @param [in] InstrumentationCallback: A pointer to an instrumentation callback handler function.
 *                                      The 32-bit instrumentation callback stores the return RIP in the ECX register. 
 * 
 * @return TRUE if the instrumentation callback was successfully registered
 * @return FALSE if the instrumentation callback was not successfully registered
 */
BOOLEAN
Wow64RegisterInstrumentationCallback( 
    _In_ LPVOID InstrumentationCallback 
    );

/**
 * @brief Add a 64-bit vectored exception handler to handle exceptions that occur in all areas of the running process
 * 
 * @param [in] VectoredHandler: Pointer to an exception handler function. This handler function is intended
 *                              to work the exact same way as a normal vectored exception handler.
 *                              Where returning EXCEPTION_CONTINUE_EXECUTION results in immediate continuation of execution,
 *                              and returning EXCEPTION_CONTINUE_SEARCH results in forwarding to other potential handlers in the list.
 * 
 * @return TRUE if the vectored handler was successfully added
 * @return FALSE if the vectored handler was not successfully added
 */
BOOLEAN
Wow64AddVectoredExceptionHandler( 
	_In_ PWOW64_VECTORED_EXCEPTION_HANDLER VectoredHandler
	);

/**
 * @brief Remove a previously added vectored exception handler
 * 
 * @param [in] VectoredHandler: The vectored exception handler to remove
 * 
 * @return TRUE if the vectored exception handler was found and removed
 * @return FALSE if the vectored exception handler was not added in the first place
 */
BOOLEAN
Wow64RemoveVectoredExceptionHandler( 
	_In_ PWOW64_VECTORED_EXCEPTION_HANDLER VectoredHandler
	);

/**
 * @brief Read a QWORD at a specified offset from the GS base(TEB base in usermode)
 * 
 * @param [in] Offset: The offset in QWORDs from the GS base at which to read the QWORD
 * 
 * @return The read QWORD 
 */
UINT64
Wow64ReadGsQword( 
    _In_ UINT32 Offset 
    );

/**
 * @brief Read a DWORD at a specified offset from the GS base(TEB base in usermode)
 *
 * @param [in] Offset: The offset in DWORDs from the GS base at which to read the DWORD
 *
 * @return The read DWORD
 */
UINT32
Wow64ReadGsDword( 
    _In_ UINT32 Offset 
    );

/**
 * @brief Read a WORD at a specified offset from the GS base(TEB base in usermode)
 *
 * @param [in] Offset: The offset in WORDs from the GS base at which to read the WORD
 *
 * @return The read WORD
 */
UINT16
Wow64ReadGsWord( 
    _In_ UINT32 Offset 
    );

/**
 * @brief Read a BYTE at a specified offset from the GS base(TEB base in usermode)
 *
 * @param [in] Offset: The offset in BYTEs from the GS base at which to read the BYTE
 *
 * @return The read BYTE
 */
UINT8
Wow64ReadGsByte( 
    _In_ UINT32 Offset 
    );

#pragma warning( pop )

#endif
#endif