# Wow64Util
Fully documented, updated, and comprehensive utilities for Windows 32-bit Wow64 processes

### What it currently has
* Easy 64-bit Memory reading/writing
* Easy 64-bit Procedure calling
* Hooking 64-bit functions
* Registering instrumentation callbacks within the wow64 layer
* 64-bit GetModuleHandle
* 64-bit GetProcAddress

## Examples
### 64-bit function hooking
```cpp
VOID
HandlerFunction( 
	_In_ PCONTEXT64 Context 
	)
{
	printf( "Hello from 64-bit hook!\n" );

	//
	// Change the return value
	//
	Context->Rax = 0x69696969;

	//
	// Return back to the caller
	//
	Context->Rip = *( UINT64* )Context->Rsp;
	Context->Rsp += 8;
}

LONG
main( 
	_In_ UINT32  Argc, 
	_In_ LPCSTR* Argv 
	)
{
	//
	// Obtain the address of LdrLoadDll
	//
	UINT64 Procedure = Wow64GetProcAddress( Wow64GetModuleHandleW( L"NTDLL.DLL" ), "LdrLoadDll" );

	//
	// Hook LdrLoadDll
	//
	Wow64InstallHook( Procedure, HandlerFunction );

	//
	// Call LdrLoadDll
	//
	UINT64 Status = Wow64CallProcedure( Procedure, NULL, NULL, NULL, NULL );

	//
	// Print the status
	//
	printf( "%X\n", Status );
}
```
