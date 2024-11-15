#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include ".\NoImportz\NoImportz.hpp"


//
// Entry point
//
NTSTATUS DriverEntry( _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath )
{
	/* Unreferenced parameters */
	UNREFERENCED_PARAMETER( DriverObject );
	UNREFERENCED_PARAMETER( RegistryPath );


	//
	// Variables
	//
	NTSTATUS status = STATUS_SUCCESS;



	//
	// Initializing the class
	// ( In this way it handles only ntoskrnl.exe functions )
	//
	NoImportz winapi;


	//
	// Checking if the class was initialized successfully
	// 
	if ( !winapi.is_initialized( ) )
		return STATUS_UNSUCCESSFUL;


	//
	// Calling ExAllocatePool2 to test
	//
	PVOID addr = winapi.call<decltype( ExAllocatePool2 )> (
		"ExAllocatePool2", POOL_FLAG_NON_PAGED,
		4096, 'TeSt'
	);

	
	//
	// Printing the allocation base
	//
	winapi.call<decltype( DbgPrintEx )>(
		"DbgPrintEx", 0, 0,
		"\n( + ) Memory allocated at: 0x%p\n",
		addr
	);


	//
	// Freeing the memory
	//
	winapi.call<decltype( ExFreePoolWithTag )>(
		"ExFreePoolWithTag", addr, 'TeSt'
	);


	return status;
}