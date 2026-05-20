
//
// inclusions
//
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
	unsigned int ndis_version = 0;
	NTSTATUS status = STATUS_SUCCESS;

	
	//
	// Initializing the class
	// ( In this way it handles only ntoskrnl.exe functions )
	//
	NoImportz winapi( true );

	
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
		"\n\n(+) Memory allocated at: 0x%p\n",
		addr
	);
	
	
	//
	// Freeing the memory
	//
	winapi.call<decltype( ExFreePoolWithTag )>(
		"ExFreePoolWithTag", addr, 'TeSt'
	);


	//
	// Testing with a different module
	//
	NoImportz ndis( L"ndis.sys", true );


	//
	// Trying to get Ndis version
	//
	ndis_version = ndis.call<unsigned int(VOID)>( "NdisGetVersion" );
	

	//
	// Printing the results
	// ( using the MACRO )
	//
	ni_call( winapi, DbgPrintEx, 0, 0, "(+) Ndis version: 0x%llx\n", static_cast< uintptr_t >( ndis_version ) );


	//
	// Verifying that the cache works correctly
	// Note: the cache will be used in the call func automatically
	// however this can be used to test the caching system.
	//
	auto cache_entry = ndis.cache_get( "NdisGetVersion" );
	if ( !cache_entry.value ) return STATUS_UNSUCCESSFUL;


	//
	// Printing the result of the cache query
	//
	ni_call( winapi, DbgPrintEx, 0, 0, "(+) Function pointer from cache: 0x%p\n", cache_entry.value );


	return status;
}