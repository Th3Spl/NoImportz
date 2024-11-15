/*

	- Author: Th3Spl

	- Lang: C++

	- Lang version: ISO C++17 Standard (/std:c++17)

	- Purpose: Create a simple header which can help
	in the creation of drivers without direct PE imports 

*/
#pragma once


//
// Inclusions
//
#include <ntifs.h>
#include <ntimage.h>


//
// This is the only needed simbol from ntoskrnl.exe
// ( which is not so easily pattern scannable... )
//
extern "C" __declspec( dllimport ) LIST_ENTRY* PsLoadedModuleList;


//
// Definitions
//
typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    // ULONG padding on IA64
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT __Unused5;
    PVOID SectionPointer;
    ULONG CheckSum;
    // ULONG padding on IA64
    PVOID LoadedImports;
    PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;


//
// NoImportz class declaration
//
class NoImportz
{
public:
		

	//
	// Attributes
	//
	PVOID base = 0;
	bool initialized = false;


	//
	// Class constructor 
	// ( If no argument is passed we assume it's ntoskrnl.exe )
	//
	__forceinline __fastcall NoImportz( )
	{
		/* The first entry in PsLoadedModuleList will always be ntoskrnl.exe */
		this->base = ( ( PKLDR_DATA_TABLE_ENTRY )PsLoadedModuleList )->DllBase;
		
		/* Checking if the initialization was successful */
		this->initialized = ( !this->base ) ? false : true;
	}


	//
	// Class constructor
	// overloaded to chose a different module
	//
	__forceinline __fastcall NoImportz( _In_ const wchar_t* module_name )
	{
		/* Getting the specified module base */
		this->base = this->get_module_base( module_name );

		/* Checking the initialization */
		this->initialized = ( !this->base ) ? false : true;
	}


	//
	// Get a module's base address
	//
	__forceinline PVOID __fastcall get_module_base( _In_ const wchar_t* module_name )
	{
		//
		// Variables
		//
		PKLDR_DATA_TABLE_ENTRY modules_entry = ( PKLDR_DATA_TABLE_ENTRY )PsLoadedModuleList;


		/* Checking if the imported list is a valid ptr */
		if ( !modules_entry )
			return ( PKLDR_DATA_TABLE_ENTRY )0;


		/* Iterating through the modules */
		do
		{
			/* Checking if the current module is the one we're interested in */
			if ( modules_entry->BaseDllName.Buffer && wcscmp( modules_entry->BaseDllName.Buffer, module_name ) == 0 )
				return modules_entry->DllBase;

			/* Incrementing the pointer */
			modules_entry = ( PKLDR_DATA_TABLE_ENTRY )modules_entry->InLoadOrderLinks.Flink;
		} while ( modules_entry != ( PKLDR_DATA_TABLE_ENTRY )PsLoadedModuleList );


		/* Module was not found! */
		return ( PKLDR_DATA_TABLE_ENTRY )0;
	}


	//
	// Checking the initialization
	//
	__forceinline bool __fastcall is_initialized( )
	{
		return this->initialized;
	}


	//
	// Wrap calling the function
	//
	template<typename func, typename... params>
	auto __fastcall call( _In_ const char* func_name, _In_ params... f_params )
	{
		/* Getting the exported function from the target module */
		PVOID l_func = find_export( this->base, func_name );
		if ( !l_func )
			return decltype( ( ( func* )nullptr )( f_params... ) )( );

		/* Building the function */
		auto target_func = reinterpret_cast< func* >( l_func );
		
		/* Calling the function and returning the result */
		return target_func( f_params... );
	}


private:

	
	//
	// ascii compare
	// We use volatile in order to signal the compiler 
	// NOT to optimize the following function.
	//
	__forceinline volatile int __fastcall ascii_cmp( _In_ const char* str1, _In_ const char* str2 )
	{
		while ( ( *str1 != '\0' ) && ( *str1 == *str2 ) ) {
			str1++;
			str2++;
		}

		return *str1 - *str2;
	}


	//
	// ASCII to int
	//
	__forceinline volatile UINT64 __fastcall ascii_to_int( _In_ const char* ascii )
	{
		UINT64 return_int = 0;
		while ( *ascii )
		{
			if ( *ascii <= '0' || *ascii >= '9' )
				return 0;
			return_int *= 10;
			return_int += *ascii - '0';
			ascii++;
		}
		return return_int;
	}


	//
	// Finding an export entry of a PE using an ordinal
	//
	UINT32* __fastcall find_export_entry_by_ordinal( _In_ VOID* module, _In_ UINT16 ordinal )
	{
		PIMAGE_DOS_HEADER dos = ( PIMAGE_DOS_HEADER )module;
		if ( dos->e_magic != 0x5A4D )
			return NULL;

		PIMAGE_NT_HEADERS64 nt = ( PIMAGE_NT_HEADERS )( ( UINT8* )module + dos->e_lfanew );
		UINT32 exports_rva = nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress; // This corresponds to export directory
		if ( !exports_rva )
			return NULL;

		PIMAGE_EXPORT_DIRECTORY export_dir = ( PIMAGE_EXPORT_DIRECTORY )( ( UINT8* )module + exports_rva );
		UINT16 index = ordinal - ( UINT16 )export_dir->Base;

		UINT32* export_func_table = ( UINT32* )( ( UINT8* )module + export_dir->AddressOfFunctions );
		if ( export_func_table[ index ] < nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress ||
			 export_func_table[ index ] > nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress + nt->OptionalHeader.DataDirectory[ 0 ].Size )
			return export_func_table + index;
		// Handle the case of a forwarder export entry
		else
		{
			wchar_t buffer[ 260 ];
			char* forwarder_rva_string = ( char* )module + export_func_table[ index ];
			UINT16 dll_name_length;
			for ( dll_name_length = 0; dll_name_length < 259; ++dll_name_length )
				if ( forwarder_rva_string[ dll_name_length ] == '.' ) break;
			for ( int i = 0; i < dll_name_length; ++i )
				buffer[ i ] = ( wchar_t )forwarder_rva_string[ i ];
			buffer[ dll_name_length ] = L'\0';
			if ( forwarder_rva_string[ dll_name_length + 1 ] == '#' )
				return find_export_entry_by_ordinal( get_module_base( buffer ), ( UINT16 )ascii_to_int( &forwarder_rva_string[ dll_name_length + 2 ] ) );
			else
				return find_export_entry( get_module_base( buffer ), forwarder_rva_string + dll_name_length + 1 );
		}
	}


	//
	// Finding an export entry of a PE
	//
	UINT32* __fastcall find_export_entry( _In_ VOID* module, _In_ const char* routine_name )
	{
		PIMAGE_DOS_HEADER dos = ( PIMAGE_DOS_HEADER )module;
		if ( dos->e_magic != 0x5A4D )
			return NULL;

		PIMAGE_NT_HEADERS64 nt = ( PIMAGE_NT_HEADERS )( ( UINT8* )module + dos->e_lfanew );
		UINT32 exports_rva = nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress; // This corresponds to export directory
		if ( !exports_rva )
			return NULL;

		PIMAGE_EXPORT_DIRECTORY export_dir = ( PIMAGE_EXPORT_DIRECTORY )( ( UINT8* )module + exports_rva );
		UINT32* name_table = ( UINT32* )( ( UINT8* )module + export_dir->AddressOfNames );

		// Binary Search
		for ( int lower = 0, upper = export_dir->NumberOfNames - 1; upper >= lower;)
		{
			int i = ( upper + lower ) / 2;
			const char* func_name = ( const char* )( ( UINT8* )module + name_table[ i ] );
			int diff = ascii_cmp( routine_name, func_name );
			if ( diff > 0 )
				lower = i + 1;
			else if ( diff < 0 )
				upper = i - 1;
			else
			{
				UINT32* export_func_table = ( UINT32* )( ( UINT8* )module + export_dir->AddressOfFunctions );
				UINT16* ordinal_table = ( UINT16* )( ( UINT8* )module + export_dir->AddressOfNameOrdinals );

				UINT16 index = ordinal_table[ i ];
				if ( export_func_table[ index ] < nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress ||
					 export_func_table[ index ] > nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress + nt->OptionalHeader.DataDirectory[ 0 ].Size )
					return export_func_table + index;
				// Handle the case of a forwarder export entry
				else
				{
					wchar_t buffer[ 260 ];
					char* forwarder_rva_string = ( char* )module + export_func_table[ index ];
					UINT16 dll_name_length;
					for ( dll_name_length = 0; dll_name_length < 259; ++dll_name_length )
						if ( forwarder_rva_string[ dll_name_length ] == '.' ) break;
					for ( int j = 0; j < dll_name_length; ++j )
						buffer[ j ] = ( wchar_t )forwarder_rva_string[ j ];
					buffer[ dll_name_length ] = L'\0';
					if ( forwarder_rva_string[ dll_name_length + 1 ] == '#' )
						return find_export_entry_by_ordinal( get_module_base( buffer ), ( UINT16 )ascii_to_int( &forwarder_rva_string[ dll_name_length + 2 ] ) );
					else
						return find_export_entry( get_module_base( buffer ), forwarder_rva_string + dll_name_length + 1 );
				}
			}
		}
		return NULL;
	}


	//
	// Finding the export of a PE similar to MmGetSystemRoutineAddress()
	//
	__forceinline PVOID __fastcall find_export( _In_ VOID* module, _In_ const char* routine_name )
	{
		UINT32* entry = find_export_entry( module, routine_name );
		if ( !entry )
			return NULL;
		return ( PVOID )( ( UINT8* )module + *entry );
	}

};