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
// Simple MACRO call ( this is for simplicity of use )
//
#define ni_call(_class, func, ...) _class.call<decltype(func)>(#func, __VA_ARGS__);
#define nip_call(_class, func, ...) _class.call<func>(#func, __VA_ARGS__);


//
// Definitions
// 
// Note: you might need to update some 
// structures for to match your windows version.
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

template <typename T>
struct ni_bucket
{
	ULONG64 key;
	T value;
};


//
// NoImportz class declaration
// 
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
	__forceinline NoImportz( _In_opt_ bool enable_cache = false )
	{
		/* resolving PsLoadedModuleList */
		this->loaded_module_list = *reinterpret_cast< PKLDR_DATA_TABLE_ENTRY* >( this->find_ps_loaded_module_list( ) );
		if ( !this->loaded_module_list ) return;

		/* The first entry in PsLoadedModuleList will always be ntoskrnl.exe */
		this->base = ( ( PKLDR_DATA_TABLE_ENTRY )this->loaded_module_list )->DllBase;
		if ( !this->base ) return;

		/* checking if we have to use the cache */
		this->cache_enabled = enable_cache;
		if ( this->cache_enabled ) 
		{ 
			if ( !this->resolve_cache_func( ) ) return;
			if ( !this->_alloc_hashmap_base_mem_( ) ) return;
		}
		
		/* Checking if the initialization was successful */
		this->initialized = ( !this->base ) ? false : true;
		return;
	}


	//
	// Class constructor
	// overloaded to chose a different module
	//
	__forceinline NoImportz( _In_ const wchar_t* module_name, bool enable_cache = false )
	{
		/* param check */
		if ( !module_name ) return;

		/* resolving PsLoadedModuleList */
		this->loaded_module_list = *reinterpret_cast< PKLDR_DATA_TABLE_ENTRY* >( this->find_ps_loaded_module_list( ) );
		if ( !this->loaded_module_list ) return;

		/* Getting the specified module base */
		this->base = this->get_module_base( module_name );
		if ( !this->base ) return;

		/* checking if we have to use the cache */
		this->cache_enabled = enable_cache;
		if ( this->cache_enabled ) 
		{ 
			if ( !this->resolve_cache_func( ) ) return;
			if ( !this->_alloc_hashmap_base_mem_( ) ) return; 
		}
		
		/* Checking the initialization */
		this->initialized = ( !this->base ) ? false : true;
	}


	//
	// Class destructor
	// so we can make sure to free the allocated
	// buffer in case we're using the cache
	//
	inline ~NoImportz( )
	{
		if ( this->hash_map && this->_ExFreePoolWithTag ) this->_ExFreePoolWithTag( this->hash_map, 0 );
		return;
	}


	//
	// Custom implementation for wcscmp 
	// because sometimes it gets marked as import
	//
	inline int __impl_wcscmp( _In_ const wchar_t* str1, _In_ const wchar_t* str2 )
	{
		/* Looping the strings */
		while ( *str1 != L'\0' && *str2 != L'\0' ) {
			if ( *str1 != *str2 ) {
				return ( *str1 - *str2 );
			}
			++str1;
			++str2;
		}
		return ( *str1 - *str2 );
	}


	//
	// Get a module's base address
	//
	inline PVOID get_module_base( _In_ const wchar_t* module_name )
	{
		/* getting PsLoadedModule list */
		PKLDR_DATA_TABLE_ENTRY modules_entry = ( PKLDR_DATA_TABLE_ENTRY )this->loaded_module_list;
		if ( !modules_entry ) return ( PKLDR_DATA_TABLE_ENTRY )0;

		/* Iterating through the modules */
		do
		{
			/* Checking if the current module is the one we're interested in */
			if ( modules_entry->BaseDllName.Buffer && this->module_name_match( modules_entry->BaseDllName.Buffer, module_name ) )
				return modules_entry->DllBase;

			/* Incrementing the pointer */
			modules_entry = ( PKLDR_DATA_TABLE_ENTRY )modules_entry->InLoadOrderLinks.Flink;
		} while ( modules_entry != ( PKLDR_DATA_TABLE_ENTRY )this->loaded_module_list );

		/* Module was not found! */
		return ( PKLDR_DATA_TABLE_ENTRY )0;
	}


	//
	// Checking the initialization
	//
	inline bool is_initialized( )
	{
		return this->initialized;
	}


	//
	// getting a function from the cache
	//
	inline ni_bucket<PVOID> cache_get( _In_ const char* _func_name )
	{
		/* checking if the params are valid */
		if ( !this->hash_map || !_func_name ) return { 0, nullptr };

		/* getting the hash for the key */
		UINT64 lookup = this->hash( _func_name, this->_impl_strlen( _func_name ) );

		/* iterating over the list in order to check if the function is present */
		for ( size_t i = 0; i < this->hashmap_bucket_count; i++ )
		{
			if ( lookup == this->hash_map[i].key ) return this->hash_map[i];
		}

		/* not found! */ return { 0, nullptr };
	}


	//
	// emptying the cache ( DOES NOT FREE THE BUFFER! )
	//
	inline void clear_cache( )
	{
		if ( !this->hash_map ) return;
		this->hashmap_bucket_count = 0;
		this->_impl_memset( reinterpret_cast< volatile UINT8* >( this->hash_map ), 0, this->base_hashmap_space * this->curr_hashmap_alloc_count );
	}


	//
	// Wrap calling the function
	//
#pragma warning(push)
#pragma warning(disable : 4190)
#pragma warning(disable : 4503)
	template<typename func, typename... params>
	inline auto call( _In_ const char* func_name, _In_ params... f_params )
	{
		/* vars */
		PVOID l_func = nullptr;

		/* checking if it's present within the cache */
		if ( this->cache_enabled ) l_func = this->cache_get( func_name ).value;
		if ( !this->cache_enabled || !l_func )
		{
			/* Getting the exported function from the target module */
			l_func = find_export( this->base, func_name );
			if ( !l_func ) return decltype( ( ( func* )nullptr )( f_params... ) )( );

			/* adding the function to the cache */
			this->cache_add( func_name, l_func );
		}

		/* Building the function */
		auto target_func = reinterpret_cast< func* >( l_func );
		
		/* Calling the function and returning the result */
		return target_func( f_params... );
	}
#pragma warning(pop)


private:

	/* attributes */
	bool cache_enabled = false;
	size_t hashmap_bucket_count = 0;
	int curr_hashmap_alloc_count = 0;
	ni_bucket<PVOID>* hash_map = nullptr;
	static const size_t base_hashmap_space = 0x1000;
	PKLDR_DATA_TABLE_ENTRY loaded_module_list = nullptr;
	decltype( ExAllocatePool2 )* _ExAllocatePool2 = nullptr;
	decltype( ExFreePoolWithTag )* _ExFreePoolWithTag = nullptr;
	static_assert( base_hashmap_space % sizeof( decltype( *hash_map ) ) == 0, "(NoImportz) Unaligned cache base memory size!" );


	//
	// resolving the functions that are used for the cache
	//
	inline bool resolve_cache_func( )
	{
		/* we need PsLoadedModuleList */
		if ( !this->loaded_module_list ) return false;

		/* getting ntoskrnl.exe's entry ( ntoskrnl.exe is always the first entry ) */
		void* _ntos_base = this->loaded_module_list->DllBase;
		if ( !_ntos_base ) return false;

		/* getting ExAllocatePool2 */
		this->_ExAllocatePool2 = reinterpret_cast< decltype( ExAllocatePool2 )* >( this->find_export( _ntos_base, "ExAllocatePool2" ) );
		if ( !this->_ExAllocatePool2 ) return false;

		/* getting ExFreePoolWithTag */
		this->_ExFreePoolWithTag = reinterpret_cast< decltype( ExFreePoolWithTag )* >( this->find_export( _ntos_base, "ExFreePoolWithTag" ) );
		if ( !this->_ExFreePoolWithTag ) return false;

		/* success */ return true;
	}

	
	//
	// ascii compare
	// We use volatile in order to signal the compiler 
	// NOT to optimize the following function.
	//
	inline volatile int ascii_cmp( _In_ const char* str1, _In_ const char* str2 )
	{
		while ( ( *str1 != '\0' ) && ( *str1 == *str2 ) ) {
			str1++;
			str2++;
		}

		return *str1 - *str2;
	}


	//
	// custom memset, since sometimes the compiler sets it as import
	//
	inline volatile void _impl_memset( _In_ volatile UINT8* buffer, _In_ char val,  _In_ size_t size )
	{
		for ( size_t i = 0; i < size; i++ ) buffer[i] = val;
	}


	//
	// custom memcpy, since sometimes the compiler sets it as import
	//
	inline volatile void _impl_memcpy( _In_ volatile UINT8* dst, _In_ volatile UINT8* src, size_t size )
	{
		for ( size_t i = 0; i < size; i++ ) { dst[i] = src[i]; }
	}


	//
	// custom strlen, since sometimes the compiler sets it as import
	//
	inline volatile size_t _impl_strlen( _In_ volatile const char* str )
	{
		size_t idx = 0;
		while ( str[idx] != '\0' ) { idx++; }
		return idx;
	}


	//
	// ASCII to int
	//
	inline volatile UINT64 ascii_to_int( _In_ const char* ascii )
	{
		UINT64 return_int = 0;
		while ( *ascii )
		{
			if ( *ascii < '0' || *ascii > '9' ) return 0;

			return_int *= 10;
			return_int += *ascii - '0';
			ascii++;
		}
		return return_int;
	}


	//
	// forwarder module name match
	//
	inline bool module_name_match( _In_ const wchar_t* loaded_name, _In_ const wchar_t* lookup_name )
	{
		/* Compare until either side hits end or '.' */
		while ( *loaded_name && *lookup_name && *loaded_name != L'.' && *lookup_name != L'.' )
		{
			wchar_t a = *loaded_name;
			wchar_t b = *lookup_name;

			if ( a >= L'A' && a <= L'Z' ) a += 32;
			if ( b >= L'A' && b <= L'Z' ) b += 32;
			if ( a != b ) return false;

			++loaded_name; ++lookup_name;
		}

		/* Both must be at a terminator( either '\0' or '.' ) */
		bool loaded_done = ( *loaded_name == L'\0' || *loaded_name == L'.' );
		bool lookup_done = ( *lookup_name == L'\0' || *lookup_name == L'.' );
		return loaded_done && lookup_done;
	}


	//
	// Finding an export entry of a PE using an ordinal
	//
	inline UINT32* find_export_entry_by_ordinal( _In_ VOID* module, _In_ UINT16 ordinal )
	{
		/* param check */
		if ( !module ) return nullptr;

		/* vars */
		UINT16 index = 0;
		wchar_t buffer[260];
		UINT32 exports_rva = 0;
		UINT16 dll_name_length = 0;
		PIMAGE_DOS_HEADER dos = nullptr;
		PIMAGE_NT_HEADERS64 nt = nullptr;
		UINT32* export_func_table = nullptr;
		CHAR* forwarder_rva_string = nullptr;
		PIMAGE_EXPORT_DIRECTORY export_dir = nullptr;

		/* getting the DOS header */
		dos = ( PIMAGE_DOS_HEADER )module;
		if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) return NULL;

		/* getting the nt headers and the export RVA */
		nt = ( PIMAGE_NT_HEADERS )( ( UINT8* )module + dos->e_lfanew );
		exports_rva = nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress; // This corresponds to export directory
		if ( !exports_rva ) return NULL;

		/* getting the export directory */
		export_dir = ( PIMAGE_EXPORT_DIRECTORY )( ( UINT8* )module + exports_rva );
		if ( !export_dir ) return NULL;
		index = ordinal - ( UINT16 )export_dir->Base;

		/* checking if it's a forwarder and if it isn't we return the target func */
		export_func_table = ( UINT32* )( ( UINT8* )module + export_dir->AddressOfFunctions );
		if ( export_func_table[ index ] < nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress ||
			 export_func_table[ index ] > nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress + nt->OptionalHeader.DataDirectory[ 0 ].Size )
			return export_func_table + index;
		
		/* getting the forwarder string and getting it's length */
		forwarder_rva_string = ( char* )module + export_func_table[index];
		for ( dll_name_length = 0; dll_name_length < 259; ++dll_name_length )
			if ( forwarder_rva_string[dll_name_length] == '.' ) break;

		/* getting teh dll name into our buffer */
		for ( int i = 0; i < dll_name_length; ++i )
			buffer[i] = ( wchar_t )forwarder_rva_string[i];

		/* checking if we have to get the export through the ordinal or not */
		buffer[dll_name_length] = L'\0';
		if ( forwarder_rva_string[dll_name_length + 1] == '#' ) return find_export_entry_by_ordinal( get_module_base( buffer ), ( UINT16 )ascii_to_int( &forwarder_rva_string[dll_name_length + 2] ) );
		else return find_export_entry( get_module_base( buffer ), forwarder_rva_string + dll_name_length + 1 );
	}


	//
	// Finding an export entry of a PE
	//
	inline UINT32* find_export_entry( _In_ VOID* module, _In_ const char* routine_name )
	{
		/* param check */
		if ( !module || !routine_name ) return nullptr;

		/* vars */
		UINT16 index = 0;
		wchar_t buffer[260];
		UINT32 exports_rva = 0;
		UINT16 dll_name_length = 0;
		UINT32* name_table = nullptr;
		UINT16* ordinal_table = nullptr;
		PIMAGE_DOS_HEADER dos = nullptr;
		PIMAGE_NT_HEADERS64 nt = nullptr;
		UINT32* export_func_table = nullptr;
		PIMAGE_EXPORT_DIRECTORY export_dir = nullptr;

		/* getting the DOS header */
		dos = ( PIMAGE_DOS_HEADER )module;
		if ( dos->e_magic != IMAGE_DOS_SIGNATURE ) return NULL;

		/* getting the nt headers and the export RVA */
		nt = ( PIMAGE_NT_HEADERS )( ( UINT8* )module + dos->e_lfanew );
		exports_rva = nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress; // This corresponds to export directory
		if ( !exports_rva ) return NULL;

		/* getting the export directory and the name table */
		export_dir = ( PIMAGE_EXPORT_DIRECTORY )( ( UINT8* )module + exports_rva );
		if ( !export_dir ) return NULL;

		name_table = ( UINT32* )( ( UINT8* )module + export_dir->AddressOfNames );
		if ( !name_table ) return NULL;

		/* since the table is sorted alphabetically we can cut the search in half */
		for ( int lower = 0, upper = export_dir->NumberOfNames - 1; upper >= lower; )
		{
			/* inner vars */
			int i = ( upper + lower ) / 2;
			const char* func_name = ( const char* )( ( UINT8* )module + name_table[ i ] );
			int diff = ascii_cmp( routine_name, func_name );

			/* deciding where we should look for the function next */
			if ( diff > 0 ) lower = i + 1;
			else if ( diff < 0 ) upper = i - 1;
			else
			{
				/* getting the export function table and the ordinal table */
				export_func_table = ( UINT32* )( ( UINT8* )module + export_dir->AddressOfFunctions );
				ordinal_table = ( UINT16* )( ( UINT8* )module + export_dir->AddressOfNameOrdinals );

				/* checking if it's a forwarder otherwise we return the function */
				index = ordinal_table[ i ];
				if ( export_func_table[ index ] < nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress ||
					 export_func_table[ index ] > nt->OptionalHeader.DataDirectory[ 0 ].VirtualAddress + nt->OptionalHeader.DataDirectory[ 0 ].Size )
					return export_func_table + index;
							
				/* getting the forwarder rva string and getting its length */
				char* forwarder_rva_string = ( char* )module + export_func_table[index];
				for ( dll_name_length = 0; dll_name_length < 259; ++dll_name_length )
					if ( forwarder_rva_string[dll_name_length] == '.' ) break;

				/* getting the string into our own buffer */
				for ( int j = 0; j < dll_name_length; ++j )
					buffer[j] = ( wchar_t )forwarder_rva_string[j];

				/* checking if we have to get the export through the ordinal or not */
				buffer[dll_name_length] = L'\0';
				if ( forwarder_rva_string[dll_name_length + 1] == '#' ) return find_export_entry_by_ordinal( get_module_base( buffer ), ( UINT16 )ascii_to_int( &forwarder_rva_string[dll_name_length + 2] ) );
				else return find_export_entry( get_module_base( buffer ), forwarder_rva_string + dll_name_length + 1 );
			}
		}

		/* not found */ return NULL;
	}


	//
	// Finding the export of a PE similar to MmGetSystemRoutineAddress()
	//
	inline PVOID find_export( _In_ VOID* module, _In_ const char* routine_name )
	{
		UINT32* entry = find_export_entry( module, routine_name );
		if ( !entry ) return NULL;
		return ( PVOID )( ( UINT8* )module + *entry );
	}


	//
	// This will find ntoskrnl.exe without the need of using 
	// PsLoadedModuleList anymore effectively leaving 0 imports
	//
	inline PKLDR_DATA_TABLE_ENTRY find_ps_loaded_module_list( )
	{
		/* vars */
		uintptr_t addr_in_ntos = 0;
		uintptr_t starting_addr = 0;

		/* reading LSTAR to get an address within ntoskrnl.exe */
		addr_in_ntos = starting_addr = __readmsr( 0xC0000082 );
		if ( !addr_in_ntos ) return nullptr;

		/* aligning the address to a page */
		addr_in_ntos = ( addr_in_ntos & ~0xFFFFF );

		/* now we iterate backwards to find the base address of ntoskrnl.exe */
		while ( true )
		{
			/* limiting */ if ( addr_in_ntos < ( starting_addr - 0xFFFFF0000 ) ) break;

			/* getting the DOS header */
			auto dos = reinterpret_cast< PIMAGE_DOS_HEADER >( addr_in_ntos );
			if ( dos->e_magic != IMAGE_DOS_SIGNATURE || ( dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000 ) ) { addr_in_ntos -= 0x10000; continue; }

			/* getting the nt headers */
			auto nt = reinterpret_cast< PIMAGE_NT_HEADERS >( addr_in_ntos + dos->e_lfanew );
			if ( nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT )
			{ 
				addr_in_ntos -= 0x10000; 
				continue; 
			}

			/* trying to find PsLoadedModuleList */
			auto res = reinterpret_cast< PKLDR_DATA_TABLE_ENTRY >( this->find_export( reinterpret_cast< void* >( addr_in_ntos ), "PsLoadedModuleList" ) );
			if ( res ) return res; /* success */

			/* failed, onto the next page */ addr_in_ntos -= 0x10000;			
		}

		return nullptr;
	}


	//
	// simple hashing function so that we can
	// create our hashmap<func_name, ptr>
	//
	ULONG64 hash( _In_ const void* data, _In_ size_t len )
	{
		/* vars */
		ULONG64 h = 0xCBF2925120000325ULL;
		const UCHAR* p = static_cast< const UCHAR* >( data );

		/* hashing the data */
		for ( size_t i = 0; i < len; i++ )
		{
			h ^= p[i];
			h *= 0x100000001B3ULL;
		}

		return h;
	}


	//
	// setting up the hashmap base memory 
	// ( starting with 1 page of space so 256 functions )
	// 
	bool _alloc_hashmap_base_mem_( )
	{
		/* allocating the base space for the hashmap */
		this->hash_map  = reinterpret_cast< decltype( this->hash_map )>( 
			this->_ExAllocatePool2( POOL_FLAG_NON_PAGED, this->base_hashmap_space, ( ULONG )__rdtsc( ) ) );
		if ( !this->hash_map ) return false;

		/* cleaning up the memory */
		this->_impl_memset( reinterpret_cast< volatile UINT8* >( this->hash_map ), 0, this->base_hashmap_space );

		/* we gotta set the alloc count to 1 */
		this->curr_hashmap_alloc_count = 1;
		this->hashmap_bucket_count = 0;

		return true;
	}


	//
	// expanding the hashmap memory
	//
	bool _expand_hashmap_mem( )
	{
		/* vars */
		const int old_count = this->curr_hashmap_alloc_count;
		const int new_count = old_count + 1;

		/* allocating the extended space for the hashmap */
		decltype( hash_map ) _temp
			= reinterpret_cast< decltype( hash_map ) >(
				this->_ExAllocatePool2( POOL_FLAG_NON_PAGED, this->base_hashmap_space * new_count, ( ULONG )__rdtsc( ) ) );
		if ( !_temp ) return false;
		
		/* copying the current buffer into the new one */
		this->_impl_memcpy( reinterpret_cast< volatile UINT8* >( _temp ), reinterpret_cast< volatile UINT8* >( this->hash_map ), this->base_hashmap_space * old_count );

		/* freeing the previous allocation */
		this->_ExFreePoolWithTag( this->hash_map, 0 );

		/* assigning the new buffer to hashmap */
		this->hash_map = _temp;
		this->curr_hashmap_alloc_count = new_count;
		return true;
	}


	//
	// adding a new bucket to the hasmap
	//
	bool cache_add( _In_ const char* _func_name, _In_ PVOID _func_ptr )
	{
		/* param check */
		if ( !_func_name || !_func_ptr || !this->hash_map ) return false;
	
		/* checking if we're still within the bounds of the current allocation otherwise we need to expand it */
		uintptr_t limit = reinterpret_cast< uintptr_t >( this->hash_map ) + ( this->base_hashmap_space * this->curr_hashmap_alloc_count );
		uintptr_t curr = reinterpret_cast< uintptr_t >( this->hash_map ) + ( sizeof( decltype( *this->hash_map ) ) * this->hashmap_bucket_count );
		if ( curr >= limit ) { if ( !this->_expand_hashmap_mem( ) ) return false; }
		
		/* if we're still within the limits then we add our bucket */
		this->hash_map[this->hashmap_bucket_count++] = { this->hash( _func_name, this->_impl_strlen( _func_name ) ), _func_ptr };
		return true;
	}

};
