# NoImportz ( By: Th3Spl )

So, i was reading a blog post about cheat detections from anti-cheats ( ACs ) </br>
specifically [`Detecting manually mapped drivers`](https://tulach.cc/detecting-manually-mapped-drivers/)
written by [`SamuelTulach`](https://github.com/SamuelTulach) <br/> 
so after reading it i came up with a very simple solution... <br/>
I highly suggest to read the article before checking this project out.

## How it works:
So, it's very easy and straightforward but i would like to explain so that people <br/>
who are just getting into the windows Kernel environment can gather some useful info. <br/>

- We get the content of the LSTAR MSR, which is a pointer within ntoskrnl.exe's memory.
- We iterate backwards at 64Kb granularity until we find a PE that looks like ntoskrnl's one.
- We get the `PsLoadedModuleList` ( which contains all the legitimately loaded drivers ) through ntoskrnl's exports.
- We iterate through the list and find the target module base address.
- We dynamically find the exports using some `PE Header` knowledge ( similar to `MmGetSystemRoutineAddress` )
- We then use some modern C++ features to create a single function `call` which can handle everything

And well... that's all, it's actually nothing new or extraordinary but it can still be useful for someone <br/><br/>

## Usage: 
For a simple code example ready to compile you can check out the [`example project`](https://github.com/Th3Spl/NoImportz/tree/main/NoImportz). <br/>
**It requires: `ISO C++17 Standard (/std:c++17)`**

Initialization:
```cpp
/* This will target ONLY ntoskrnl.exe */ 
NoImportz winapi;

/* In case you want to specify a specific module */
NoImportz fltmgr( L"fltmgr.sys" );

/* Initialization check */
if ( !winapi.is_initialized() )
  return STATUS_UNSUCCESSFUL;
```

Calling a function:
```cpp
/* standard call */
PVOID addr = winapi.call<decltype( ExAllocatePool2 )> (
	"ExAllocatePool2", POOL_FLAG_NON_PAGED,
	4096, 'TeSt'
);

/* using wrapper MACROs */
addr = ni_call(
	winapi, ExAllocatePool2, 
	POOL_FLAG_NON_PAGED, 4096, 'TeSt'
);
```

## Features:
- [x] Supports all modules
- [x] Supports variadic functions
- [x] **NEW**: Supports caching

#### By: Th3Spl

