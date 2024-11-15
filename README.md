# NoImportz ( By: Th3Spl )

So, i was reading a blog post about cheat detections from anti-cheats ( ACs ) </br>
specifically [`Detecting manually mapped drivers`](https://tulach.cc/detecting-manually-mapped-drivers/)
written by [`SamuelTulach`](https://github.com/SamuelTulach) <br/> 
so after reading it i came up with a very simple solution... <br/>
I highly suggest to read the article before checking this project out.

## How it works:
So, it's very easy and straightforward but i would like to explain so that people <br/>
who are just getting into the windows Kernel environment can gather some useful info. <br/>

- We get the `PsLoadedModuleList` ( which contains all the legitly loaded drivers )
- We iterate through the list and find the target module base address
- We dynamically find the exports using some `PE Header` knowledge ( similar to `MmSystemRoutineAddress` )
- We then use some modern C++ features to create a single function `call` which can handle everything

And well... that's all, is actually nothing new or extraordinary but it can still be useful for someone <br/><br/>
**Note: there will be only one import: `PsLoadedModuleList` which will most likely be inlined by the compiler </br>
and does not represent a problem since it does not generate `jmp` ( it's just a pointer. )**

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
PVOID addr = winapi.call<decltype( ExAllocatePool2 )> (
	"ExAllocatePool2", POOL_FLAG_NON_PAGED,
	4096, 'TeSt'
);
```
**Note: if you have to call a function multiple times you can wrap it into a different unique function...**

## Features:
- [x] Supports all modules
- [x] Supports variadic functions

#### By: Th3Spl

