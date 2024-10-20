# AmsiBypass
 Bypassing AMSI using `LdrLoadDll`, either through hooking or by utilizing a hardware breakpoint.<br>
 ## LdrLoadDll!Ntdll.dll
 `LdrLoadDll` is the final destination for all WinAPI functions such as `LoadLibraryA`, `LoadLibraryW`, `LoadLibraryExA`, and `LoadLibraryExW` before the DLL is actually loaded into the process's address space. This means that by hooking LdrLoadDll, we effectively hook all these WinAPI functions.
 ## A Look at [CoreCLR](https://github.com/dotnet/runtime/) source code
  By examining the CoreCLR , which is the CLR runtime for .NET Core, it can be seen that when a buffer is scanned by AMSI, amsi.dll is loaded first, followed by the scanning process using AmsiScanBuffer. If the initialization fails, it returns that the content is not detected. It can be assumed that this is also the case for the .NET Framework CLR.</br>[Amsi::IsBlockedByAmsiScan](https://github.com/dotnet/runtime/blob/dfc2b85a00f3baf5ac52d7615bf857e6217011c8/src/coreclr/vm/amsi.cpp#L16)</br>
  
 <img width="667" alt="image" src="https://github.com/user-attachments/assets/fcc88b5d-13d3-491e-8b20-e9ce56dc6f93">

 ## Technique <br>
   when `amsi.dll` is loaded using `LdrLoadDll`, we return an 'Access Denied' error, effectively bypassing AMSI." <br>
  
  - ### Using Hardware breakpoints
    Resolve the address of LdrLoadDll and register a hardware breakpoint on it. When our exception handler is invoked, retrieve the dllName argument, which is the third argument located in the r8 register in the x64 architecture. Check if the dllName contains amsi.dll. If it does, obtain the return address from the stack, manually pop the return address from the stack, and return an 'Access Denied' response in the rax register. This will prevent amsi.dll from loading, effectively bypassing AMSI.<br>

    <img width="569" alt="image" src="https://github.com/user-attachments/assets/5d54602d-4811-4606-9116-5cdaecf59f04">

 - ### Using Hooking
    By inserting a hook into LdrLoadDll, we can redirect to our own version of LdrLoadDll using an unconditional jump instruction. This allows us to inspect the dllName argument; if the DLL being loaded is amsi.dll, we simply return an 'Access Denied' response, thereby bypassing AMSI.
   
    <img width="655" alt="image" src="https://github.com/user-attachments/assets/d3402d3f-521a-4d82-96fa-b2d03e0a8277">
- ## Proof of Concept
  <img width="1153" alt="image" src="https://github.com/user-attachments/assets/9c012993-9e9c-4f8a-ba06-9fe1e5715bd1">
