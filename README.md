# What is Process Injection?
* It is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process’s memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.

### ****TECHNICAL DETAILS****

- ****OpenProcess API****
    
    Opens an existing local process object and return an open handle to the specified process.****
    
    **Parameters**
    
    `[in] dwDesiredAccess`
    
    The access to the process object. This access right is checked against the security descriptor for the process. This parameter can be one or more of the [process access rights](https://docs.microsoft.com/en-us/windows/desktop/ProcThread/process-security-and-access-rights).
    
    If the caller has enabled the SeDebugPrivilege privilege, the requested access is granted regardless of the contents of the security descriptor.
    
    `[in] bInheritHandle`
    
    If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
    
    `[in] dwProcessId`
    
    The identifier of the local process to be opened.
    
    If the specified process is the System Idle Process (0x00000000), the function fails and the last error code is `ERROR_INVALID_PARAMETER`. If the specified process is the System process or one of the Client Server Run-Time Subsystem (CSRSS) processes, this function fails and the last error code is `ERROR_ACCESS_DENIED` because their access restrictions prevent user-level code from opening them.
    
    If you are using [GetCurrentProcessId](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid) as an argument to this function, consider using [GetCurrentProcess](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess) instead of OpenProcess, for improved performance.
    
- VirtualAllocEx API
    
    Reserves a region of memory within the virtual address space of a specified process, The function initializes the memory it allocates to zero and return the base address of the allocated memory .
    
- WriteProcessMemory API
    
    Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.****
    
- **CreateRemoteThread API**
    
    Creates a thread that runs in the virtual address space of another process and return a handle to the new thread.
    

# DEMO 

![Alt Text](https://github.com/ZeroM3m0ry/Shellcode-Injector/blob/master/demo.gif)

