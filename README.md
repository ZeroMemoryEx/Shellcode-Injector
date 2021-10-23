# What is Process Injection?
* It is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process’s memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.

# TECHNICAL DETAILS

* Open process with Access Rights
* LPTHREAD_START_ROUTINE (its a pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process. The function must exist in the remote process.)
* VirtualAllocEx (used to allocate space from the target process virtual memory)
* WriteProcessMemory (used to write the path of the shellcode into the allocated memory)
* CreateRemoteThread (used to creates a thread in the virtual memory area of a process)
* WaitForSingleObject (Waits until the specified object is in the signaled state or the time-out interval elapses)

# Other Features 

* RtlSetProcessIsCritical used to protect the process from termination , any attempt to terminate it will cause the system to crash (Not Stable)

# DEMO 

![Alt Text](https://github.com/ZeroM3m0ry/Shellcode-Injector/blob/master/demo.gif)

