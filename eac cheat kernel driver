#include <ntddk.h>

// Define the driver entry function
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

// Define the unload function to restore the original process name
VOID UnloadDriver(_In_ PDRIVER_OBJECT DriverObject);

// Define the callback function to change the process name
VOID ChangeProcessNameCallback(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo);

// Define the global variable for the callback registration
PVOID g_CallbackRegistration = NULL;

// Define the function to hide the driver from Easy Anti-Cheat
VOID HideDriverFromEAC();

// Define the function to hide the driver from process listing
VOID HideDriverFromProcessListing();

// Driver entry point
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // Register the process creation callback
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(ChangeProcessNameCallback, FALSE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    // Save the registration handle for cleanup
    g_CallbackRegistration = (PVOID)1;

    // Set the unload function
    DriverObject->DriverUnload = UnloadDriver;

    // Hide the driver from Easy Anti-Cheat
    HideDriverFromEAC();

    // Hide the driver from process listing
    HideDriverFromProcessListing();

    return STATUS_SUCCESS;
}

// Unload function
VOID UnloadDriver(_In_ PDRIVER_OBJECT DriverObject)
{
    // Unregister the process creation callback
    if (g_CallbackRegistration != NULL)
    {
        PsSetCreateProcessNotifyRoutineEx(ChangeProcessNameCallback, TRUE);
        g_CallbackRegistration = NULL;
    }

    // Clear the unload function
    DriverObject->DriverUnload = NULL;
}

// Callback function to change the process name
VOID ChangeProcessNameCallback(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _Inout_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(ParentId);
    
    // Generate a random process name
    WCHAR newName[MAX_PATH];
    const WCHAR* baseName = L"NewProcessName";
    swprintf_s(newName, MAX_PATH, L"%s_%04X", baseName, (USHORT)ProcessId);

    // Change the process name
    UNICODE_STRING newProcessName;
    RtlInitUnicodeString(&newProcessName, newName);
    RtlCopyUnicodeString(&CreateInfo->ImageFileName, &newProcessName);
}

// Function to hide the driver from Easy Anti-Cheat
VOID HideDriverFromEAC()
{
    HANDLE eacHandle = NULL;
    OBJECT_ATTRIBUTES objAttributes;
    UNICODE_STRING driverName;

    // Open a handle to the Easy Anti-Cheat driver
    RtlInitUnicodeString(&driverName, L"\\Device\\EasyAntiCheatDriver");
    InitializeObjectAttributes(&objAttributes, &driverName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS status = ZwOpenFile(&eacHandle, FILE_ALL_ACCESS, &objAttributes, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE);
    if (NT_SUCCESS(status))
    {
        // Hide the driver from Easy Anti-Cheat
        FILE_BASIC_INFORMATION basicInfo;
        basicInfo.FileAttributes = FILE_ATTRIBUTE_HIDDEN;
        status = ZwSetInformationFile(eacHandle, &IoStatusBlock, &basicInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation);
        ZwClose(eacHandle);
    }
}

// Function to hide the driver from process listing
VOID HideDriverFromProcessListing()
{
    PEPROCESS currentProcess = PsGetCurrentProcess();
    ULONG_PTR pProcess = (ULONG_PTR)currentProcess;

    // Set the process to be invisible in the process list
    if (NT_SUCCESS(ObReferenceObjectByPointer(currentProcess, STANDARD_RIGHTS_ALL, NULL, KernelMode)))
    {
        ULONG_PTR pActiveProcessLinks = pProcess + 0x188;
        PLIST_ENTRY pActiveProcessLinksListEntry = (PLIST_ENTRY)pActiveProcessLinks;

        // Remove the process from the active process links list
        pActiveProcessLinksListEntry->Blink->Flink = pActiveProcessLinksListEntry->Flink;
        pActiveProcessLinksListEntry->Flink->Blink = pActiveProcessLinksListEntry->Blink;

        // Remove the process from the session process links list
        PLIST_ENTRY pSessionProcessLinksListEntry = (PLIST_ENTRY)(pProcess + 0x188 + 0x2f0);
        pSessionProcessLinksListEntry->Blink->Flink = pSessionProcessLinksListEntry->Flink;
        pSessionProcessLinksListEntry->Flink->Blink = pSessionProcessLinksListEntry->Blink;

        ObfDereferenceObject(currentProcess);
    }
}
