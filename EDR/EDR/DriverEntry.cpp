#include<ntifs.h>

EXTERN_C PCHAR PsGetProcessImageFileName(PEPROCESS Process);

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	ULONG64 ExceptionTable;
	ULONG64 ExceptionTableSize;
	ULONG64 GpValue;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG64 Flags;

}KLDR_DATA_TABLE_ENTRY,*PKLDR_DATA_TABLE_ENTRY;


EXTERN_C VOID
ProcessNotifyRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
	HANDLE hParentProcessId = NULL;
	PCHAR pszImageFileName = PsGetProcessImageFileName(Process);
	//CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
	
	if (CreateInfo == NULL)
	{
		DbgPrint("[ExitProcess][Name:%s][Id:%d]", pszImageFileName, ProcessId);
	}
	else
	{

		hParentProcessId = CreateInfo->CreatingThreadId.UniqueProcess;
		PEPROCESS pEprocess = NULL;
		PsLookupProcessByProcessId(hParentProcessId, &pEprocess);
		PCHAR ParentProcessName = PsGetProcessImageFileName(pEprocess);
		DbgPrint("[CreateProcess][Name:%s][Id:%d][[ParentName:%s][ParentId:%d][Path:%wZ]", pszImageFileName, ProcessId, ParentProcessName,hParentProcessId,CreateInfo->ImageFileName);
		PCHAR ProtectName = "chrome.exe";
		int result = strcmp(ParentProcessName, ProtectName);
		int result2 = strcmp(pszImageFileName, ProtectName);
		if (result == 0&& result2!=0) {
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
		}
	}
}

EXTERN_C VOID GrkUnInstallNotifyRoutine()
{
	NTSTATUS ntStatus = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyRoutine, TRUE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("PsSetCreateProcessNotifyRoutineEx UnInstall Failed!\r\n");
	}
}


EXTERN_C VOID GrkInstallNotifyRoutine()
{
	NTSTATUS ntStatus = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyRoutine, FALSE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("PsSetCreateProcessNotifyRoutineEx Install Failed!\r\n");
	}
}

EXTERN_C VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	GrkUnInstallNotifyRoutine();
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	PKLDR_DATA_TABLE_ENTRY pKLDR = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	pKLDR->Flags |= 0x20;
	GrkInstallNotifyRoutine();
	pDriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}