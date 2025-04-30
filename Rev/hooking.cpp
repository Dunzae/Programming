#include <stdio.h>
#include <windows.h>
#include <winnt.h>

void hookFunc(const char *str)
{
    printf("IAT puts 함수 후킹 성공 : %s\n", str);
}

int main()
{
    void *startMemory = GetModuleHandle(NULL);

    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)startMemory;
    IMAGE_FILE_HEADER *fileHeader = (IMAGE_FILE_HEADER *)(startMemory + dosHeader->e_lfanew + 4);
    IMAGE_OPTIONAL_HEADER32 *optionalHeader = (IMAGE_OPTIONAL_HEADER32 *)(fileHeader + 1);

    IMAGE_IMPORT_DESCRIPTOR *importTable = (IMAGE_IMPORT_DESCRIPTOR *)(startMemory + optionalHeader->DataDirectory[1].VirtualAddress);
    IMAGE_IMPORT_DESCRIPTOR emptyIID = {
        0,
    };
    _IMAGE_THUNK_DATA32 emptyThunkData = {
        0,
    };

    while (memcmp(importTable, &emptyIID, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0)
    {
        _IMAGE_THUNK_DATA32 *originalFirstThunk = (_IMAGE_THUNK_DATA32 *)(startMemory + importTable->OriginalFirstThunk); // Function Name Table
        _IMAGE_THUNK_DATA32 *firstThunk = (_IMAGE_THUNK_DATA32 *)(startMemory + importTable->FirstThunk);                 // Function Address Table
        int index = 0;
        while (memcmp(firstThunk, &emptyThunkData, sizeof(_IMAGE_THUNK_DATA32)) != 0)
        {
            IMAGE_IMPORT_BY_NAME *funcInfo = (IMAGE_IMPORT_BY_NAME *)(startMemory + originalFirstThunk->u1.AddressOfData);
            printf("Hint : %x\n", funcInfo->Hint);
            printf("Function Name : %s\n", funcInfo->Name);

            if (strcmp((char *)funcInfo->Name, "puts") == 0)
            {
                firstThunk->u1.Function = (DWORD)hookFunc;
                break;
            }

            originalFirstThunk += 1;
            firstThunk += 1;
        }

        index += 1;
        importTable = importTable + 1;
    }

    puts("puts 함수 실행");
    return 0;
}