#include "pch.h"
#include <fstream>

std::pair<std::unique_ptr<char[]>, std::streampos> GetOriginalExePtr()
{
    fstream file("test.exe", std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open())
    {
        printf("Couldn't open test.exe\n");
        return std::make_pair(nullptr, std::streampos());
    }

    file.seekg(0, std::ios::end);

    auto ogSize = file.tellg();

    file.seekg(0, std::ios::beg);

    std::unique_ptr<char[]> exePtr(new char[ogSize]);

    file.read(exePtr.get(), ogSize);
    file.close();

    return std::make_pair(std::move(exePtr), ogSize);
}

void DumpSelf(CModule* selfMod)
{
    CModule* loader = &g_sCachedModules["loader.dll"];

    // Get a ROP gadget for setting our RIP into loader.dll for reading .text. There is a 8-Byte version but I just went with this.
    auto readByteFn = CMemory(loader->GetModuleBase()).FindPatternSelf("8A 01 C3", CMemory::Direction::DOWN, loader->GetModuleSize()).RCast<uint8_t(*)(uintptr_t)>();

    CMemory memAllocated = VirtualAlloc(NULL, selfMod->GetModuleSize(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memAllocated)
    {
        printf("Failed to allocate memory.\n");
        return;
    }

    // Dump the whole module now.
    for (int i = 0; i < selfMod->GetModuleSize(); i++)
    {
        *reinterpret_cast<uint8_t*>(memAllocated.GetPtr() + i) = readByteFn(selfMod->GetModuleBase() + i);
    }

    // Instead of Hyperion replacing the section containing the encrypted/obfuscated code they create a dynamic function table.
    // Here we parse it and replace it with the existing one.
    // Cool article on this topic: https://hackmag.com/uncategorized/exceptions-for-hardcore-users/
    CModule* ntdll = &g_sCachedModules["ntdll.dll"];

    // Get dynamicFunctionTableStruct from RtlAddFunctionTable lea operation on a ptr of it.
    CMemory dynamicFunctionTableStruct = ntdll->FindPatternSIMD("48 8D 0D ? ? ? ? 48 39 08 74 21").ResolveRelativeAddressSelf(0x3, 0x7).DerefSelf();

    // Get the actual table containing the exception directory.
    CMemory runtimeFunctionTable = dynamicFunctionTableStruct.Offset(0x10).Deref();

    // Get the count of functions in the exception directory.
    uint32_t dynamicFuctionTableCount = dynamicFunctionTableStruct.Offset(0x54).GetValue<uint32_t>();

    // Taking it times 12 due to the each entry being that size and we write per byte.
    uint32_t dynamicFuctionTableCountBytes = dynamicFuctionTableCount * 12;

    // Get NT Header from our full dump.
    IMAGE_NT_HEADERS64* ntDumpHdr = reinterpret_cast<IMAGE_NT_HEADERS64*>(memAllocated.GetPtr() + reinterpret_cast<IMAGE_DOS_HEADER*>(memAllocated.GetPtr())->e_lfanew);

    IMAGE_SECTION_HEADER* hDumpSection = IMAGE_FIRST_SECTION(ntDumpHdr);

    for (WORD i = 0; i < ntDumpHdr->FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER& hCurrentSection = hDumpSection[i];
        std::string sec = std::string(reinterpret_cast<const char*>(hCurrentSection.Name));

        if (sec.compare(".text") == 0)
        {
            printf("Found Dump .text, fixing .text now.\n");

            // Fix Characteristics of .text.
            hCurrentSection.Characteristics = 0x60000020;
        }

        if (sec.compare("") == 0)
        {
            // Fix .pdata in full dump.
            printf("Found Dump .pdata, fixing .pdata now.\n");

            // Give section a name now. (It deserves it :D)
            char pdata[8] = { ".pdata\0" };
            memcpy(hCurrentSection.Name, pdata, 8);

            // Fix exception data directory.
            ntDumpHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = hCurrentSection.VirtualAddress;
            ntDumpHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = dynamicFuctionTableCount;

            for (int a = 0; a < dynamicFuctionTableCountBytes; a++)
            {
                *reinterpret_cast<uint8_t*>((memAllocated.GetPtr() + hCurrentSection.VirtualAddress) + a) = *reinterpret_cast<uint8_t*>(runtimeFunctionTable.GetPtr() + a);
            }
        }

        // Fix all section data.
        hCurrentSection.SizeOfRawData = hCurrentSection.Misc.VirtualSize;
        hCurrentSection.PointerToRawData = hCurrentSection.VirtualAddress;
    }

    printf("Writing full dump.\n");

    ofstream afteros("full_dump.bin", std::ios::out | std::ios::binary);
    afteros.write((char*)memAllocated.GetPtr(), selfMod->GetModuleSize());
    afteros.close();

    // Now we use the packed .exe as a base for making a "clean" one,
    auto exePtr = GetOriginalExePtr();
    IMAGE_NT_HEADERS64* ntOgHdr = reinterpret_cast<IMAGE_NT_HEADERS64*>(exePtr.first.get() + reinterpret_cast<IMAGE_DOS_HEADER*>(exePtr.first.get())->e_lfanew);

    IMAGE_SECTION_HEADER* hOgSection = IMAGE_FIRST_SECTION(ntOgHdr);

    for (WORD i = 0; i < ntDumpHdr->FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER& hCurrentSection = hOgSection[i];
        std::string sec = std::string(reinterpret_cast<const char*>(hCurrentSection.Name));

        if (sec.compare(".text") == 0)
        {
            // Fix .text clean data.
            printf("Found OG .text, overwriting now.\n");

            // Fix Characteristics of .text.
            hCurrentSection.Characteristics = hDumpSection[i].Characteristics;

            // Now write all the .text data into our base .exe.
            for (int a = 0; a < hCurrentSection.SizeOfRawData; a++)
            {
                *reinterpret_cast<uint8_t*>((exePtr.first.get() + hCurrentSection.PointerToRawData) + a) = *reinterpret_cast<uint8_t*>((memAllocated.GetPtr() + hDumpSection[i].PointerToRawData) + a);
            }
        }

        if (sec.compare("") == 0)
        {
            // Fix .pdata clean data.
            printf("Found OG .pdata, fixing .pdata now.\n");

            // Fix exception data directory.
            ntOgHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = hCurrentSection.VirtualAddress;
            ntOgHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = dynamicFuctionTableCount;

            // Give section a name now. (It deserves it :D)
            memcpy(hCurrentSection.Name, hDumpSection[i].Name, 8);
            for (int a = 0; a < dynamicFuctionTableCountBytes; a++)
            {
                *reinterpret_cast<uint8_t*>((exePtr.first.get() + hCurrentSection.PointerToRawData) + a) = *reinterpret_cast<uint8_t*>(runtimeFunctionTable.GetPtr() + a);
            }
        }
    }

    printf("Writing .bin now.\n");

    // Imports and bla are broken. You will need to manually fix them with Scylla.

    ofstream cleanos("clean_dump.bin", std::ios::out | std::ios::binary);
    cleanos.write(exePtr.first.get(), exePtr.second);
    cleanos.close();

    VirtualFree(memAllocated, 0, MEM_RELEASE);
}

void Initialize()
{
    GetModules();

    CModule* self = &g_sCachedModules["self.exe"];

    //self.UnlinkFromPEB();

    if (AllocConsole())
    {
        SetConsoleTitle("hypercat");

        // Open input/output streams
        FILE* fDummy;
        freopen_s(&fDummy, "CONIN$", "r", stdin);
        freopen_s(&fDummy, "CONOUT$", "w", stdout);
        freopen_s(&fDummy, "CONOUT$", "w", stderr);
    }

    DumpSelf(self);
}

void Terminate()
{
    FreeConsole();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            Initialize();
            break;
        }

        case DLL_PROCESS_DETACH:
        {
            Terminate();
            break;
        }
    }

    return TRUE;
}