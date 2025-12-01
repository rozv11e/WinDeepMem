using System;
using System.Runtime.InteropServices;

namespace WinDeepMem.Imports.Structures
{
    [StructLayout(LayoutKind.Sequential, Pack = 8)] // Важно: Pack = 8 для 64-бит
    public struct IMAGE_NT_HEADERS64
    {
        public uint Signature; // "PE\0\0"
        public IMAGE_FILE_HEADER FileHeader; // Эта структура одинакова
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader; // Новая 64-битная структура
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)] // Важно: Pack = 8
    public unsafe struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;                   // 0x20B
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;

        // BaseOfData (uint) отсутствует в 64-битном заголовке!

        // === 64-битные поля (ulong) ===
        public ulong ImageBase;                // 64-bit

        // ... [Поля выравнивания и версий (32-битные)] ...
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;

        // === 64-битные поля (ulong) ===
        public ulong SizeOfStackReserve;       // 64-bit
        public ulong SizeOfStackCommit;        // 64-bit
        public ulong SizeOfHeapReserve;        // 64-bit
        public ulong SizeOfHeapCommit;         // 64-bit

        // ... [Остальные поля] ...
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;

        // Data Directory (IMAGE_DATA_DIRECTORY[16])
        public fixed uint DataDirectory[16 * 2]; // Или используйте IMAGE_DATA_DIRECTORY[] с MarshalAs
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)] // Важно: Pack = 8
    public struct IMAGE_TLS_DIRECTORY64
    {
        // Адреса (Start/End/Index/Callbacks) становятся 64-битными
        public ulong StartAddressOfRawData;
        public ulong EndAddressOfRawData;
        public ulong AddressOfIndex;
        public ulong AddressOfCallBacks;

        public uint SizeOfZeroFill;
        public uint Characteristics;
    }
}
