using System.Runtime.InteropServices;
using System.Text;

namespace WinDeepMem.Imports.Structures
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;       // Magic number "MZ" = 0x5A4D
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        public fixed ushort e_res1[4];   // вместо ushort[]
        public ushort e_oemid;
        public ushort e_oeminfo;
        public fixed ushort e_res2[10];  // вместо ushort[]
        public int e_lfanew;         // Offset to IMAGE_NT_HEADERS
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS32
    {
        public uint Signature; // "PE\0\0"
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
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
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;

        //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        //public IMAGE_DATA_DIRECTORY[] DataDirectory;
        public fixed uint DataDirectory[16 * 2]; // IMAGE_DATA_DIRECTORY[16] -> 2 uints per entry
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_TLS_DIRECTORY32
    {
        public uint StartAddressOfRawData;
        public uint EndAddressOfRawData;
        public uint AddressOfIndex;
        public uint AddressOfCallBacks;
        public uint SizeOfZeroFill;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct IMAGE_SECTION_HEADER
    {
        public fixed byte Name[8];           // Имя секции (8 байт, например ".text")

        public uint VirtualSize;             // Размер секции в ПАМЯТИ
        public uint VirtualAddress;          // RVA - куда загружать в памяти
        public uint SizeOfRawData;           // Размер секции в ФАЙЛЕ
        public uint PointerToRawData;        // Offset в ФАЙЛЕ, где лежат данные
        public uint PointerToRelocations;    // Для .obj файлов (обычно 0)
        public uint PointerToLinenumbers;    // Устаревшее (обычно 0)
        public ushort NumberOfRelocations;   // Для .obj файлов (обычно 0)
        public ushort NumberOfLinenumbers;   // Устаревшее (обычно 0)
        public uint Characteristics;         // Флаги (executable, readable, writable)

        public string SectionName //  свойство не меняет layout
        {
            get
            {
                fixed (byte* ptr = Name)
                {
                    return Encoding.ASCII.GetString(ptr, 8).TrimEnd('\0');
                }
            }
        }
    }
    // Всего = 40 байт

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAddress;  // RVA начала блока
        public uint SizeOfBlock;     // размер блока, включая заголовок и массив Type/Offset
    }

}
