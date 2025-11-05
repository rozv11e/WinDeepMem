using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using WinDeepMem.Imports.Structures;


namespace WinDeepMem
{
    public class PEParser
    {
        private byte[] _fileBytes;

        public PEParser(byte[] fileBytes)
        {
            _fileBytes = fileBytes;
        }

        public bool Is32Bit => NtHeaders.OptionalHeader.Magic == 0x10B;
        public bool Is64Bit => NtHeaders.OptionalHeader.Magic == 0x20B;


        public IMAGE_DOS_HEADER DosHeader
        {
            get { return ReadStruct<IMAGE_DOS_HEADER>(_fileBytes, 0); }
        }

        public IMAGE_NT_HEADERS32 NtHeaders
        {
            get { return ReadStruct<IMAGE_NT_HEADERS32>(_fileBytes, DosHeader.e_lfanew); }
        }

        public uint ImageBase
        {
            get { return NtHeaders.OptionalHeader.ImageBase; }
        }

        public uint SizeOfImage
        {
            get { return NtHeaders.OptionalHeader.SizeOfImage; }
        }

        public uint EntryPoint
        {
            get { return NtHeaders.OptionalHeader.AddressOfEntryPoint; }
        }

        public uint NumberOfSections
        {
            get { return NtHeaders.FileHeader.NumberOfSections; }
        }

        // 12 - IAT; 9 - TLS; 5 - reloc;
        public IMAGE_DATA_DIRECTORY GetDirectory(int index)
        {
            if (index < 0 || index >= 16)
                throw new ArgumentOutOfRangeException(nameof(index));

            var dir = new IMAGE_DATA_DIRECTORY();

            var opt = NtHeaders.OptionalHeader;

            unsafe
            {
                uint* ptr = opt.DataDirectory;
                dir.VirtualAddress = ptr[index * 2];
                dir.Size = ptr[index * 2 + 1];
            }

            return dir;
        }

        public byte[] GetSectionData(int index, bool asImage = true)
        {
            if (index < 0 || index >= NumberOfSections)
                throw new ArgumentOutOfRangeException(nameof(index));

            // Смещение заголовков секций
            int sectionHeadersOffset = DosHeader.e_lfanew
                                       + 4
                                       + 20
                                       + NtHeaders.FileHeader.SizeOfOptionalHeader;

            // Чтение нужного заголовка секции
            var section = ReadStruct<IMAGE_SECTION_HEADER>(_fileBytes, sectionHeadersOffset + index * 40);

            int fileOffset = (int)section.PointerToRawData;
            int rawSize = (int)section.SizeOfRawData;
            int virtualSize = (int)section.VirtualSize;

            if (fileOffset + rawSize > _fileBytes.Length)
                throw new InvalidDataException("Section extends beyond file size");

            if (!asImage)
            {
                // raw data (точно как в файле)
                byte[] rawData = new byte[rawSize];
                if (rawSize > 0)
                    Array.Copy(_fileBytes, fileOffset, rawData, 0, rawSize);
                return rawData;
            }
            else
            {
                // virtualized: длина = VirtualSize, хвост дополняем нулями
                int size = Math.Max(rawSize, virtualSize);
                byte[] data = new byte[size];
                if (rawSize > 0)
                    Array.Copy(_fileBytes, fileOffset, data, 0, rawSize);
                // остальная часть уже нули
                return data;
            }
        }


        //   - GetImports()
        public void Parse()
        {
            var bytes = _fileBytes;
            var dosHeader = DosHeader;
            var ntHeaders = NtHeaders;

            if (dosHeader.e_magic != 0x5A4D)
            {
                Console.WriteLine("[Error] Invalid DOS signature!");
                return;
            }


            if (ntHeaders.Signature != 0x00004550) // "PE\0\0"
            {
                Console.WriteLine("[Error] Invalid PE signature!");
                return;
            }

            if (NumberOfSections == 0)
            {
                Console.WriteLine("[Error] Can't find sections");
                return;
            }

            Console.WriteLine("IAT");
            var iat = GetDirectory(12);
            Console.WriteLine($"0x{iat.VirtualAddress:X}");
            Console.WriteLine($"0x{iat.Size:X}");

            Console.WriteLine("TLS");
            var tls = GetDirectory(9);
            Console.WriteLine($"0x{tls.VirtualAddress:X}");
            Console.WriteLine($"0x{tls.Size:X}");


            int sectionHeadersOffset = dosHeader.e_lfanew          // Начало NT Header
                              + 4                           // PE Signature (4 байта)
                              + 20                          // IMAGE_FILE_HEADER (20 байт)
                              + ntHeaders.FileHeader.SizeOfOptionalHeader; // Optional Header


            for (int i = 0; i < NumberOfSections; i++)
            {
                var offset = sectionHeadersOffset + (i * 40);

                var section = ReadStruct<IMAGE_SECTION_HEADER>(bytes, offset);

                string sectionName = section.SectionName; // Encoding.ASCII.GetString(section.Name).TrimEnd('\0');

                Console.WriteLine($"[Section {i}] {sectionName}");
                Console.WriteLine($"  VirtualAddress (RVA): 0x{section.VirtualAddress:X}");
                Console.WriteLine($"  VirtualSize: 0x{section.VirtualSize:X} ({section.VirtualSize} bytes)");
                Console.WriteLine($"  PointerToRawData (file offset): 0x{section.PointerToRawData:X}");
                Console.WriteLine($"  SizeOfRawData: 0x{section.SizeOfRawData:X} ({section.SizeOfRawData} bytes)");
                Console.WriteLine($"  Characteristics: 0x{section.Characteristics:X}");
                Console.WriteLine();

            }


            var sec = GetSectionData(3, true);
            Console.WriteLine(BitConverter.ToString(sec));
        }


        public T ReadStruct<T>(byte[] data, int offset) where T : struct
        {
            int size = Marshal.SizeOf<T>();

            if (offset + size > data.Length)
                throw new ArgumentException("Offset + size exceeds data length");

            ReadOnlySpan<byte> span = new ReadOnlySpan<byte>(data, offset, size);
            return MemoryMarshal.Read<T>(span);
        }

    }
}