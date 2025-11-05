using static WinDeepMem.Imports.WinApi;
using System.Diagnostics;
using System.Text;
using WinDeepMem.Imports.Structures;

namespace WinDeepMem
{
    public class Injector
    {
        private readonly string _pathToDll;
        private readonly Process _process;
        private readonly Memory mem;
        private readonly PEParser peParser;


        public Injector(Process targetProcess, string pathToDll)
        {
            _process = targetProcess;
            _pathToDll = pathToDll;
            mem = new Memory(targetProcess);


            var rawImage = File.ReadAllBytes(pathToDll);
            peParser = new PEParser(rawImage);
        }

        public bool InjectDll()
        {
            var hProcess = _process.Handle;
            if (hProcess == null)
            {
                Console.WriteLine("[Error] Could't get handle to process");
                return false;
            }

            if (string.IsNullOrEmpty(_pathToDll))
            {
                Console.WriteLine("[Error] Path string is empty");
                return false;
            }

            byte[] path = Encoding.Unicode.GetBytes(_pathToDll + "\0");
            uint size = (uint)path.Length;

            // Allocate memory in remote process
            var pDllPath = VirtualAllocEx(hProcess,
                IntPtr.Zero,
                size,
                (uint)MemoryAllocationType.MEM_COMMIT,
                (uint)MemoryProtectionType.PAGE_READWRITE);
            
            if (pDllPath == IntPtr.Zero)
            {
                Console.WriteLine("Could not write to memory in remote process");
                return false;
            }

            Thread.Sleep(500);

            Console.WriteLine("[Debug] pDllPath: 0x" + pDllPath.ToString("X"));

            // for LoadLibraryW (UTF-16) - Unicode || LoadLibraryA (ANSI) - Default
            mem.WriteBytes(pDllPath, path);
            Thread.Sleep(500);

            // Check if array isn't empty
            var bytesToRead = mem.ReadBytes(pDllPath, (uint)path.Length);
            Console.WriteLine("[Debug] bytesToRead: " + BitConverter.ToString(bytesToRead));


            var hModule = GetModuleHandle("kernel32.dll");
            if (hModule == nint.Zero)
            {
                Console.WriteLine("[Error] Could't get handle to kernel32.dll");
                return false;
            }

            var ploadlib = GetProcAddress(hModule, "LoadLibraryW");
            if (ploadlib == nint.Zero)
            {
                Console.WriteLine("[Error] Couldn't get pointer to LoadLibraryW");
                return false;
            }

            Console.WriteLine("[Debug] pLoadLibraryA: 0x" + ploadlib.ToString("X"));
            Thread.Sleep(500);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, ploadlib, pDllPath, 0, out _);
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[Error] phThread: 0x" + hThread.ToString("X"));
                VirtualFreeEx(hProcess, pDllPath, 0, MemoryFreeType.MEM_RELEASE);
                return false;
            }

            Console.WriteLine("[Debug] hThread: 0x" + hThread);

            // Wait thread finish
            WaitForSingleObject(hThread, INFINITE);

            //uint exitCode;

            //if (!GetExitCodeThread(hThread, out exitCode))
            //{
            //    Console.WriteLine("[Error] Could not get thread exit code.");
            //    return false;
            //}

            //if (exitCode == 0)
            //{
            //    Console.WriteLine("[Error] Call to LoadLibraryW in remote process failed. DLL must have exited non-gracefully.");
            //    return false;
            //}

            var error = GetLastError();
            Console.WriteLine("[Debug] LastError: " + error);

            VirtualFreeEx(hProcess, pDllPath, 0, MemoryFreeType.MEM_RELEASE);

            return true;
        }


        public bool MapImage(byte[] rawImage)
        {

            // Get headers
            var dosHeader = peParser.DosHeader;
            var ntHeaders = peParser.NtHeaders;
            var optionalHeader = ntHeaders.OptionalHeader;
            var fileHeader = ntHeaders.FileHeader;

            var imageBase = optionalHeader.ImageBase;
            var entryPoint = optionalHeader.AddressOfEntryPoint;
            var remoteSize = optionalHeader.SizeOfImage;
            
            // Create buffer for alloc
            var buffer = new byte[remoteSize];

            // Move headers to buffer
            Array.Copy(rawImage, buffer, optionalHeader.SizeOfHeaders);

            // Print - MZ
            var mz = new byte[2];
            Array.Copy(buffer, mz, 2);
            Console.WriteLine(Encoding.UTF8.GetString(mz));


            int sectionHeadersOffset = dosHeader.e_lfanew
                                       + 4
                                       + 20
                                       + ntHeaders.FileHeader.SizeOfOptionalHeader;

            // Move sections
            for (int i = 0; i < peParser.NumberOfSections; i++)
            {
                var offset = sectionHeadersOffset + i * 40;
                var section = peParser.ReadStruct<IMAGE_SECTION_HEADER>(rawImage, offset);

                // Print: Name, VirtualAddress, VirtualSize, PointerToRawData, SizeOfRawData
                Console.WriteLine(section.SectionName);
                // memory:
                Console.WriteLine(section.VirtualAddress.ToString("X"));
                Console.WriteLine(section.VirtualSize.ToString("X"));
                // file:
                Console.WriteLine(section.PointerToRawData.ToString("X"));
                Console.WriteLine(section.SizeOfRawData.ToString("X"));
                Console.WriteLine();

                Array.Copy(
                    rawImage, // From
                    section.PointerToRawData, // offset in file
                    buffer, // To
                    section.VirtualAddress, // offset in memory
                    section.SizeOfRawData); // size of bytes to copy
            }

            // Alloc
            var allocatedBase = mem.AllocateMemory((uint)buffer.Length);
            Console.WriteLine("Allocated memory: 0x" + allocatedBase.ToString("X"));
            mem.WriteBytes(allocatedBase, buffer);
            // Check alloc
            var dllBytes = mem.ReadBytes(allocatedBase, 10);
            Console.WriteLine("BytesWrited: " + BitConverter.ToString(dllBytes));

            // Relocations
            Console.WriteLine("Relocations");
            IMAGE_DATA_DIRECTORY relocs = peParser.GetDirectory(5);
            Console.WriteLine(relocs.VirtualAddress.ToString("X"));
            Console.WriteLine(relocs.Size.ToString("X"));

            var delta = (int)(allocatedBase - optionalHeader.ImageBase);

            var currentBlock = allocatedBase + relocs.VirtualAddress;

            while (true)
            {
                // Read block header
                var block = mem.ReadStruct<IMAGE_BASE_RELOCATION>((nint)(currentBlock));
                
                if (block.SizeOfBlock == 0) 
                    break;

                var pageVA = block.VirtualAddress;
                var count = (block.SizeOfBlock - 8) / 2; // Count of TypeOffset

                var entry = currentBlock + 8; // 8 - cuz our header (pageVA + sizeOfBlock) = 8 byte

                for (int i = 0; i < count; i++)
                {
                    ushort typeOffset = mem.ReadUShort((IntPtr)entry + i * 2);

                    // WORD Type   : 4;
                    // WORD Offset : 12; 
                    int type = typeOffset >> 12; 
                    int offset = typeOffset & 0xFFF;

                    if (type == 0 || type == 10) continue; // 10 - x64, IMAGE_REL_BASED_ABSOLUTE - 0, 3 - IMAGE_REL_BASED_HIGHLOW

                    // Patch reloc addr
                    var patchAddr = allocatedBase + block.VirtualAddress + offset;
                    var value = mem.ReadInt32((IntPtr)patchAddr);
                    if (type == 0x3) // IMAGE_REL_BASED_HIGHLOW
                    {
                        mem.WriteBytes((nint)patchAddr, BitConverter.GetBytes(value + delta));
                    }
                }

                // Get the next block
                currentBlock += block.SizeOfBlock;
            }

            // IAT
            // TLS
            // Execute - createRemoteThread or thread hijacking

            return true;
        }

        // TODO: Unload
    }
}
