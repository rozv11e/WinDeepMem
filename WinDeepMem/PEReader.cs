using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using WinDeepMem.Imports.Structures;
using static WinDeepMem.Imports.NativeAPI;
using static WinDeepMem.Imports.WinApi;

namespace WinDeepMem
{
    public unsafe class PEReader // Read PE in memory
    {
        private readonly Process process;
        private readonly Memory memory;
        public PEReader(Process process)
        {
            this.process = process;
            memory = new Memory(process);
        }

        public TEB GetTEB(int threadId)
        {
            ProcessThread thread = process.Threads
            .Cast<ProcessThread>()
            .FirstOrDefault(t => t.Id == threadId);

            if (thread == null)
            {
                Console.WriteLine($"Thread {threadId} not found in process");
                return default;
            }

            IntPtr hThread = OpenThread(
                    (uint)ThreadAccess.QUERY_INFORMATION,
                    false,
                    (uint)thread.Id);

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine($"Failed to open thread {threadId}");
                return default;
            }

            try
            {
                THREAD_BASIC_INFORMATION tbi;
                int retLen;


                int status = NtQueryInformationThread(
                       hThread,
                       THREADINFOCLASS.ThreadBasicInformation,
                       out tbi,
                       (int)Marshal.SizeOf(typeof(THREAD_BASIC_INFORMATION)),
                       out retLen);

                if (status != 0)
                {
                    Console.WriteLine($"NtQueryInformationThread failed with status: 0x{status:X}");
                    return default;
                }

                return memory.ReadStruct<TEB>(tbi.TebBaseAddress);
            }
            finally
            {
                CloseHandle(hThread);
            }
        }

        // Reversing Common Obfuscation Techniques  https://web.archive.org/web/20220408174924/https://ferib.dev/blog.php?l=post/Reversing_Common_Obfuscation_Techniques
        // Manipulating PEB — Process Environment Block - https://medium.com/@s12deff/manipulating-peb-process-environment-block-e21374d9e0eb
        public PEB GetPEB()
        {
            PEB peb = new PEB();

            var threads = process.Threads;
            var teb = GetTEB(threads[0].Id);
            if (teb.Equals(default(TEB)))
            {
                Console.WriteLine("Failed to read TEB for PEB");
                return default;
            }

            return memory.ReadStruct<PEB>(teb.ProcessEnvironmentBlock);
        }
        public RTL_USER_PROCESS_PARAMETERS GetProcParams()
        {
            var peb = GetPEB();
            return memory.ReadStruct<RTL_USER_PROCESS_PARAMETERS>(peb.ProcessParameters);
        }

        #region LDR

        public LDR_DATA_TABLE_ENTRY GetModule(string name)
        {
            string target = name.ToLower();

            foreach (var module in GetLoadedModules())
            {
                string dllName = ReadUnicodeString(module.BaseDllName).ToLower();
                Console.WriteLine($"|LDR|DLL_NAME|{dllName}");
                if (dllName == target)
                    return module;
            }

            return new LDR_DATA_TABLE_ENTRY();
        }

        public IEnumerable<LDR_DATA_TABLE_ENTRY> GetLoadedModules()
        {
            List<LDR_DATA_TABLE_ENTRY> moudleList = new List<LDR_DATA_TABLE_ENTRY>();

            var peb = GetPEB();

            PEB_LDR_DATA ldrData = memory.ReadStruct<PEB_LDR_DATA>(peb.Ldr);

            var currentEntry = ldrData.InLoadOrderModuleList.Flink;
            var head = currentEntry;
            //Console.WriteLine($"Head: 0x{head:X}");

            var tale = ldrData.InInitializationOrderModuleList.Blink;
            //Console.WriteLine($"Tale: 0x{tale:X}");

            do
            {
                var module = memory.ReadStruct<LDR_DATA_TABLE_ENTRY>(currentEntry);
                moudleList.Add(module);

                currentEntry = module.InLoadOrderLinks.Flink;
            } while (currentEntry != ldrData.InLoadOrderModuleList.Flink);


            return moudleList;
        }
        /// <summary>
        /// Example: "Loader.dll"
        /// </summary>
        /// <param name="moduleName">ext</param>
        /// <returns></returns>
        public bool HideModule(string moduleName)
        {
            var modules = GetLoadedModules();

            var module = modules.FirstOrDefault(m => ReadUnicodeString(m.BaseDllName) == moduleName);
            if (!module.Equals(default(LDR_DATA_TABLE_ENTRY)))
            {
                // Write Module header:
                IntPtr size = (IntPtr)0x1000;
                IntPtr baseAddr = module.DllBase;
                uint oldProtect;

                int status = NtProtectVirtualMemory(process.Handle, ref baseAddr, ref size, (uint)MemoryProtectionType.PAGE_READWRITE, out oldProtect);
                if (status == 0)
                {
                    memory.ZeroMemory(module.DllBase, 0x1000);
                    NtProtectVirtualMemory(process.Handle, ref baseAddr, ref size, oldProtect, out _);
                }
                else
                {
                    Console.WriteLine("[Error] NtProtectVirtualMemory failed");
                    return false;
                }
            }

            // Delete size in PEB

            return false;
        } // TODO: Add ldr remove // Manipulate PEB to hide Loaded DLL - https://medium.com/@s12deff/manipulate-peb-to-hide-loaded-dll-1f7c54507a43
        #endregion


        public void Test()
        {

            /// TODO: 
            /// TLS Callback, IAT (Read/Hook), SEH, Syscalls, Hijack, Dumper
            /// ASM
            /// Detour
            /// spoof ret func address
            /// Syscalls
            /// thread hijacking
            /// process hollowing

            var peb = GetPEB();

            IntPtr ImageBase = peb.ImageBaseAddress;
            Console.WriteLine($"Base: 0x{ImageBase:X}");

            var dosHeader = memory.ReadStruct<IMAGE_DOS_HEADER>(ImageBase);
            var ntHeader = memory.ReadStruct<IMAGE_NT_HEADERS32>(ImageBase + dosHeader.e_lfanew);

            var sections = ntHeader.FileHeader.NumberOfSections;
            Console.WriteLine(sections);
            var size = ntHeader.FileHeader.SizeOfOptionalHeader;
            Console.WriteLine($"size:{size:X}");

            IMAGE_OPTIONAL_HEADER32 optionalHeader = ntHeader.OptionalHeader;
            //Console.WriteLine(ntHeader.OptionalHeader.DataDirectory[9].ToString("X"));

            int tlsDataDirOffset = 9 * 8;
            IntPtr optionalHeaderPtr = ImageBase + dosHeader.e_lfanew + 4 + 20;
            IntPtr tlsDataDirPtr = optionalHeaderPtr + 0x60 + tlsDataDirOffset;

            var tlsDataDir = memory.ReadStruct<IMAGE_TLS_DIRECTORY32>(tlsDataDirPtr);

            // IAT

            //IMAGE_DATA_DIRECTORY iat;

            //iat.VirtualAddress = ntHeader.OptionalHeader.DataDirectory[1 * 2 + 0];
            //iat.Size = ntHeader.OptionalHeader.DataDirectory[1 * 2 + 1];

            // https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++
            // https://www.youtube.com/watch?v=g4RaCFXUqhQ


            // TLS Rva HERE and get Tls Callbacks

            // Dump PEB :
            /// BeingDebugged
            /// ImageBaseAddress
            /// Ldr
            ///     InLoadOrderModuleList
            /// ProcessParameters
            ///     DebugFlags
            ///     ConsoleHandle
            ///     StandartInput
            ///     StandartOutput
            ///     ImagePathName
            ///     CommandLine
            ///     Enviroment
            ///     WindowTitle
            ///     ShellInfo
            /// ProcessHeap
        }

        public void GetAddress<T>(long offset, int dataPosition) where T : unmanaged
        {
            var _base = process.MainModule.BaseAddress;
            uint size = (uint)sizeof(T);

            IntPtr instructionAddress = IntPtr.Add(_base, (int)offset);
            Console.WriteLine($"insructionAddress: {instructionAddress:X}");


            int res;
            // Читаем ОТНОСИТЕЛЬНОЕ СМЕЩЕНИЕ (4 байта)
            memory.Read<int>(IntPtr.Add(instructionAddress, dataPosition), out res);
            Console.WriteLine("ОТНОСИТЕЛЬНОЕ СМЕЩЕНИЕ " + res.ToString("X"));

            // Вычисляем АБСОЛЮТНЫЙ АДРЕС данных
            IntPtr dataAddress = IntPtr.Add(instructionAddress, dataPosition + 4 + res);

            // Преобразуем в RVA (относительное смещение от базы)
            long rva = (long)dataAddress - (long)_base;
            Console.WriteLine($"Data RVA: 0x{rva:X}");
        } // https://github.com/Razzue/Wow-Dumper/blob/main/Version2/Helpers/Scan.cs

        public string ReadUnicodeString(UNICODE_STRING ustr)
        {
            if (ustr.Buffer == IntPtr.Zero || ustr.Length == 0)
                return string.Empty;

            byte[] buffer = memory.ReadBytes(ustr.Buffer, ustr.Length);
            return Encoding.Unicode.GetString(buffer);
        }
    }
}
