using System.Runtime.InteropServices;
using WinDeepMem.Imports.Structures;

namespace WinDeepMem.Imports
{
    public class NativeAPI
    {
        public enum THREADINFOCLASS
        {
            ThreadBasicInformation = 0, // вернет THREAD_BASIC_INFORMATION
                                        // есть и другие значения, но это самое нужное для TEB
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct THREAD_BASIC_INFORMATION
        {
            public int ExitStatus;
            public IntPtr TebBaseAddress;      // <-- то, ради чего используем
            public CLIENT_ID ClientId;
            public IntPtr AffinityMask;
            public int Priority;
            public int BasePriority;
        }

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationThread(
            IntPtr ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            out THREAD_BASIC_INFORMATION ThreadInformation,
            int ThreadInformationLength,
            out int ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref UIntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        public static uint MEM_COMMIT = 0x1000;
        public static uint MEM_RESERVE = 0x2000;
        public static uint PAGE_EXECUTE_READWRITE = 0x40;


        /// From Xmemory
        /// 
        /// <summary>
        /// FASM assembler library is used to assembly our injection stuff.
        /// </summary>
        /// <param name="szSource">Assembly instructions.</param>
        /// <param name="lpMemory">Output bytes</param>
        /// <param name="nSize">Output buffer size</param>
        /// <param name="nPassesLimit">FASM pass limit</param>
        /// <param name="hDisplayPipe">FASM display pipe</param>
        /// <returns>FASM status struct pointer</returns>
        [DllImport("FASM.dll", EntryPoint = "fasm_Assemble", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        public static extern unsafe int FasmAssemble(
            [MarshalAs(UnmanagedType.LPStr)] string szSource, // ANSI (UTF-8 не корректно через CharSet)
            byte* lpMemory,
            int nSize,
            int nPassesLimit,
            IntPtr hDisplayPipe);

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct FasmStateOk
        {
            public int Condition { get; set; }

            public uint OutputLength { get; set; }

            public IntPtr OutputData { get; set; }
        }

        [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern int EnumProcessModules(IntPtr hProcess, [Out] ulong lphModule, uint cb, out uint lpcbNeeded);
    }
}
