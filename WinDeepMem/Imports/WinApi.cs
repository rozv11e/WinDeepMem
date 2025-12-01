using System.Runtime.InteropServices;
using System.Text;

namespace WinDeepMem.Imports
{
    public unsafe class WinApi
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        public enum ProcessCreationFlag
        {
            CREATE_DEFAULT_ERROR_MODE = 0x04000000
        }

        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            ProcessCreationFlag dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("ntdll.dll")]
        public static extern int NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        out uint OldProtect
    );

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAcess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProc, IntPtr address, void* lpBuffer, uint тSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr address, [In][Out] byte[] buffer, uint size, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr dwAddress, int nSize, MemoryFreeType dwFreeType);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetModuleBaseName(
        IntPtr hProcess,
        IntPtr hModule,
        StringBuilder lpBaseName,
        uint nSize);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", EntryPoint = "GetProcAddress")]
        public static extern IntPtr GetProcAddressOrdinal(IntPtr hModule, IntPtr ordinal);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        public static uint PROCESS_CREATE_THREAD = 0x0002;
        public static uint PROCESS_QUERY_INFORMATION = 0x0400;
        public static uint PROCESS_VM_OPERATION = 0x0008;
        public static uint PROCESS_VM_WRITE = 0x0020;
        public static uint MEM_COMMIT = 0x1000;
        public static uint PAGE_READWRITE = 0x04;
        public static uint INFINITE = 0xFFFFFFFF;

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [Flags]
        public enum MemoryAllocationType
        {
            MEM_COMMIT = 0x1000,
            MEM_RESERVE = 0x2000,
            MEM_RESET = 0x80000,
            MEM_TOP_DOWN = 0x100000
        }

        [Flags]
        public enum MemoryProtectionType
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
        }

        public enum MemoryFreeType
        {
            MEM_RELEASE = 0x8000
        }

        [Flags]
        public enum ThreadAccess : uint
        {
            TERMINATE = 0x0001,
            SUSPEND_RESUME = 0x0002,
            GET_CONTEXT = 0x0008,
            SET_CONTEXT = 0x0010,
            SET_INFORMATION = 0x0020,
            QUERY_INFORMATION = 0x0040,
            SET_THREAD_TOKEN = 0x0080,
            IMPERSONATE = 0x0100,
            DIRECT_IMPERSONATION = 0x0200,
            THREAD_ALL_ACCESS = 0x1F03FF
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);


        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwThreadId);

        [DllImport("ntdll.dll")]
        public static extern int NtSuspendThread(IntPtr threadHandle, out uint previousSuspendCount);

        [DllImport("ntdll.dll")]
        public static extern int NtResumeThread(IntPtr threadHandle, out uint previousSuspendCount);

        public static uint THREAD_SUSPEND_RESUME = 0x0002;
        public static uint THREAD_GET_CONTEXT = 0x0008;
        public static uint THREAD_SET_CONTEXT = 0x0010;


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessId);

        public static uint TH32CS_SNAPHEAPLIST = 0x00000001; // Снимок heap-ов процесса
        public static uint TH32CS_SNAPPROCESS = 0x00000002; // Снимок процессов
        public static uint TH32CS_SNAPTHREAD = 0x00000004; // Снимок потоков
        public static uint TH32CS_SNAPMODULE = 0x00000008; // Снимок модулей
        public static uint TH32CS_SNAPMODULE32 = 0x00000010; // 32-bit модули
        public static uint TH32CS_SNAPALL =
            TH32CS_SNAPHEAPLIST |
            TH32CS_SNAPPROCESS |
            TH32CS_SNAPTHREAD |
            TH32CS_SNAPMODULE;   // Все основные типы снимков

        public static uint TH32CS_INHERIT = 0x80000000; // Наследование снимка

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [StructLayout(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        // Thread context

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public uint ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;

            public ulong Rip;
        }

        public const uint CONTEXT_CONTROL = 0x00100001;   // RIP/RSP/RBP
        public const uint CONTEXT_INTEGER = 0x00100002;   // RAX/RBX/etc
        public const uint CONTEXT_SEGMENTS = 0x00000004;

        public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        public static uint THREAD_QUERY_INFORMATION = 0x0040;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetThreadPriority(IntPtr hThread);


    }
}
