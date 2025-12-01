using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using static WinDeepMem.Imports.WinApi;
using static WinDeepMem.Imports.NativeAPI;

namespace WinDeepMem
{
    public unsafe class Memory
    {
        public readonly Process _process;
        public Memory(Process process)
        {
            this._process = process;
        }

        public IntPtr GetModuleBase(string module)
        {
            foreach (ProcessModule item in _process.Modules)
            {
                if (item.ModuleName == module)
                {
                    return item.BaseAddress; 
                }
            }
            return IntPtr.Zero;
        }

        public string ReadString(IntPtr address, int maxLength = 256)
        {
            byte[] buffer = ReadBytes(address, (uint)maxLength);
            if (buffer == null) return null;

            int stringLength = Array.IndexOf(buffer, (byte)0);
            if (stringLength < 0) stringLength = buffer.Length;

            return Encoding.ASCII.GetString(buffer, 0, stringLength);

        }

        public string ReadUnicodeString(IntPtr address, int maxLength = 256)
        {
            byte[] buffer = ReadBytes(address, (uint)(maxLength * 2)); // 2 байта на символ
            if (buffer == null) return null;

            int stringLength = 0;
            while (stringLength + 1 < buffer.Length)
            {
                if (buffer[stringLength] == 0 && buffer[stringLength + 1] == 0)
                    break;
                stringLength += 2;
            }

            return Encoding.Unicode.GetString(buffer, 0, stringLength);
        }

        public float ReadFloat(IntPtr address)
        {
            Read<float>(address, out var value);
            return value;
        }

        public uint ReadUInt32(IntPtr address)
        {
            Read<uint>(address, out var value);
            return value;
        }

        public ulong ReadUInt64(IntPtr address)
        {
            Read<ulong>(address, out var value);
            return value;
        }

        public int ReadInt32(IntPtr address)
        {
            Read<int>(address, out var value);
            return value;
        }

        public long ReadInt64(IntPtr address)
        {
            Read<long>(address, out var value);
            return value;
        }

        public ulong ReadULong(IntPtr address)
        {
            Read<ulong>(address, out var value);
            return value;
        }

        public long ReadLong(IntPtr address)
        {
            Read<long>(address, out var value);
            return value;
        }

        public ushort ReadUShort(nint address)
        {
            Read<ushort>(address, out var value);
            return value;
        }

        public Vector3 ReadVec3(IntPtr MemoryAddress)
        {
            float x = ReadFloat(MemoryAddress);
            float y = ReadFloat(MemoryAddress + 4);
            float z = ReadFloat(MemoryAddress + 8);

            return new Vector3(x, y, z);
        }

        public byte[] ReadBytes(IntPtr address, uint length)
        {
            byte[] buffer = new byte[length];

            fixed (byte* pBuffer = buffer)
            {
                if (ReadProcessMemory(_process.Handle, address, pBuffer, length, out _))
                {
                    return buffer;
                }
            }

            return null;
        }
        public float[] ReadMatrix(IntPtr address)
        {
            byte[] array = ReadBytes(address, 64);
            float[] array2 = new float[array.Length];
            array2[0] = BitConverter.ToSingle(array, 0);
            array2[1] = BitConverter.ToSingle(array, 4);
            array2[2] = BitConverter.ToSingle(array, 8);
            array2[3] = BitConverter.ToSingle(array, 12);
            array2[4] = BitConverter.ToSingle(array, 16);
            array2[5] = BitConverter.ToSingle(array, 20);
            array2[6] = BitConverter.ToSingle(array, 24);
            array2[7] = BitConverter.ToSingle(array, 28);
            array2[8] = BitConverter.ToSingle(array, 32);
            array2[9] = BitConverter.ToSingle(array, 36);
            array2[10] = BitConverter.ToSingle(array, 40);
            array2[11] = BitConverter.ToSingle(array, 44);
            array2[12] = BitConverter.ToSingle(array, 48);
            array2[13] = BitConverter.ToSingle(array, 52);
            array2[14] = BitConverter.ToSingle(array, 56);
            array2[15] = BitConverter.ToSingle(array, 60);
            return array2;
        }

        //public IntPtr[] ReadArray<T>(IntPtr address, uint count)
        //{
        //    byte[] buffer = new byte[count * Marshal.SizeOf(typeof(T))];

        //    var pArray = ReadProcessMemory(address, (uint)buffer.Length);

        //    IntPtr[] intptrArray = new IntPtr[pArray.Length / IntPtr.Size];

        //    for (int i = 0; i < intptrArray.Length; i++)
        //    {
        //        intptrArray[i] = (IntPtr)BitConverter.ToInt64(pArray, i * IntPtr.Size);
        //    }

        //    return intptrArray;
        //}

        public byte ReadByte(IntPtr address)
        {
            Read<byte>(address, out var value);
            return value;
        }

        public IntPtr ReadPointer(IntPtr address)
        {
            Read<IntPtr>(address, out var value);
            return value;
        }

        public T ReadStruct<T>(IntPtr address) where T : unmanaged
        {
            Read<T>(address, out var value);
            return value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe bool Read<T>(IntPtr MemoryAddress, out T value) where T : unmanaged
        {
            int size = sizeof(T);

            fixed (byte* pBuffer = new byte[size])
            {
                if (ReadProcessMemory(_process.Handle, MemoryAddress, pBuffer, (uint)size, out var _))
                {
                    value = *(T*)pBuffer;
                    return true;
                }
            }

            value = default;
            return false;
        }

        public bool Write<T>(IntPtr address, T value) where T : unmanaged
        {
            uint size = (uint)sizeof(T);
            byte[] buffer = new byte[size];

            fixed (byte* pBuffer = buffer)
            {
                *(T*)pBuffer = value;
            }

            return WriteProcessMemory(_process.Handle, address, buffer, size, out _);
        }

        public bool WriteFloat(IntPtr address, float value)
        {
            return WriteBytes(address, BitConverter.GetBytes(value));
        }

        public bool WriteBytes(IntPtr address, byte[] newbytes)
        {
            return WriteProcessMemory(_process.Handle, address, newbytes, (uint)newbytes.Length, out var _);
        }

        public bool ZeroMemory(IntPtr address, int size)
        {
            byte[] zeros = new byte[size];
            return WriteBytes(address, zeros);
        }

        public bool PatchMemory<T>(IntPtr address, T data) where T : unmanaged
        {
            if (address == IntPtr.Zero)
                return false;
            IntPtr size = (IntPtr)sizeof(T);

            uint oldProtect;

            var status = NtProtectVirtualMemory(_process.Handle, ref address, ref size, (uint)MemoryProtectionType.PAGE_READWRITE, out oldProtect);
            if (status == 0)
            {
                Write<T>(address, data);
                NtProtectVirtualMemory(_process.Handle, ref address, ref size, oldProtect, out _);
                return true;
            }

            return false;
        }

        // TODO: Nt + Check XMemory
        public bool AllocateMemory(uint size, IntPtr address)
        {
            var res = VirtualAllocEx(_process.Handle,
                address, size,
                (uint)MemoryAllocationType.MEM_COMMIT | (uint)MemoryAllocationType.MEM_RESERVE,
                (uint)MemoryProtectionType.PAGE_EXECUTE_READWRITE);

            return res != IntPtr.Zero;
        }

        public IntPtr AllocateMemory(uint size)
        {
            return VirtualAllocEx(_process.Handle,
                IntPtr.Zero, size,
                (uint)MemoryAllocationType.MEM_COMMIT | (uint)MemoryAllocationType.MEM_RESERVE,
            (uint)MemoryProtectionType.PAGE_EXECUTE_READWRITE);
        }

        public bool FreeMemory(IntPtr address)
        {
            return VirtualFreeEx(_process.Handle, address, 0, MemoryFreeType.MEM_RELEASE);
        }

        private const int FASM_MEMORY_SIZE = 8192;
        private const int FASM_PASSES = 100;

        // lock needs to be static as FASM isn't thread safe
        private static readonly object fasmLock = new object();

        /// <summary>
        /// !!!Make sure you have FASM.dll
        /// </summary>
        /// <param name="asm"></param>
        /// <param name="address"></param>
        /// <param name="patchMemProtection"></param>
        /// <returns></returns>
        public bool InjectAsm(IEnumerable<string> asm, IntPtr address, bool patchMemProtection = false) // TODO: Add patchMemProtection
        {
            lock (fasmLock)
            {
                fixed (byte* pBytes = stackalloc byte[FASM_MEMORY_SIZE]) // Выделяем память на стеке и фиксим от сборщика
                {
                    string source = "use32\norg 0x" + address.ToString("X08") + "\n" + string.Join("\n", asm); // корректируем под FASM
                    //string source = $"use32\r\norg 0x{address.ToString("X08")}\r\nret";
                    //Console.WriteLine("source:" + source);

                    if (FasmAssemble(source, pBytes, FASM_MEMORY_SIZE, FASM_PASSES, IntPtr.Zero) == 0) // Переводим строку в асм инструкции в байтах
                    {
                        FasmStateOk fasmState = *(FasmStateOk*)pBytes; // читаем из указателя байты и приводим к структуре FasmStateOk
                        // Создаем буфер для записи в память асм стаба
                        var len = (int)fasmState.OutputLength;
                        byte[] bytesToWrite = new byte[len];
                        Marshal.Copy(fasmState.OutputData, bytesToWrite, 0, len); // Копируем байты из fasmState в наш буфер для записи через wpm

                        if (patchMemProtection)
                        {
                            uint oldProtect = 0;
                            IntPtr size = (IntPtr)len;

                            NtProtectVirtualMemory(_process.Handle, ref address, ref size, PAGE_EXECUTE_READWRITE, out oldProtect);
                            var status = WriteProcessMemory(_process.Handle, address, bytesToWrite, (uint)len, out _);
                            NtProtectVirtualMemory(_process.Handle, ref address, ref size, oldProtect, out _);

                            return status;
                        }

                        return WriteProcessMemory(_process.Handle, address, bytesToWrite, (uint)len, out _);
                    }
                    else
                        return false;
                }
            }
        }

    }
}
