# WinMemCore

A low-level **Windows memory and system framework** for .NET developers.  
Provides powerful tools for **memory reading/writing, process analysis, syscall invocation, IAT/TLS inspection, and assembly-level operations**.
---

## 🚀 Features

- **Memory Management**
  - Read and write process memory
  - Virtual memory operations (allocation, protection, freeing)
  - Pattern scanning and pointer resolution

- **System Structures**
  - PEB / TEB access and parsing
  - Import Address Table (IAT) and Thread Local Storage (TLS) inspection *not implemented yet*

- **Syscalls** *not implemented yet*
  - Direct system call interface
  - Dynamic syscall number resolution
  - Anti-hook bypass (Nt/Zw call integrity)

- **Low-level Utilities**
  - Inline ASM injection and code execution
  - Module enumeration and handle management
  - Remote thread creation and code mapping

---

## 📁 Project Structure

## 🧩 Requirements

- **.NET Framework 4.7.2+** or (**.NET 8.0** // in future)
- **Windows 10/11**
- Visual Studio 2022 or newer

## ⚡ Quick Example

```csharp
using Reader;

var memory = new MemoryReader(process);

int value = memory.Read<int>(0x7FFDF000);
Console.WriteLine($"Value: {value}");

process.Write(0x7FFDF000, 12345);