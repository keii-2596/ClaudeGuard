// Minimal WFP bindings. Compiled in memory by the protected PowerShell helper.
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public sealed class ClaudeGuardWfp : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct Display { public IntPtr name, description; }
    [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
    [StructLayout(LayoutKind.Sequential)] struct Value { public uint type; public ulong value; }
    [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid field; public uint match; public Value value; }
    [StructLayout(LayoutKind.Sequential)] struct Action { public uint type; public Guid key; }
    [StructLayout(LayoutKind.Sequential)] struct Filter {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob data; public Guid layer, sublayer; public Value weight;
        public uint count; public IntPtr conditions; public Action action;
        public ulong context, contextPadding; public IntPtr reserved; public ulong id; public Value effectiveWeight;
    }
    [StructLayout(LayoutKind.Sequential)] struct Sublayer {
        public Guid key; public Display display; public uint flags; public IntPtr provider;
        public Blob data; public ushort weight;
    }
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmEngineOpen0(string server, uint auth, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerAdd0(IntPtr engine, ref Sublayer sublayer, IntPtr security);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr security, out ulong id);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr engine, ref Guid key, out IntPtr filter);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);
    [DllImport("fwpuclnt.dll", CharSet=CharSet.Unicode)] static extern uint FwpmGetAppIdFromFileName0(string file, out IntPtr blob);
    [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr memory);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll")] static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandle(IntPtr file, StringBuilder path, uint length, uint flags);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public static string Canonical(string path) {
        IntPtr file=CreateFile(path,0,7,IntPtr.Zero,3,0x02000000,IntPtr.Zero);
        if(file==new IntPtr(-1)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        try {
            var result=new StringBuilder(32768);
            uint length=GetFinalPathNameByHandle(file,result,(uint)result.Capacity,0);
            if(length==0 || length>=result.Capacity) throw new InvalidOperationException("Cannot canonicalize application path");
            string value=result.ToString();
            if(value.StartsWith(@"\\?\UNC\")) value=@"\\"+value.Substring(8);
            else if(value.StartsWith(@"\\?\")) value=value.Substring(4);
            return value.ToLowerInvariant();
        } finally { CloseHandle(file); }
    }
    IntPtr engine;
    Guid sublayer;
    static readonly Guid[] layers = { new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82"), new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4") };
    static readonly Guid appId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
    static void Check(uint result) { if (result != 0) throw new InvalidOperationException("WFP 0x" + result.ToString("X8")); }
    static Guid Key(string text) { using (var hash = SHA256.Create()) { var bytes = hash.ComputeHash(Encoding.UTF8.GetBytes(text)); var key = new byte[16]; Array.Copy(bytes, key, 16); return new Guid(key); } }
    public ClaudeGuardWfp(string installation) {
        if (IntPtr.Size != 8) throw new PlatformNotSupportedException("64-bit PowerShell required");
        if (Marshal.SizeOf(typeof(Filter)) != 200 || Marshal.SizeOf(typeof(Condition)) != 40) throw new InvalidOperationException("Invalid WFP ABI layout");
        Check(FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out engine));
        sublayer = Key("ClaudeGuard/sublayer/" + installation);
        IntPtr title = Marshal.StringToHGlobalUni("ClaudeGuard " + installation);
        try {
            Sublayer sub = new Sublayer { key=sublayer, display=new Display {name=title}, flags=1, weight=0x8000 };
            uint result = FwpmSubLayerAdd0(engine, ref sub, IntPtr.Zero);
            if (result != 0x80320009) Check(result); // FWP_E_ALREADY_EXISTS
        } finally { Marshal.FreeHGlobal(title); }
    }
    Guid FilterKey(string path, Guid layer) { return Key("ClaudeGuard/filter/" + sublayer + "/" + layer + "/" + path.ToLowerInvariant()); }
    bool Exists(Guid key) { IntPtr filter; uint result=FwpmFilterGetByKey0(engine, ref key, out filter); if (result==0) { FwpmFreeMemory0(ref filter); return true; } if(result==0x80320003) return false; Check(result); return false; }
    public void SetBlocked(string[] programs, bool blocked) {
        Check(FwpmTransactionBegin0(engine, 0));
        try {
            foreach (string path in programs) foreach (Guid layer in layers) {
                Guid key=FilterKey(path, layer);
                bool exists=Exists(key);
                if (!blocked) { if(exists) Check(FwpmFilterDeleteByKey0(engine, ref key)); continue; }
                if (exists) continue;
                IntPtr blob=IntPtr.Zero, condition=IntPtr.Zero, title=IntPtr.Zero;
                try {
                    Check(FwpmGetAppIdFromFileName0(path, out blob));
                    Condition cond=new Condition { field=appId, match=0, value=new Value { type=12, value=unchecked((ulong)blob.ToInt64()) } };
                    condition=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Condition)));
                    Marshal.StructureToPtr(cond,condition,false);
                    title=Marshal.StringToHGlobalUni("ClaudeGuard outbound block");
                    Filter filter=new Filter {key=key, display=new Display {name=title}, flags=1, layer=layer, sublayer=sublayer,
                        weight=new Value {type=1,value=15}, count=1, conditions=condition, action=new Action {type=0x1001}};
                    ulong id; Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, out id));
                } finally {
                    if(blob!=IntPtr.Zero) FwpmFreeMemory0(ref blob);
                    if(condition!=IntPtr.Zero) Marshal.FreeHGlobal(condition);
                    if(title!=IntPtr.Zero) Marshal.FreeHGlobal(title);
                }
            }
            Check(FwpmTransactionCommit0(engine));
        } catch { FwpmTransactionAbort0(engine); throw; }
    }
    public void Remove(string[] programs) { SetBlocked(programs,false); Check(FwpmSubLayerDeleteByKey0(engine,ref sublayer)); }
    public void Dispose() { if(engine!=IntPtr.Zero) {FwpmEngineClose0(engine); engine=IntPtr.Zero;} }
}
