class Impersonation
{
    #region WINAPI
    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool OpenProcessToken(System.IntPtr ProcessHandle, System.UInt32 DesiredAccess, out System.IntPtr TokenHandle);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    static extern System.IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint processId);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    static extern bool ImpersonateLoggedOnUser(System.IntPtr hToken);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    public extern static bool CloseHandle(System.IntPtr handle);
    #endregion
    /// <summary>
    /// Provides the called thread with the security context of the user, whose token is represented in the handle of the desired process.
    /// </summary>
    /// <param name="Name">Name of the process whose context will be used, for example, ImpersonateProcessTokenByName("winlogon")</param>
    /// <returns></returns>
    public static bool ImpersonateProcessTokenByName(string Name)
    {
        System.IntPtr tokenHandle = System.IntPtr.Zero;
        //Get process Id
        if (System.Diagnostics.Process.GetProcessesByName(Name).Length == 0) return false;
        //Try OpenProcess to get handle of process with QueryLimitedInformation rights
        System.IntPtr processHandle = OpenProcess(0x00001000, true, (uint)System.Diagnostics.Process.GetProcessesByName(Name)[0].Id);
        //Try to open process with TOKEN_DUPLICATE | TOKEN_QUERY desiredAccess rights 
        if (!OpenProcessToken(processHandle, 0x0002 | 0x0008, out tokenHandle)) return false;
        //Try to impersonate user from process token
        if (!ImpersonateLoggedOnUser(tokenHandle)) return false;
        //Close handle
        CloseHandle(tokenHandle);
        return true;
    }
}
