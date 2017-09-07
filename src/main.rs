
// https://crates.io/crates/errloc_macros
macro_rules! errloc {
    () => {
        concat!(file!(), ':', line!())
    }
}

fn errloc_msg<'a>(e: &'a std::boxed::Box<std::any::Any + std::marker::Send + 'static>) -> &'a str {
    match e.downcast_ref::<&str>() {
        Some(st) => st,
        None => {
            match e.downcast_ref::<std::string::String>() {
                Some(stw) => stw.as_str(),
                None => "()",
            }
        },
    }
}

// https://crates.io/crates/scopeguard
pub struct ScopeGuard<T, F> where F: FnMut(&mut T) {
    __dropfn: F,
    __value: T
}

impl<T, F> ScopeGuard<T, F> where F: FnMut(&mut T) {
    pub fn new(v: T, dropfn: F) -> ScopeGuard<T, F> {
        ScopeGuard {
            __value: v,
            __dropfn: dropfn
        }
    }
}

impl<T, F> Drop for ScopeGuard<T, F> where F: FnMut(&mut T) {
    fn drop(&mut self) {
        (self.__dropfn)(&mut self.__value)
    }
}

macro_rules! defer {
    ($e:expr) => {
        let _deferred = ScopeGuard::new((), |_| $e);
    }
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct STARTUPINFOEXW {
    StartupInfo: STARTUPINFOW,
    lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST
}

#[cfg(windows)]
#[repr(C, packed)]
#[allow(non_snake_case)]
pub struct TASKDIALOGCONFIG {
    cbSize: UINT,
    hwndParent: HWND,
    hInstance: HINSTANCE,
    dwFlags: u32,
    dwCommonButtons: TASKDIALOG_COMMON_BUTTON_FLAGS,
    pszWindowTitle: PCWSTR,
    pszMainIcon: PCWSTR,
    pszMainInstruction: PCWSTR,
    pszContent: PCWSTR,
    cButtons: UINT,
    pButtons: *const TASKDIALOG_BUTTON,
    nDefaultButton: std::os::raw::c_int,
    cRadioButtons: UINT,
    pRadioButtons: *const TASKDIALOG_BUTTON,
    nDefaultRadioButton: std::os::raw::c_int,
    pszVerificationText: PCWSTR,
    pszExpandedInformation: PCWSTR,
    pszExpandedControlText: PCWSTR,
    pszCollapsedControlText: PCWSTR,
    pszFooterIcon: PCWSTR,
    pszFooter: PCWSTR,
    pfCallback: extern "system" fn(hwnd: HWND, msg: UINT, wParam: WPARAM, lParam: LPARAM, lpRefData: LONG_PTR) -> HRESULT,
    lpCallbackData: LONG_PTR,
    cxWidth: UINT,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct TASKDIALOG_BUTTON {
    pub nButtonID: std::os::raw::c_int,
    pub pszButtonText: PCWSTR,
}

#[cfg(windows)]
#[repr(u32)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
enum TASKDIALOG_FLAGS {
    TDF_ENABLE_HYPERLINKS = 0x0001,
    TDF_USE_HICON_MAIN = 0x0002,
    TDF_USE_HICON_FOOTER = 0x0004,
    TDF_ALLOW_DIALOG_CANCELLATION = 0x0008,
    TDF_USE_COMMAND_LINKS = 0x0010,
    TDF_USE_COMMAND_LINKS_NO_ICON = 0x0020,
    TDF_EXPAND_FOOTER_AREA = 0x0040,
    TDF_EXPANDED_BY_DEFAULT = 0x0080,
    TDF_VERIFICATION_FLAG_CHECKED = 0x0100,
    TDF_SHOW_PROGRESS_BAR = 0x0200,
    TDF_SHOW_MARQUEE_PROGRESS_BAR = 0x0400,
    TDF_CALLBACK_TIMER = 0x0800,
    TDF_POSITION_RELATIVE_TO_WINDOW = 0x1000,
    TDF_RTL_LAYOUT = 0x2000,
    TDF_NO_DEFAULT_RADIO_BUTTON = 0x4000,
    TDF_CAN_BE_MINIMIZED = 0x8000,
    TDF_NO_SET_FOREGROUND = 0x00010000,
    TDF_SIZE_TO_CONTENT = 0x01000000,
}

#[cfg(windows)]
#[repr(u32)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
enum TASKDIALOG_COMMON_BUTTON_FLAGS {
    TDCBF_OK_BUTTON = 0x0001,
    TDCBF_YES_BUTTON = 0x0002,
    TDCBF_NO_BUTTON = 0x0004,
    TDCBF_CANCEL_BUTTON = 0x0008,
    TDCBF_RETRY_BUTTON = 0x0010,
    TDCBF_CLOSE_BUTTON = 0x0020,
}

#[cfg(windows)]
#[repr(u32)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
enum KNOWN_FOLDER_FLAG {
    KF_FLAG_DEFAULT = 0x00000000,
    KF_FLAG_NO_APPCONTAINER_REDIRECTION = 0x00010000,
    KF_FLAG_CREATE = 0x00008000,
    KF_FLAG_DONT_VERIFY = 0x00004000,
    KF_FLAG_DONT_UNEXPAND = 0x00002000,
    KF_FLAG_NO_ALIAS = 0x00001000,
    KF_FLAG_INIT = 0x00000800,
    KF_FLAG_DEFAULT_PATH = 0x00000400,
    KF_FLAG_NOT_PARENT_RELATIVE = 0x00000200,
    KF_FLAG_SIMPLE_IDLIST = 0x00000100,
    KF_FLAG_ALIAS_ONLY = 0x80000000u32,
}

#[cfg(windows)]
#[repr(u32)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
enum TASKDIALOG_NOTIFICATIONS {
    TDN_CREATED = 0,
    TDN_NAVIGATED = 1,
    TDN_BUTTON_CLICKED = 2,
    TDN_HYPERLINK_CLICKED = 3,
    TDN_TIMER = 4,
    TDN_DESTROYED = 5,
    TDN_RADIO_BUTTON_CLICKED = 6,
    TDN_DIALOG_CONSTRUCTED = 7,
    TDN_VERIFICATION_CLICKED = 8,
    TDN_HELP = 9,
    TDN_EXPANDO_BUTTON_CLICKED = 10,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct GUID {
    pub Data1: std::os::raw::c_ulong,
    pub Data2: std::os::raw::c_ushort,
    pub Data3: std::os::raw::c_ushort,
    pub Data4: [std::os::raw::c_uchar; 8],
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

#[cfg(windows)]
#[allow(non_camel_case_types)]
type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;

#[cfg(windows)]
type KNOWNFOLDERID = GUID;

#[cfg(windows)]
type REFKNOWNFOLDERID = *const KNOWNFOLDERID;

#[cfg(windows)]
type WORD = std::os::raw::c_ushort;

#[cfg(windows)]
type DWORD = std::os::raw::c_ulong;

#[cfg(windows)]
type LPDWORD = *mut DWORD;

#[cfg(windows)]
type HANDLE = *mut std::os::raw::c_void;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type wchar_t = std::os::raw::c_ushort;

#[cfg(windows)]
type WCHAR = wchar_t;

#[cfg(windows)]
type PWSTR = *mut WCHAR;

#[cfg(windows)]
type HRESULT = std::os::raw::c_long;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type size_t = usize;

#[cfg(windows)]
type BYTE = std::os::raw::c_uchar;

#[cfg(windows)]
type LPBYTE = *mut BYTE;

#[cfg(windows)]
type LPVOID = *mut std::os::raw::c_void;

#[cfg(windows)]
type LPCVOID = *const std::os::raw::c_void;

#[cfg(windows)]
type UINT = std::os::raw::c_uint;

#[cfg(windows)]
type CHAR = std::os::raw::c_char;

#[cfg(windows)]
type LPCCH = *const CHAR;

#[cfg(windows)]
type LPSTR = *mut CHAR;

#[cfg(windows)]
type LPCWCH = *const WCHAR;

#[cfg(windows)]
type LPWSTR = *mut WCHAR;

#[cfg(windows)]
type LPCWSTR = *const WCHAR;

#[cfg(windows)]
type PCWSTR = *const WCHAR;

#[cfg(windows)]
type BOOL = std::os::raw::c_int;

#[cfg(windows)]
type LPBOOL = *mut BOOL;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type va_list = *mut std::os::raw::c_char;

#[cfg(windows)]
type HLOCAL = HANDLE;

#[cfg(windows)]
type HINSTANCE = HANDLE;

#[cfg(windows)]
type HMODULE = HINSTANCE;

#[cfg(windows)]
type HWND = HANDLE;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type ULONG_PTR = u64;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type SIZE_T = ULONG_PTR;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type PSIZE_T = *mut ULONG_PTR;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type DWORD_PTR = ULONG_PTR;

#[cfg(windows)]
type PVOID = *mut std::os::raw::c_void;

#[cfg(windows)]
type LONG = std::os::raw::c_long;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type UINT_PTR = u64;

#[cfg(windows)]
type WPARAM = UINT_PTR;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type LONG_PTR = i64;

#[cfg(windows)]
type LPARAM = LONG_PTR;

#[cfg(windows)]
type LANGID = WORD;

#[cfg(windows)]
const CP_UTF8: DWORD = 65001;

#[cfg(windows)]
const FORMAT_MESSAGE_ALLOCATE_BUFFER: DWORD = 0x00000100;

#[cfg(windows)]
const FORMAT_MESSAGE_FROM_SYSTEM: DWORD = 0x00001000;

#[cfg(windows)]
const FORMAT_MESSAGE_IGNORE_INSERTS: DWORD = 0x00000200;

#[cfg(windows)]
const LANG_NEUTRAL: WORD = 0x00;

#[cfg(windows)]
const SUBLANG_DEFAULT: WORD = 0x01;

#[cfg(windows)]
const MAX_PATH: usize = 260;

#[cfg(windows)]
const S_OK: HRESULT = 0;

#[cfg(windows)]
const ERROR_ALREADY_EXISTS: DWORD = 183;

#[cfg(windows)]
const TRUE: BOOL = 1;

#[cfg(windows)]
const FILE_WRITE_DATA: DWORD = 0x0002;

#[cfg(windows)]
const FILE_APPEND_DATA: DWORD = 0x0004;

#[cfg(windows)]
const FILE_SHARE_WRITE: DWORD = 0x00000002;

#[cfg(windows)]
const FILE_SHARE_READ: DWORD = 0x00000001;

#[cfg(windows)]
const CREATE_ALWAYS: DWORD = 2;

#[cfg(windows)]
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;

#[cfg(windows)]
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

#[cfg(windows)]
const ERROR_INSUFFICIENT_BUFFER: DWORD = 122;

#[cfg(windows)]
const STARTF_USESTDHANDLES: DWORD = 0x00000100;

#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: DWORD = 0x00000200;

#[cfg(windows)]
const DETACHED_PROCESS: DWORD = 0x00000008;

#[cfg(windows)]
const CREATE_UNICODE_ENVIRONMENT: DWORD = 0x00000400;

#[cfg(windows)]
const EXTENDED_STARTUPINFO_PRESENT: DWORD = 0x00080000;

#[cfg(windows)]
const SW_SHOW: std::os::raw::c_int = 5;

#[cfg(windows)]
#[repr(C)]
#[allow(non_camel_case_types)]
struct PROC_THREAD_ATTRIBUTE_LIST {
    pub dummy: *mut std::os::raw::c_void,
}

#[cfg(windows)]
#[allow(non_camel_case_types)]
type LPPROC_THREAD_ATTRIBUTE_LIST = *mut PROC_THREAD_ATTRIBUTE_LIST;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type PPROC_THREAD_ATTRIBUTE_LIST = *mut PROC_THREAD_ATTRIBUTE_LIST;

#[cfg(windows)]
#[allow(non_camel_case_types)]
type ACCESS_MASK = DWORD;

#[cfg(windows)]
type REGSAM = ACCESS_MASK;

#[cfg(windows)]
pub const READ_CONTROL: DWORD = 0x00020000;

#[cfg(windows)]
const STANDARD_RIGHTS_READ: DWORD = READ_CONTROL;

#[cfg(windows)]
const KEY_QUERY_VALUE: REGSAM = 0x0001;

#[cfg(windows)]
const KEY_ENUMERATE_SUB_KEYS: REGSAM = 0x0008;

#[cfg(windows)]
const KEY_NOTIFY: REGSAM = 0x0010;

#[cfg(windows)]
const SYNCHRONIZE: DWORD = 0x00100000;

#[cfg(windows)]
const REG_SZ: DWORD = 1;

#[cfg(windows)]
const KEY_READ: REGSAM = (
    STANDARD_RIGHTS_READ |
        KEY_QUERY_VALUE |
        KEY_ENUMERATE_SUB_KEYS |
        KEY_NOTIFY
) & (!SYNCHRONIZE);

#[cfg(windows)]
type HKEY = *mut std::os::raw::c_void;

#[cfg(windows)]
pub const HKEY_LOCAL_MACHINE: HKEY = 0x80000002 as HKEY;

#[cfg(windows)]
type PHKEY = *mut HKEY;


#[cfg(windows)]
#[allow(non_snake_case)]
fn MAKELANGID(p: WORD, s: WORD) -> LANGID {
    (s << 10 | p)
}

#[cfg(windows)]
const ERROR_SUCCESS: DWORD = 0;

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lpReserved: LPWSTR,
    pub lpDesktop: LPWSTR,
    pub lpTitle: LPWSTR,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: WORD,
    pub cbReserved2: WORD,
    pub lpReserved2: LPBYTE,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

#[cfg(windows)]
type LPSTARTUPINFOW = *mut STARTUPINFOW;

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
}

#[cfg(windows)]
#[allow(non_camel_case_types)]
type LPPROCESS_INFORMATION = *mut PROCESS_INFORMATION;

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

#[cfg(windows)]
type PFILETIME = *mut FILETIME;

// https://github.com/retep998/winapi-rs/blob/2e79232883a819806ef2ae161bad5583783aabd9/src/um/winuser.rs#L135
#[cfg(windows)]
#[allow(non_snake_case)]
fn MAKEINTRESOURCEW(i: WORD) -> LPWSTR {
    i as ULONG_PTR as LPWSTR
}


#[cfg(windows)]
extern "system" {

    fn MultiByteToWideChar(
        CodePage: UINT,
        dwFlags: DWORD,
        lpMultiByteStr: LPCCH,
        cbMultiByte: std::os::raw::c_int,
        lpWideCharStr: LPWSTR,
        cchWideChar: std::os::raw::c_int
    ) -> std::os::raw::c_int;

    fn WideCharToMultiByte(
        CodePage: UINT,
        dwFlags: DWORD,
        lpWideCharStr: LPCWCH,
        cchWideChar: std::os::raw::c_int,
        lpMultiByteStr: LPSTR,
        cbMultiByte: std::os::raw::c_int,
        lpDefaultChar: LPCCH,
        lpUsedDefaultChar: LPBOOL
    ) -> std::os::raw::c_int;

    fn GetLastError(
    ) -> DWORD;

    fn FormatMessageW(
        dwFlags: DWORD,
        lpSource: LPCVOID,
        dwMessageId: DWORD,
        dwLanguageId: DWORD,
        lpBuffer: LPWSTR,
        nSize: DWORD,
        Arguments: *mut va_list
    ) -> DWORD;

    fn LocalFree(
        hMem: HLOCAL
    ) -> HLOCAL;

    fn GetModuleFileNameW(
        hModule: HMODULE,
        lpFilename: LPWSTR,
        nSize: DWORD
    ) -> DWORD;

    fn CreateDirectoryW(
        lpPathName: LPCWSTR,
        lpSecurityAttributes: LPSECURITY_ATTRIBUTES
    ) -> BOOL;

    fn CreateFileW(
        lpFileName: LPCWSTR,
        dwDesiredAccess: DWORD,
        dwShareMode: DWORD,
        lpSecurityAttributes: LPSECURITY_ATTRIBUTES,
        dwCreationDisposition: DWORD,
        dwFlagsAndAttributes: DWORD,
        hTemplateFile: HANDLE
    ) -> HANDLE;

    fn CloseHandle(
        hObject: HANDLE
    ) -> BOOL;

    fn InitializeProcThreadAttributeList(
        lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
        dwAttributeCount: DWORD,
        dwFlags: DWORD,
        lpSize: PSIZE_T
    ) -> BOOL;

    fn DeleteProcThreadAttributeList(
        lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST
    );

    fn UpdateProcThreadAttribute(
        lpAttributeList: LPPROC_THREAD_ATTRIBUTE_LIST,
        dwFlags: DWORD,
        Attribute: DWORD_PTR,
        lpValue: PVOID,
        cbSize: SIZE_T,
        lpPreviousValue: PVOID,
        lpReturnSize: PSIZE_T
    ) -> BOOL;

    fn CreateProcessW(
        lpApplicationName: LPCWSTR,
        lpCommandLine: LPWSTR,
        lpProcessAttributes: LPSECURITY_ATTRIBUTES,
        lpThreadAttributes: LPSECURITY_ATTRIBUTES,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: LPVOID,
        lpCurrentDirectory: LPCWSTR,
        lpStartupInfo: LPSTARTUPINFOW,
        lpProcessInformation: LPPROCESS_INFORMATION
    ) -> BOOL;

    fn GetModuleHandleW(
        lpModuleName: LPCWSTR
    ) -> HMODULE;

    fn GetProcessId(
        Process: HANDLE
    ) -> DWORD;

    fn ShellExecuteW(
        hwnd: HWND,
        lpOperation: LPCWSTR,
        lpFile: LPCWSTR,
        lpParameters: LPCWSTR,
        lpDirectory: LPCWSTR,
        nShowCmd: std::os::raw::c_int,
    ) -> HINSTANCE;
    
    fn TaskDialogIndirect(
        pTaskConfig: *const TASKDIALOGCONFIG,
        pnButton: *mut std::os::raw::c_int,
        pnRadioButton: *mut std::os::raw::c_int,
        pfVerificationFlagChecked: *mut BOOL,
    ) -> HRESULT;

    fn TaskDialog(
        hwndOwner: HWND,
        hInstance: HINSTANCE,
        pszWindowTitle: PCWSTR,
        pszMainInstruction: PCWSTR,
        pszContent: PCWSTR,
        dwCommonButtons: TASKDIALOG_COMMON_BUTTON_FLAGS,
        pszIcon: PCWSTR,
        pnButton: *mut std::os::raw::c_int
    ) -> HRESULT;

    fn SHGetKnownFolderPath(
        rfid: REFKNOWNFOLDERID,
        dwFlags: DWORD,
        hToken: HANDLE,
        pszPath: *mut PWSTR
    ) -> HRESULT;

    fn RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: LPCWSTR,
        ulOptions: DWORD,
        samDesired: REGSAM,
        phkResult: PHKEY
    ) -> LONG;

    fn RegCloseKey(
        hKey: HKEY
    ) -> LONG;

    fn RegQueryInfoKeyW(
        hKey: HKEY,
        lpClass: LPWSTR,
        lpcClass: LPDWORD,
        lpReserved: LPDWORD,
        lpcSubKeys: LPDWORD,
        lpcMaxSubKeyLen: LPDWORD,
        lpcMaxClassLen: LPDWORD,
        lpcValues: LPDWORD,
        lpcMaxValueNameLen: LPDWORD,
        lpcMaxValueLen: LPDWORD,
        lpcbSecurityDescriptor: LPDWORD,
        lpftLastWriteTime: PFILETIME
    ) -> LONG;

    fn RegEnumKeyExW(
        hKey: HKEY,
        dwIndex: DWORD,
        lpName: LPWSTR,
        lpcName: LPDWORD,
        lpReserved: LPDWORD,
        lpClass: LPWSTR,
        lpcClass: LPDWORD,
        lpftLastWriteTime: PFILETIME
    ) -> LONG;

    fn RegQueryValueExW(
        hKey: HKEY,
        lpValueName: LPCWSTR,
        lpReserved: LPDWORD,
        lpType: LPDWORD,
        lpData: LPBYTE,
        lpcbData: LPDWORD
    ) -> LONG;

    fn wcslen(
        buf: *const wchar_t
    ) -> size_t;

    fn malloc(
        size: size_t
    ) -> *mut std::os::raw::c_void;

    fn free(
        p: *mut std::os::raw::c_void
    );

    fn CoTaskMemFree(
        pv: LPVOID
    );
}

#[cfg(windows)]
fn widen(st: &str) -> std::vec::Vec<u16> {
    unsafe {
        let size_needed = MultiByteToWideChar(
                CP_UTF8,
                0,
                st.as_ptr() as *mut i8,
                st.len() as std::os::raw::c_int,
                std::ptr::null_mut::<u16>(),
                0);
        if 0 == size_needed {
            panic!(format!("Error on string widen calculation, \
                string: [{}], error: [{}]", st, errcode_to_string(GetLastError())));
        }
        let mut res: std::vec::Vec<u16> = std::vec::Vec::new();
        res.resize((size_needed + 1) as usize, 0);
        let chars_copied = MultiByteToWideChar(
                CP_UTF8,
                0,
                st.as_ptr() as *mut i8,
                st.len() as std::os::raw::c_int,
                res.as_mut_ptr(),
                size_needed);
        if chars_copied != size_needed {
            panic!(format!("Error on string widen execution, \
                string: [{}], error: [{}]", st, errcode_to_string(GetLastError())));
        }
        res.resize(size_needed as usize, 0);
        res
    }
}

#[cfg(windows)]
fn narrow(wst: &[u16]) -> std::string::String {
    unsafe {
        let size_needed = WideCharToMultiByte(
                CP_UTF8,
                0,
                wst.as_ptr(),
                wst.len() as std::os::raw::c_int,
                std::ptr::null_mut::<i8>(),
                0,
                std::ptr::null::<std::os::raw::c_char>(),
                std::ptr::null_mut::<std::os::raw::c_int>());
        if 0 == size_needed {
            panic!(format!("Error on string narrow calculation, \
                string length: [{}], error code: [{}]", wst.len(), GetLastError()));
        }
        let mut vec: std::vec::Vec<u8> = std::vec::Vec::new();
        vec.resize(size_needed as usize, 0);
        let bytes_copied = WideCharToMultiByte(
                CP_UTF8,
                0,
                wst.as_ptr(),
                wst.len() as std::os::raw::c_int,
                vec.as_mut_ptr() as *mut i8,
                size_needed,
                std::ptr::null::<std::os::raw::c_char>(),
                std::ptr::null_mut::<std::os::raw::c_int>());
        if bytes_copied != size_needed {
            panic!(format!("Error on string narrow execution, \
                string length: [{}], error code: [{}]", vec.len(), GetLastError()));
        }
        std::string::String::from_utf8(vec).expect(errloc!())
    }
}

#[cfg(windows)]
fn errcode_to_string(code: std::os::raw::c_ulong) -> std::string::String {
    if 0 == code {
        return std::string::String::new();
    }
    unsafe {
        let mut buf: *mut u16 = std::ptr::null_mut::<u16>();
        let size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                std::ptr::null::<std::os::raw::c_void>(),
                code,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as DWORD,
                std::mem::transmute::<*mut *mut u16, *mut u16>(&mut buf),
                0,
                std::ptr::null_mut::<va_list>());
        if 0 == size {
            return format!("Cannot format code: [{}] \
                 into message, error code: [{}]", code, GetLastError());
        }
        defer!({
            LocalFree(buf as HLOCAL);
        });
        if size <= 2 {
            return format!("code: [{}], message: []", code);
        }
        std::panic::catch_unwind(|| {
            let slice = std::slice::from_raw_parts(buf, (size - 2) as usize);
            let msg = narrow(slice);
            format!("code: [{}], message: [{}]", code, msg)
        }).unwrap_or_else(|e| {
            format!("Cannot format code: [{}] \
                 into message, narrow error: [{}]", code, errloc_msg(&e))
        })
    }
}

#[cfg(windows)]
fn process_dir() -> std::string::String {
    let mut vec: std::vec::Vec<u16> = std::vec::Vec::new();
    vec.resize(MAX_PATH, 0);
    unsafe {
        let success = GetModuleFileNameW(
                std::ptr::null_mut::<std::os::raw::c_void>() as HMODULE,
                vec.as_mut_ptr(),
                vec.len() as DWORD);
        if 0 == success {
            panic!(format!("Error getting current executable dir, \
                 error: [{}]", errcode_to_string(GetLastError())));
        }
        let path_badslash = narrow(&vec);
        let path = path_badslash.replace("\\", "/");
        match path.rfind('/') {
            None => path,
            Some(sid) => {
                let slice = &path[0..sid + 1];
                slice.to_string()
            }
        }
    }
}

#[cfg(windows)]
fn userdata_dir() -> std::string::String {
    unsafe {
        let mut wbuf: *mut u16 = std::ptr::null_mut::<u16>();
        let dt4: [std::os::raw::c_uchar; 8] = [ 0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91 ];
        let id = KNOWNFOLDERID { Data1: 0xF1B32785, Data2: 0x6FBA, Data3: 0x4FCF, Data4: dt4 };
        let err = SHGetKnownFolderPath(
                &id,
                KNOWN_FOLDER_FLAG::KF_FLAG_CREATE as u32,
                std::ptr::null_mut::<std::os::raw::c_void>(),
                &mut wbuf);
        if S_OK != err || std::ptr::null_mut::<u16>() == wbuf {
            panic!("Error getting userdata dir");
        }
        defer!({
            CoTaskMemFree(wbuf as *mut std::os::raw::c_void);
        });
        let slice = std::slice::from_raw_parts(wbuf, wcslen(wbuf));
        let path_badslash = narrow(slice);
        let mut path = path_badslash.replace("\\", "/");
        path.push('/');
        path
    }
}

#[cfg(windows)]
fn create_dir(dirpath: &str) -> () {
    let wpath = widen(dirpath);
    unsafe {
        let err = CreateDirectoryW(
                wpath.as_ptr(),
                std::ptr::null_mut::<SECURITY_ATTRIBUTES>());
        if 0 == err && ERROR_ALREADY_EXISTS != GetLastError() {
            panic!(format!("Error getting creating dir, \
                path: [{}], error: [{}]", dirpath, errcode_to_string(GetLastError())));
        }
    }
}

#[cfg(windows)]
fn start_process(executable: &str, args: &[std::string::String], out: &str) -> u32 {
    // open stdout file
    let wout = widen(out);
    unsafe {
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
            lpSecurityDescriptor: std::ptr::null_mut::<std::os::raw::c_void>(),
            bInheritHandle: TRUE
        };
        let mut out_handle = CreateFileW(
                wout.as_ptr(),
                FILE_WRITE_DATA | FILE_APPEND_DATA,
                FILE_SHARE_WRITE | FILE_SHARE_READ,
                &mut sa,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut::<std::os::raw::c_void>());
        if INVALID_HANDLE_VALUE == out_handle {
            panic!(format!("Error opening log file descriptor, \
                    message: [{}], specified out path: [{}]", errcode_to_string(GetLastError()), out));
        }
        let out_handle_copy = out_handle;
        defer!({
            CloseHandle(out_handle_copy);
        });

        // prepare list of handles to inherit
        // see: https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873
        let mut tasize: SIZE_T = 0;
        let err_tasize = InitializeProcThreadAttributeList(
                std::ptr::null_mut::<PROC_THREAD_ATTRIBUTE_LIST>(),
                1,
                0,
                &mut tasize);

        if 0 != err_tasize || GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            panic!(format!("Error preparing attrlist, \
                    message: [{}]", errcode_to_string(GetLastError())));
        }
        let talist = malloc(tasize as usize) as *mut PROC_THREAD_ATTRIBUTE_LIST;
        if std::ptr::null_mut::<PROC_THREAD_ATTRIBUTE_LIST>() == talist {
            panic!(format!("Error preparing attrlist, \
                    message: [{}]", errcode_to_string(GetLastError())));
        }
        defer!({
            free(talist as *mut std::os::raw::c_void);
        });
        let err_ta = InitializeProcThreadAttributeList(
                talist,
                1,
                0,
                &mut tasize);
        if 0 == err_ta {
            panic!(format!("Error initializing attrlist, \
                    message: [{}]", errcode_to_string(GetLastError())));
        }
        defer!({
            DeleteProcThreadAttributeList(talist);
        });
        let hptr: *mut *mut std::os::raw::c_void = &mut out_handle;
        let err_taset = UpdateProcThreadAttribute(
            talist,
            0,
            (2 & 0x0000FFFF) | 0x00020000, // PROC_THREAD_ATTRIBUTE_HANDLE_LIST
            hptr as *mut std::os::raw::c_void,
            std::mem::size_of::<*mut std::os::raw::c_void>() as SIZE_T,
            std::ptr::null_mut::<std::os::raw::c_void>(),
            std::ptr::null_mut::<SIZE_T>());
        if 0 == err_taset {
            panic!(format!("Error filling attrlist, \
                    message: [{}]", errcode_to_string(GetLastError())));
        }

        // prepare process
        let mut si = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as DWORD,
                    lpReserved: std::ptr::null_mut::<u16>(),
                    lpDesktop: std::ptr::null_mut::<u16>(),
                    lpTitle: std::ptr::null_mut::<u16>(),
                    dwX: 0,
                    dwY: 0,
                    dwXSize: 0,
                    dwYSize: 0,
                    dwXCountChars: 0,
                    dwYCountChars: 0,
                    dwFillAttribute: 0,
                    dwFlags: STARTF_USESTDHANDLES,
                    wShowWindow: 0,
                    cbReserved2: 0,
                    lpReserved2: std::ptr::null_mut::<BYTE>(),
                    hStdInput: std::ptr::null_mut::<std::os::raw::c_void>(),
                    hStdError: out_handle,
                    hStdOutput: out_handle },
            lpAttributeList: talist };

        let mut pi = PROCESS_INFORMATION {
                hProcess: std::ptr::null_mut::<std::os::raw::c_void>(),
                hThread: std::ptr::null_mut::<std::os::raw::c_void>(),
                dwProcessId: 0,
                dwThreadId: 0,
        };

        let mut cmd_string = format!("\"{}\"", executable).to_string();
        for arg in args {
            cmd_string.push_str(" ");
            cmd_string.push_str(arg);
        }

        // run process
        println!("{}", cmd_string.as_str());
        let mut wcmd = widen(cmd_string.as_str());
        let ret = CreateProcessW(
                std::ptr::null_mut::<u16>(),
                wcmd.as_mut_ptr(),
                std::ptr::null_mut::<SECURITY_ATTRIBUTES>(),
                std::ptr::null_mut::<SECURITY_ATTRIBUTES>(),
                TRUE,
                CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS |
                        CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null_mut::<std::os::raw::c_void>(),
                std::ptr::null_mut::<u16>(),
                &mut si.StartupInfo,
                &mut pi);
        if 0 == ret {
            panic!(format!("Process create error: [{}], \
                command line: [{}]", errcode_to_string(GetLastError()), cmd_string));
        }
        CloseHandle(pi.hThread);
        let res = GetProcessId(pi.hProcess);
        CloseHandle(pi.hProcess);
        println!("{}", res);
        res
    }
}

#[cfg(windows)]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn error_dialog_cb(_: HWND, uNotification: UINT, _: WPARAM,
        lParam: LPARAM, _: LONG_PTR) -> HRESULT {
    if TASKDIALOG_NOTIFICATIONS::TDN_HYPERLINK_CLICKED as u32 != uNotification {
        return S_OK;
    }
    unsafe {
        let res = ShellExecuteW(
                std::ptr::null_mut::<std::os::raw::c_void>(),
                std::ptr::null_mut::<u16>(),
                std::mem::transmute::<LPARAM, LPCWSTR> (lParam),
                std::ptr::null_mut::<u16>(),
                std::ptr::null_mut::<u16>(),
                SW_SHOW);
        let intres = res as i64;
        let success = intres > 32;
        if !success {
            let wtitle = widen("IcedTea-Web");
            let werror = widen("Error starting default web-browser");
            let wempty = widen("");
            TaskDialog(
                    std::ptr::null_mut::<std::os::raw::c_void>(),
                    GetModuleHandleW(std::ptr::null_mut::<u16>()),
                    wtitle.as_ptr(),
                    werror.as_ptr(),
                    wempty.as_ptr(),
                    TASKDIALOG_COMMON_BUTTON_FLAGS::TDCBF_CLOSE_BUTTON,
                    std::ptr::null::<u16>(), // TD_ERROR_ICON,
                    std::ptr::null_mut::<std::os::raw::c_int>());
        }
        S_OK
    }
}

#[cfg(windows)]
fn show_error_dialog(error: &str) -> () {
    let wtitle = widen("IcedTea-Web");
    let url = "http://icedtea.classpath.org/wiki/IcedTea-Web";
    let link = format!("<a href=\"{}\">{}</a>", url, url);
    let wlink = widen(link.as_str());
    let wmain = widen("IcedTea-Web was unable to start Java VM.\n\nPlease follow the link below for troubleshooting information.");
    let wexpanded = widen("Hide detailed error message");
    let wcollapsed = widen("Show detailed error message");
    let werror = widen(error);

    unsafe {
        let cf = TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            hwndParent: std::ptr::null_mut::<std::os::raw::c_void>(),
            hInstance: GetModuleHandleW(std::ptr::null_mut::<u16>()),
            dwFlags: TASKDIALOG_FLAGS::TDF_ENABLE_HYPERLINKS as u32 | TASKDIALOG_FLAGS::TDF_EXPAND_FOOTER_AREA as u32 |
                    TASKDIALOG_FLAGS::TDF_ALLOW_DIALOG_CANCELLATION as u32 | TASKDIALOG_FLAGS::TDF_SIZE_TO_CONTENT as u32,
            dwCommonButtons: TASKDIALOG_COMMON_BUTTON_FLAGS::TDCBF_CLOSE_BUTTON,
            pszWindowTitle: wtitle.as_ptr(),
            pszMainIcon: MAKEINTRESOURCEW(111),
            pszMainInstruction: wmain.as_ptr(),
            pszContent: std::ptr::null_mut::<u16>(),
            cButtons: 0,
            pButtons: std::ptr::null::<TASKDIALOG_BUTTON>(),
            nDefaultButton: 0,
            cRadioButtons: 0,
            pRadioButtons: std::ptr::null::<TASKDIALOG_BUTTON>(),
            nDefaultRadioButton: 0,
            pszVerificationText: std::ptr::null_mut::<u16>(),
            pszExpandedInformation: werror.as_ptr(),
            pszExpandedControlText: wexpanded.as_ptr(),
            pszCollapsedControlText: wcollapsed.as_ptr(),
            pszFooterIcon: MAKEINTRESOURCEW(111),
            pszFooter: wlink.as_ptr(),
            pfCallback: error_dialog_cb,
            lpCallbackData: 0,
            cxWidth: 0,
        };

        TaskDialogIndirect(
                &cf,
                std::ptr::null_mut::<std::os::raw::c_int>(),
                std::ptr::null_mut::<std::os::raw::c_int>(),
                std::ptr::null_mut::<BOOL>());
    }
}

#[cfg(windows)]
fn find_java_exe() -> std::string::String {
    let jdk_key_name = "SOFTWARE\\JavaSoft\\Java Development Kit";
    let wjdk_key_name = widen(jdk_key_name);
    let jdk_prefix = "1.8.0";
    let java_home = "JavaHome";
    let wjava_home = widen("JavaHome");
    let java_exe_postfix = "bin/java.exe";
    unsafe {
        // open root
        let mut jdk_key = std::ptr::null_mut::<std::os::raw::c_void>();
        let err_jdk = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wjdk_key_name.as_ptr(), 
                0,
                KEY_READ | KEY_ENUMERATE_SUB_KEYS,
                &mut jdk_key) as u32;
        if ERROR_SUCCESS != err_jdk {
            panic!(format!("Error opening registry key, \
                    name: [{}], message: [{}]", jdk_key_name, errcode_to_string(err_jdk)));
        }
        defer!({
            RegCloseKey(jdk_key);
        });
        // identify buffer size for children
        let mut subkeys_num: DWORD = 0;
        let mut max_subkey_len: DWORD = 0;
        let err_info = RegQueryInfoKeyW(
                jdk_key,
                std::ptr::null_mut::<u16>(),
                std::ptr::null_mut::<DWORD>(),
                std::ptr::null_mut::<DWORD>(),
                &mut subkeys_num,
                &mut max_subkey_len,
                std::ptr::null_mut::<DWORD>(),
                std::ptr::null_mut::<DWORD>(),
                std::ptr::null_mut::<DWORD>(),
                std::ptr::null_mut::<DWORD>(),
                std::ptr::null_mut::<DWORD>(),
                std::ptr::null_mut::<FILETIME>()) as u32;
        if ERROR_SUCCESS != err_info {
            panic!(format!("Error querieing registry key, \
                    name: [{}], message: [{}]", jdk_key_name, errcode_to_string(err_info)));
        }
        // collect children names
        let mut vec: std::vec::Vec<std::string::String> = std::vec::Vec::new();
        vec.reserve(subkeys_num as usize);
        max_subkey_len += 1; // NUL-terminator
        let mut subkey_buf: std::vec::Vec<u16> = std::vec::Vec::new();
        subkey_buf.resize(max_subkey_len as usize, 0);
        for i in 0..subkeys_num {
            let mut len = max_subkey_len;
            let err_enum = RegEnumKeyExW(
                    jdk_key,
                    i as DWORD,
                    subkey_buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut::<DWORD>(),
                    std::ptr::null_mut::<u16>(),
                    std::ptr::null_mut::<DWORD>(),
                    std::ptr::null_mut::<FILETIME>()) as u32;
            if ERROR_SUCCESS != err_enum {
                panic!(format!("Error enumerating registry key, \
                        name: [{}], message: [{}]", jdk_key_name, errcode_to_string(err_enum)));
            }
            let slice = std::slice::from_raw_parts(subkey_buf.as_ptr(), len as usize); 
            vec.push(narrow(slice));
        }
        // look for prefix match
        vec.sort();
        let mut versions = std::string::String::new();
        for el in vec {
            if !versions.is_empty() {
                versions.push_str(", ");
            }
            versions.push_str(el.as_str());
            if el.starts_with(jdk_prefix) {
                // found match, open it
                let subkey_name = format!("{}\\{}", jdk_key_name, el);
                let wsubkey_name = widen(subkey_name.as_str());
                let mut jdk_subkey = std::ptr::null_mut::<std::os::raw::c_void>();
                let err_jdk_subkey = RegOpenKeyExW(
                        HKEY_LOCAL_MACHINE,
                        wsubkey_name.as_ptr(), 
                        0,
                        KEY_READ,
                        &mut jdk_subkey) as u32;
                if ERROR_SUCCESS != err_jdk_subkey {
                    panic!(format!("Error opening registry key, \
                            name: [{}], message: [{}]", subkey_name, errcode_to_string(err_jdk_subkey)));
                }
                defer!({
                    RegCloseKey(jdk_subkey);
                });
                // find out value len
                let mut value_len: DWORD = 0;
                let mut value_type: DWORD = 0;
                let err_len = RegQueryValueExW(
                        jdk_subkey,
                        wjava_home.as_ptr(),
                        std::ptr::null_mut::<DWORD>(),
                        &mut value_type,
                        std::ptr::null_mut::<BYTE>(),
                        &mut value_len) as u32;
                if ERROR_SUCCESS != err_len || !(value_len > 0) || REG_SZ != value_type {
                    panic!(format!("Error opening registry value len, \
                            key: [{}], value: [{}], message: [{}]", subkey_name, java_home, errcode_to_string(err_len)));
                }
                // get value
                let mut wvalue: std::vec::Vec<u16> = std::vec::Vec::new();
                wvalue.resize((value_len as usize)/std::mem::size_of::<u16>(), 0);
                let err_val = RegQueryValueExW(
                        jdk_subkey,
                        wjava_home.as_ptr(),
                        std::ptr::null_mut::<DWORD>(),
                        std::ptr::null_mut::<DWORD>(),
                        wvalue.as_mut_ptr() as LPBYTE,
                        &mut value_len) as u32;
                if ERROR_SUCCESS != err_val {
                    panic!(format!("Error opening registry value, \
                            key: [{}], value: [{}], message: [{}]", subkey_name, java_home, errcode_to_string(err_val)));
                }
                // format and return path
                let slice = std::slice::from_raw_parts(wvalue.as_ptr(), wvalue.len() - 1 as usize); 
                let jpath_badslash = narrow(slice);
                let mut jpath = jpath_badslash.replace("\\", "/");
                if '/' as u8 != jpath.as_bytes()[jpath.len() - 1] {
                    jpath.push('/');
                }
                jpath.push_str(java_exe_postfix);
                return jpath;
            }
        }
        panic!(format!("JDK 8 runtime directory not found, please install JDK 8, available versions: [{}].", versions));
    }
}

fn main() {
    let netx_jar = "../../netx.jar";
    let xboot_prefix = "-Xbootclasspath/a:";
    let main_class = "net.sourceforge.jnlp.runtime.Boot";
    let log_dir_name = "IcedTeaWeb/";
    let log_file_name = "javaws_last_log.txt";
    std::panic::catch_unwind(|| {
        let cline: std::vec::Vec<std::string::String> = std::env::args().collect(); 
        if cline.len() < 2 {
            panic!("No arguments specified. Please specify a path to JNLP file or a 'jnlp://' URL.");
        }
        let localdir = process_dir();
        let java = find_java_exe();
        let mut args: std::vec::Vec<std::string::String> = std::vec::Vec::new();
        args.push(format!("{}{}{}", xboot_prefix, localdir, netx_jar));
        args.push(main_class.to_string());
        for (i, cl) in cline.iter().enumerate() {
            if i > 0 {
                args.push(cl.clone());
            }
        }
        let uddir = userdata_dir();
        let logdir = uddir + log_dir_name;
        create_dir(logdir.as_str());
        let logfile = format!("{}{}", logdir, log_file_name);
        start_process(java.as_str(), &args, logfile.as_str());
    }).unwrap_or_else(|e| {
        show_error_dialog(errloc_msg(&e));
    });
}

