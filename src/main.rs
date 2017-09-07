
#[macro_use]
extern crate scopeguard;

#[cfg(windows)]
extern crate winapi;
#[cfg(windows)]
extern crate user32;
#[cfg(windows)]
extern crate advapi32;
#[cfg(windows)]
extern crate kernel32;
#[cfg(windows)]
extern crate ole32;
#[cfg(windows)]
extern crate shell32;
#[cfg(windows)]
extern crate comctl32;
#[cfg(windows)]
extern crate libc;

// errloc
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


#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
pub struct STARTUPINFOEXW {
    StartupInfo: winapi::processthreadsapi::STARTUPINFOW,
    lpAttributeList: winapi::processthreadsapi::PPROC_THREAD_ATTRIBUTE_LIST
}

#[cfg(windows)]
#[repr(C, packed)]
#[allow(non_snake_case)]
pub struct TASKDIALOGCONFIG {
    cbSize: winapi::minwindef::UINT,
    hwndParent: winapi::windef::HWND,
    hInstance: winapi::minwindef::HINSTANCE,
    dwFlags: winapi::commctrl::TASKDIALOG_FLAGS,
    dwCommonButtons: winapi::commctrl::TASKDIALOG_COMMON_BUTTON_FLAGS,
    pszWindowTitle: winapi::winnt::PCWSTR,
    pszMainIcon: winapi::winnt::PCWSTR,
    pszMainInstruction: winapi::winnt::PCWSTR,
    pszContent: winapi::winnt::PCWSTR,
    cButtons: winapi::minwindef::UINT,
    pButtons: *const winapi::commctrl::TASKDIALOG_BUTTON,
    nDefaultButton: std::os::raw::c_int,
    cRadioButtons: winapi::minwindef::UINT,
    pRadioButtons: *const winapi::commctrl::TASKDIALOG_BUTTON,
    nDefaultRadioButton: std::os::raw::c_int,
    pszVerificationText: winapi::winnt::PCWSTR,
    pszExpandedInformation: winapi::winnt::PCWSTR,
    pszExpandedControlText: winapi::winnt::PCWSTR,
    pszCollapsedControlText: winapi::winnt::PCWSTR,
    pszFooterIcon: winapi::winnt::PCWSTR,
    pszFooter: winapi::winnt::PCWSTR,
    pfCallback: extern "system" fn(hwnd: winapi::windef::HWND, msg: winapi::minwindef::UINT, wParam: winapi::minwindef::WPARAM, lParam: winapi::minwindef::LPARAM, lpRefData: winapi::basetsd::LONG_PTR) -> winapi::winerror::HRESULT,
    lpCallbackData: winapi::basetsd::LONG_PTR,
    cxWidth: winapi::minwindef::UINT,
}

// https://github.com/retep998/winapi-rs/blob/2e79232883a819806ef2ae161bad5583783aabd9/src/um/winuser.rs#L135
#[cfg(windows)]
#[allow(non_snake_case)]
fn MAKEINTRESOURCEW(i: winapi::minwindef::WORD) -> winapi::winnt::LPWSTR {
    i as winapi::basetsd::ULONG_PTR as winapi::winnt::LPWSTR
}

#[cfg(windows)]
extern "system" {
    pub fn ShellExecuteW(
        hwnd: winapi::windef::HWND,
        lpOperation: winapi::winnt::LPCWSTR,
        lpFile: winapi::winnt::LPCWSTR,
        lpParameters: winapi::winnt::LPCWSTR,
        lpDirectory: winapi::winnt::LPCWSTR,
        nShowCmd: std::os::raw::c_int,
    ) -> winapi::minwindef::HINSTANCE;
    
    pub fn TaskDialogIndirect(
        pTaskConfig: *const TASKDIALOGCONFIG,
        pnButton: *mut std::os::raw::c_int,
        pnRadioButton: *mut std::os::raw::c_int,
        pfVerificationFlagChecked: *mut winapi::minwindef::BOOL,
    ) -> winapi::winerror::HRESULT;

}

#[cfg(windows)]
fn widen(st: &str) -> std::vec::Vec<u16> {
    unsafe {
        let size_needed = kernel32::MultiByteToWideChar(
                winapi::winnls::CP_UTF8,
                0,
                st.as_ptr() as *mut i8,
                st.len() as std::os::raw::c_int,
                std::ptr::null_mut::<u16>(),
                0);
        if 0 == size_needed {
            panic!(format!("Error on string widen calculation, \
                string: [{}], error: [{}]", st, errcode_to_string(kernel32::GetLastError())));
        }
        let mut res: std::vec::Vec<u16> = std::vec::Vec::new();
        res.resize((size_needed + 1) as usize, 0);
        let chars_copied = kernel32::MultiByteToWideChar(
                winapi::winnls::CP_UTF8,
                0,
                st.as_ptr() as *mut i8,
                st.len() as std::os::raw::c_int,
                res.as_mut_ptr(),
                size_needed);
        if chars_copied != size_needed {
            panic!(format!("Error on string widen execution, \
                string: [{}], error: [{}]", st, errcode_to_string(kernel32::GetLastError())));
        }
        res.resize(size_needed as usize, 0);
        res
    }
}

#[cfg(windows)]
fn narrow(wst: &[u16]) -> std::string::String {
    unsafe {
        let size_needed = kernel32::WideCharToMultiByte(
                winapi::winnls::CP_UTF8,
                0,
                wst.as_ptr(),
                wst.len() as std::os::raw::c_int,
                std::ptr::null_mut::<i8>(),
                0,
                std::ptr::null::<std::os::raw::c_char>(),
                std::ptr::null_mut::<std::os::raw::c_int>());
        if 0 == size_needed {
            panic!(format!("Error on string narrow calculation, \
                string length: [{}], error code: [{}]", wst.len(), kernel32::GetLastError()));
        }
        let mut vec: std::vec::Vec<u8> = std::vec::Vec::new();
        vec.resize(size_needed as usize, 0);
        let bytes_copied = kernel32::WideCharToMultiByte(
                winapi::winnls::CP_UTF8,
                0,
                wst.as_ptr(),
                wst.len() as std::os::raw::c_int,
                vec.as_mut_ptr() as *mut i8,
                size_needed,
                std::ptr::null::<std::os::raw::c_char>(),
                std::ptr::null_mut::<std::os::raw::c_int>());
        if bytes_copied != size_needed {
            panic!(format!("Error on string narrow execution, \
                string length: [{}], error code: [{}]", vec.len(), kernel32::GetLastError()));
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
        let size = kernel32::FormatMessageW(
                winapi::winbase::FORMAT_MESSAGE_ALLOCATE_BUFFER | 
                        winapi::winbase::FORMAT_MESSAGE_FROM_SYSTEM | 
                        winapi::winbase::FORMAT_MESSAGE_IGNORE_INSERTS,
                std::ptr::null::<std::os::raw::c_void>(),
                code,
                winapi::winnt::MAKELANGID(winapi::winnt::LANG_NEUTRAL, winapi::winnt::SUBLANG_DEFAULT) as winapi::minwindef::DWORD, 
                std::mem::transmute::<*mut *mut u16, *mut u16>(&mut buf),
                0,
                std::ptr::null_mut::<winapi::vadefs::va_list>());
        if 0 == size {
            return format!("Cannot format code: [{}] \
                 into message, error code: [{}]", code, kernel32::GetLastError());
        }
        defer!({
            kernel32::LocalFree(buf as winapi::minwindef::HLOCAL);
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
    vec.resize(winapi::minwindef::MAX_PATH, 0);
    unsafe {
        let success = kernel32::GetModuleFileNameW(
                std::ptr::null_mut::<std::os::raw::c_void>() as winapi::minwindef::HMODULE,
                vec.as_mut_ptr(),
                vec.len() as winapi::minwindef::DWORD);
        if 0 == success {
            panic!(format!("Error getting current executable dir, \
                 error: [{}]", errcode_to_string(kernel32::GetLastError())));
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
        let id = winapi::shtypes::KNOWNFOLDERID { Data1: 0xF1B32785, Data2: 0x6FBA, Data3: 0x4FCF, Data4: dt4 };
        let err = shell32::SHGetKnownFolderPath(
                &id,
                winapi::shlobj::KF_FLAG_CREATE.0,
                std::ptr::null_mut::<std::os::raw::c_void>(),
                &mut wbuf);
        if winapi::winerror::S_OK != err || std::ptr::null_mut::<u16>() == wbuf {
            panic!("Error getting userdata dir");
        }
        defer!({
            ole32::CoTaskMemFree(wbuf as *mut std::os::raw::c_void);
        });
        let slice = std::slice::from_raw_parts(wbuf, libc::wcslen(wbuf)); 
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
        let err = kernel32::CreateDirectoryW(
                wpath.as_ptr(),
                std::ptr::null_mut::<winapi::minwinbase::SECURITY_ATTRIBUTES>());
        if 0 == err && winapi::winerror::ERROR_ALREADY_EXISTS != kernel32::GetLastError() {
            panic!(format!("Error getting creating dir, \
                path: [{}], error: [{}]", dirpath, errcode_to_string(kernel32::GetLastError())));
        }
    }
}

#[cfg(windows)]
fn start_process(executable: &str, args: &[std::string::String], out: &str) -> u32 {
    // open stdout file
    let wout = widen(out);
    unsafe {
        let mut sa = winapi::minwinbase::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<winapi::minwinbase::SECURITY_ATTRIBUTES>() as winapi::minwindef::DWORD,
            lpSecurityDescriptor: std::ptr::null_mut::<std::os::raw::c_void>(),
            bInheritHandle: winapi::minwindef::TRUE 
        };
        let mut out_handle = kernel32::CreateFileW(
                wout.as_ptr(), 
                winapi::winnt::FILE_WRITE_DATA | winapi::winnt::FILE_APPEND_DATA,
                winapi::winnt::FILE_SHARE_WRITE | winapi::winnt::FILE_SHARE_READ,
                &mut sa,
                winapi::fileapi::CREATE_ALWAYS,
                winapi::winnt::FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut::<std::os::raw::c_void>());
        if winapi::shlobj::INVALID_HANDLE_VALUE == out_handle {
            panic!(format!("Error opening log file descriptor, \
                    message: [{}], specified out path: [{}]", errcode_to_string(kernel32::GetLastError()), out));
        }
        let out_handle_copy = out_handle;
        defer!({
            kernel32::CloseHandle(out_handle_copy);
        });

        // prepare list of handles to inherit
        // see: https://blogs.msdn.microsoft.com/oldnewthing/20111216-00/?p=8873
        let mut tasize: winapi::basetsd::SIZE_T = 0;
        let err_tasize = kernel32::InitializeProcThreadAttributeList(
                std::ptr::null_mut::<winapi::processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST>(),
                1,
                0,
                &mut tasize);
        
        if 0 != err_tasize || kernel32::GetLastError() != winapi::winerror::ERROR_INSUFFICIENT_BUFFER {
            panic!(format!("Error preparing attrlist, \
                    message: [{}]", errcode_to_string(kernel32::GetLastError())));
        }
        let talist = libc::malloc(tasize as usize) as *mut winapi::processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST;
        if std::ptr::null_mut::<winapi::processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST>() == talist {
            panic!(format!("Error preparing attrlist, \
                    message: [{}]", errcode_to_string(kernel32::GetLastError())));
        }
        defer!({
            libc::free(talist as *mut libc::c_void);
        });
        let err_ta = kernel32::InitializeProcThreadAttributeList(
                talist,
                1,
                0,
                &mut tasize);
        if 0 == err_ta {
            panic!(format!("Error initializing attrlist, \
                    message: [{}]", errcode_to_string(kernel32::GetLastError())));
        }
        defer!({
            kernel32::DeleteProcThreadAttributeList(talist);
        });
        let hptr: *mut *mut std::os::raw::c_void = &mut out_handle;
        let err_taset = kernel32::UpdateProcThreadAttribute(
            talist,
            0,
            (2 & 0x0000FFFF) | 0x00020000, // PROC_THREAD_ATTRIBUTE_HANDLE_LIST
            hptr as *mut std::os::raw::c_void,
            std::mem::size_of::<*mut std::os::raw::c_void>() as winapi::basetsd::SIZE_T,
            std::ptr::null_mut::<std::os::raw::c_void>(),
            std::ptr::null_mut::<winapi::basetsd::SIZE_T>()); 
        if 0 == err_taset {
            panic!(format!("Error filling attrlist, \
                    message: [{}]", errcode_to_string(kernel32::GetLastError())));
        }

        // prepare process
        let mut si = STARTUPINFOEXW {
            StartupInfo: winapi::processthreadsapi::STARTUPINFOW {
                    cb: std::mem::size_of::<STARTUPINFOEXW>() as winapi::minwindef::DWORD,
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
                    dwFlags: winapi::winbase::STARTF_USESTDHANDLES,
                    wShowWindow: 0,
                    cbReserved2: 0,
                    lpReserved2: std::ptr::null_mut::<winapi::minwindef::BYTE>(),
                    hStdInput: std::ptr::null_mut::<std::os::raw::c_void>(),
                    hStdError: out_handle,
                    hStdOutput: out_handle }, 
            lpAttributeList: talist };

        let mut pi = winapi::processthreadsapi::PROCESS_INFORMATION {
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
        let ret = kernel32::CreateProcessW(
                std::ptr::null_mut::<u16>(), 
                wcmd.as_mut_ptr(), 
                std::ptr::null_mut::<winapi::minwinbase::SECURITY_ATTRIBUTES>(), 
                std::ptr::null_mut::<winapi::minwinbase::SECURITY_ATTRIBUTES>(), 
                winapi::minwindef::TRUE,
                winapi::winbase::CREATE_NEW_PROCESS_GROUP | winapi::winbase::DETACHED_PROCESS |
                        winapi::winbase::CREATE_UNICODE_ENVIRONMENT | winapi::winbase::EXTENDED_STARTUPINFO_PRESENT, 
                std::ptr::null_mut::<std::os::raw::c_void>(), 
                std::ptr::null_mut::<u16>(), 
                &mut si.StartupInfo, 
                &mut pi);
        if 0 == ret {
            panic!(format!("Process create error: [{}], \
                command line: [{}]", errcode_to_string(kernel32::GetLastError()), cmd_string));
        }
        kernel32::CloseHandle(pi.hThread);
        let res = kernel32::GetProcessId(pi.hProcess);
        kernel32::CloseHandle(pi.hProcess);
        println!("{}", res);
        res
    }
}

#[cfg(windows)]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn error_dialog_cb(_: winapi::windef::HWND, uNotification: winapi::minwindef::UINT, _: winapi::minwindef::WPARAM,
        lParam: winapi::minwindef::LPARAM, _: winapi::basetsd::LONG_PTR) -> winapi::winerror::HRESULT {
    if winapi::commctrl::TDN_HYPERLINK_CLICKED.0 != uNotification {
        return winapi::winerror::S_OK;
    }
    unsafe {
        let res = ShellExecuteW(
                std::ptr::null_mut::<winapi::windef::HWND__>(),
                std::ptr::null_mut::<u16>(),
                std::mem::transmute::<winapi::minwindef::LPARAM, winapi::winnt::LPCWSTR> (lParam),
                std::ptr::null_mut::<u16>(),
                std::ptr::null_mut::<u16>(),
                winapi::winuser::SW_SHOW);
        let intres = res as i64;
        let success = intres > 32;
        if !success {
            let wtitle = widen("IcedTea-Web");
            let werror = widen("Error starting default web-browser");
            let wempty = widen("");
            comctl32::TaskDialog(
                    std::ptr::null_mut::<winapi::windef::HWND__>(),
                    kernel32::GetModuleHandleW(std::ptr::null_mut::<u16>()),
                    wtitle.as_ptr(),
                    werror.as_ptr(),
                    wempty.as_ptr(),
                    winapi::commctrl::TDCBF_CLOSE_BUTTON,
                    std::ptr::null::<u16>(), // TD_ERROR_ICON,
                    std::ptr::null_mut::<std::os::raw::c_int>());
        }
        winapi::winerror::S_OK
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
            hwndParent: std::ptr::null_mut::<winapi::windef::HWND__>(),
            hInstance: kernel32::GetModuleHandleW(std::ptr::null_mut::<u16>()),
            dwFlags: winapi::commctrl::TDF_ENABLE_HYPERLINKS | winapi::commctrl::TDF_EXPAND_FOOTER_AREA | 
                    winapi::commctrl::TDF_ALLOW_DIALOG_CANCELLATION | winapi::commctrl::TDF_SIZE_TO_CONTENT,
            dwCommonButtons: winapi::commctrl::TDCBF_CLOSE_BUTTON,
            pszWindowTitle: wtitle.as_ptr(),
            pszMainIcon: MAKEINTRESOURCEW(111),
            pszMainInstruction: wmain.as_ptr(),
            pszContent: std::ptr::null_mut::<u16>(),
            cButtons: 0,
            pButtons: std::ptr::null::<winapi::commctrl::TASKDIALOG_BUTTON>(),
            nDefaultButton: 0,
            cRadioButtons: 0,
            pRadioButtons: std::ptr::null::<winapi::commctrl::TASKDIALOG_BUTTON>(),
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
                std::ptr::null_mut::<winapi::minwindef::BOOL>());
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
        let mut jdk_key = std::ptr::null_mut::<winapi::minwindef::HKEY__>();
        let err_jdk = advapi32::RegOpenKeyExW(
                winapi::HKEY_LOCAL_MACHINE,
                wjdk_key_name.as_ptr(), 
                0,
                winapi::winnt::KEY_READ | winapi::winnt::KEY_ENUMERATE_SUB_KEYS,
                &mut jdk_key) as u32;
        if winapi::winerror::ERROR_SUCCESS != err_jdk {
            panic!(format!("Error opening registry key, \
                    name: [{}], message: [{}]", jdk_key_name, errcode_to_string(err_jdk)));
        }
        defer!({
            advapi32::RegCloseKey(jdk_key);
        });
        // identify buffer size for children
        let mut subkeys_num: winapi::minwindef::DWORD = 0;
        let mut max_subkey_len: winapi::minwindef::DWORD = 0;
        let err_info = advapi32::RegQueryInfoKeyW(
                jdk_key,
                std::ptr::null_mut::<u16>(),
                std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                &mut subkeys_num,
                &mut max_subkey_len,
                std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                std::ptr::null_mut::<winapi::minwindef::FILETIME>()) as u32;
        if winapi::winerror::ERROR_SUCCESS != err_info {
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
            let err_enum = advapi32::RegEnumKeyExW(
                    jdk_key,
                    i as winapi::minwindef::DWORD,
                    subkey_buf.as_mut_ptr(),
                    &mut len,
                    std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                    std::ptr::null_mut::<u16>(),
                    std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                    std::ptr::null_mut::<winapi::minwindef::FILETIME>()) as u32;
            if winapi::winerror::ERROR_SUCCESS != err_enum {
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
                let mut jdk_subkey = std::ptr::null_mut::<winapi::minwindef::HKEY__>();
                let err_jdk_subkey = advapi32::RegOpenKeyExW(
                        winapi::HKEY_LOCAL_MACHINE,
                        wsubkey_name.as_ptr(), 
                        0,
                        winapi::winnt::KEY_READ,
                        &mut jdk_subkey) as u32;
                if winapi::winerror::ERROR_SUCCESS != err_jdk_subkey {
                    panic!(format!("Error opening registry key, \
                            name: [{}], message: [{}]", subkey_name, errcode_to_string(err_jdk_subkey)));
                }
                defer!({
                    advapi32::RegCloseKey(jdk_subkey);
                });
                // find out value len
                let mut value_len: winapi::minwindef::DWORD = 0;
                let mut value_type: winapi::minwindef::DWORD = 0;
                let err_len = advapi32::RegQueryValueExW(
                        jdk_subkey,
                        wjava_home.as_ptr(),
                        std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                        &mut value_type,
                        std::ptr::null_mut::<winapi::minwindef::BYTE>(),
                        &mut value_len) as u32;
                if winapi::winerror::ERROR_SUCCESS != err_len || !(value_len > 0) || winapi::winnt::REG_SZ != value_type {
                    panic!(format!("Error opening registry value len, \
                            key: [{}], value: [{}], message: [{}]", subkey_name, java_home, errcode_to_string(err_len)));
                }
                // get value
                let mut wvalue: std::vec::Vec<u16> = std::vec::Vec::new();
                wvalue.resize((value_len as usize)/std::mem::size_of::<u16>(), 0);
                let err_val = advapi32::RegQueryValueExW(
                        jdk_subkey,
                        wjava_home.as_ptr(),
                        std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                        std::ptr::null_mut::<winapi::minwindef::DWORD>(),
                        wvalue.as_mut_ptr() as winapi::minwindef::LPBYTE,
                        &mut value_len) as u32;
                if winapi::winerror::ERROR_SUCCESS != err_val {
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

