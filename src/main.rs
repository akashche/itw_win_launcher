

#[macro_use]
extern crate errloc_macros;
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

#[cfg(windows)]
#[repr(C)]
struct STARTUPINFOEXW {
    StartupInfo: winapi::processthreadsapi::STARTUPINFOW,
    lpAttributeList: winapi::processthreadsapi::PPROC_THREAD_ATTRIBUTE_LIST
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
                 into message, narrow error: [{}]", code, errloc_macros::msg(&e))
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
        let mut talist = libc::malloc(tasize as usize) as *mut winapi::processthreadsapi::PROC_THREAD_ATTRIBUTE_LIST;
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

extern "system" {
    pub fn ShellExecuteW(
        hwnd: winapi::windef::HWND,
        lpOperation: winapi::winnt::LPCWSTR,
        lpFile: winapi::winnt::LPCWSTR,
        lpParameters: winapi::winnt::LPCWSTR,
        lpDirectory: winapi::winnt::LPCWSTR,
        nShowCmd: std::os::raw::c_int,
    ) -> winapi::minwindef::HINSTANCE;
}

#[cfg(windows)]
#[no_mangle]
pub extern "system" fn error_dialog_cb(hwnd: winapi::windef::HWND, uNotification: winapi::minwindef::UINT, wParam: winapi::minwindef::WPARAM,
        lParam: winapi::minwindef::LPARAM, lpRefData: winapi::basetsd::LONG_PTR) -> winapi::winerror::HRESULT {
    if (winapi::commctrl::TDN_HYPERLINK_CLICKED.0 != uNotification) {
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
        if (!success) {
            let wtitle = widen("IcedTea-Web");
            let werror = widen("Error starting default web-browser");
            let wempty = widen("");
            comctl32::TaskDialog(
                    std::ptr::null_mut::<winapi::windef::HWND__>(),
                    std::ptr::null_mut::<winapi::minwindef::HINSTANCE__>(),
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
    let wmain = widen("IcedTea-Web was unable to start Java VM.\n\nPlease follow the link below for troubleshooting information.");
    let wexpanded = widen("Hide detailed error message");
    let wcollapsed = widen("Show detailed error message");
    let werror = widen(error);

    let link = format!("<a href=\"{}\">{}</a>", url, url);
    let wlink = widen(link.as_str());
    unsafe {
        let cf = winapi::commctrl::TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<winapi::commctrl::TASKDIALOGCONFIG>() as u32,
            hwndParent: std::ptr::null_mut::<winapi::windef::HWND__>(),
            hInstance: std::ptr::null_mut::<winapi::minwindef::HINSTANCE__>(),
            dwFlags: winapi::commctrl::TDF_ENABLE_HYPERLINKS | winapi::commctrl::TDF_EXPAND_FOOTER_AREA | 
                    winapi::commctrl::TDF_ALLOW_DIALOG_CANCELLATION | winapi::commctrl::TDF_SIZE_TO_CONTENT,
            dwCommonButtons: winapi::commctrl::TDCBF_CLOSE_BUTTON,
            pszWindowTitle: wtitle.as_ptr(),
            hMainIcon: std::ptr::null_mut::<winapi::windef::HICON__>(),
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
            hFooterIcon: std::ptr::null_mut::<winapi::windef::HICON__>(),
            pszFooter: wlink.as_ptr(),
            pfCallback: Some(error_dialog_cb),
            lpCallbackData: 0,
            cxWidth: 0,
        };
        let err = comctl32::TaskDialogIndirect(
                &cf,
                std::ptr::null_mut::<std::os::raw::c_int>(),
                std::ptr::null_mut::<std::os::raw::c_int>(),
                std::ptr::null_mut::<winapi::minwindef::BOOL>());
        println!("{:?}", err);
        user32::MessageBoxW(
                std::ptr::null_mut::<winapi::windef::HWND__>(),
                werror.as_ptr(),
                wtitle.as_ptr(),
                winapi::winuser::MB_OKCANCEL);
    }
}

fn main() {
    let netx_jar = "netx.jar";
    let xboot_prefix = "-Xbootclasspath/a:";
    let main_class = "net.sourceforge.jnlp.runtime.Boot";
    let log_dir_name = "IcedTeaWeb";
    let log_file_name = "javaws_last_log.txt";
    std::panic::catch_unwind(|| {
        let cline: std::vec::Vec<std::string::String> = std::env::args().collect(); 
        if 0 == cline.len() {
            panic!("No arguments specified. Please specify a path to JNLP file or a 'jnlp://' URL.");
        }
        let localdir = process_dir();
        let java = "jdk/bin/java.exe"; //itw::find_java_exe();
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
        start_process(java, &args, logfile.as_str());
    }).unwrap_or_else(|e| {
        show_error_dialog(errloc_macros::msg(&e));
    });
}

