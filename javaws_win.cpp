

#include <algorithm>
#include <iostream>
#include <exception>
#include <memory>
#include <string>
#include <vector>

#define UNICODE
#define _UNICODE
#include <windows.h>

#ifdef __MINGW32__
#define JAVAWS_NOEXCEPT noexcept
#else // MSVC
#define JAVAWS_NOEXCEPT
#endif

std::string errcode_to_string(unsigned long code) JAVAWS_NOEXCEPT;

class javaws_exception : public std::exception {
protected:
    std::string message{};

public:
    javaws_exception(const std::string& message) :
    message(message) { }

    virtual const char* what() const JAVAWS_NOEXCEPT {
        return message.c_str();
    }
};

class LocalFreeDeleter {
public:
    void operator()(wchar_t* buf) {
       LocalFree(buf);
    }
};

std::vector<wchar_t> widen(const std::string& st) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, st.c_str(), static_cast<int>(st.length()), nullptr, 0);
    if (0 == size_needed) throw javaws_exception(std::string("Error on string widen calculation,") +
            " string: [" + st + "], error: [" + errcode_to_string(GetLastError()) + "]");
    std::vector<wchar_t> vec{};
    vec.resize(size_needed + 1);
    int chars_copied = MultiByteToWideChar(CP_UTF8, 0, st.c_str(), static_cast<int>(st.size()), vec.data(), size_needed);
    if (chars_copied != size_needed) throw javaws_exception(std::string("Error on string widen execution,") +
            " string: [" + st + "], error: [" + errcode_to_string(GetLastError()) + "]");
    return vec;
}

std::string narrow(const wchar_t* wstring, size_t length) {
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstring, static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (0 == size_needed) throw javaws_exception(std::string("Error on string narrow calculation,") +
            " string length: [" + std::to_string(length) + "], error code: [" + std::to_string(GetLastError()) + "]");
    std::vector<char> vec{};
    vec.resize(size_needed);
    int bytes_copied = WideCharToMultiByte(CP_UTF8, 0, wstring, static_cast<int>(length), vec.data(), size_needed, nullptr, nullptr);
    if (bytes_copied != size_needed) throw javaws_exception(std::string("Error on string narrow execution,") +
            " string length: [" + std::to_string(vec.size()) + "], error code: [" + std::to_string(GetLastError()) + "]");
    std::string st{vec.begin(), vec.end()};
    return st;
}

std::string errcode_to_string(unsigned long code) JAVAWS_NOEXCEPT {
    if (0 == code) return std::string{};
    wchar_t* buf_p = nullptr;
    size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            reinterpret_cast<wchar_t*>(&buf_p), 0, nullptr);
    if (0 == size) {
        return "Cannot format code: [" + std::to_string(code) + "]" +
            " into message, error code: [" + std::to_string(GetLastError()) + "]";
    }
    auto buf = std::unique_ptr<wchar_t, LocalFreeDeleter>(buf_p, LocalFreeDeleter{});
    if (size <= 2) {
        return "code: [" + std::to_string(code) + "], message: []";
    }
    try {
        std::string msg = narrow(buf.get(), size - 2);
        return "code: [" + std::to_string(code) + "], message: [" + msg + "]";
    } catch(const std::exception& e) {
        return "Cannot format code: [" + std::to_string(code) + "]" +
            " into message, narrow error: [" + e.what() + "]";
    }
}

std::string process_dir() {
    std::vector<wchar_t> vec{};
    vec.resize(MAX_PATH);
    auto success = GetModuleFileName(nullptr, vec.data(), static_cast<DWORD>(vec.size()));
    if (0 == success) throw javaws_exception(std::string("Error getting current executable dir,") +
            " error: [" + errcode_to_string(GetLastError()) + "]");
    auto path = narrow(vec.data(), vec.size());
    std::replace(path.begin(), path.end(), '\\', '/');
    auto sid = path.rfind('/');
    return std::string::npos != sid ? path.substr(0, sid + 1) : path;
}

int start_process(const std::string& executable, const std::vector<std::string>& args) {
    // prepare process
    STARTUPINFOW si;
    ::memset(std::addressof(si), 0, sizeof(STARTUPINFO));
    si.cb = sizeof(si);
    // si.dwFlags = STARTF_USESTDHANDLES;
    // si.hStdInput = nullptr;
    // si.hStdError = out_handle;
    // si.hStdOutput = out_handle;
    PROCESS_INFORMATION pi;
    memset(std::addressof(pi), 0, sizeof(PROCESS_INFORMATION));
    std::string cmd_string = "\"" + executable + "\"";
    for (const std::string& arg : args) {
        cmd_string += " ";
        cmd_string += arg;
    }
    // run process
    auto ret = ::CreateProcessW(
            nullptr, 
            std::addressof(widen(cmd_string).front()), 
            nullptr, 
            nullptr, 
            true, 
            // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, 
            CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT, 
            nullptr, 
            nullptr, 
            std::addressof(si), 
            std::addressof(pi));
    if (0 == ret) throw javaws_exception("Process create error: [" + errcode_to_string(::GetLastError()) + "]," +
            " command line: [" + cmd_string + "]");
    ::CloseHandle(pi.hThread);
    int res = ::GetProcessId(pi.hProcess);
    ::CloseHandle(pi.hProcess);
    return res;
}

// c:/apps/jdk/jre/bin/java -splash:C:/apps/cygwin/usr/local/share/icedtea-web/javaws_splash.png '-Xbootclasspath/a:C:/apps/cygwin/usr/local/share/icedtea-web/netx.jar;C:/apps/cygwin/usr/local/share/icedtea-web/plugin.jar;C:/apps/cygwin/usr/local/share/icedtea-web/jsobject.jar:c:/apps/jdk/jre/lib/ext/nashorn.jar' -Xms8m -classpath c:/apps/jdk/jre/lib/rt.jar:c:/apps/jdk/jre/lib/jfxrt.jar -Dicedtea-web.bin.name=javaws -Dicedtea-web.bin.location=C:/apps/cygwin/usr/local/bin/javaws net.sourceforge.jnlp.runtime.Boot AccessibleScrollDemo.jnlp
int main() {
    try {
        // relative paths, should be taken from input/env/config
        std::string java_home = "jdk/";
        std::string netx_jar = "netx.jar";
        std::string jnlp_file = "test.jnlp";
        auto localdir = process_dir();
        std::string java = localdir + java_home + "/bin/java.exe";
        std::vector<std::string> args;
        args.emplace_back("-Xbootclasspath/a:" + localdir + netx_jar);
        args.emplace_back("net.sourceforge.jnlp.runtime.Boot");
        args.emplace_back(localdir + jnlp_file);
        std::cout << java << std::endl;
        for (auto& st : args) {
            std::cout << st << std::endl;
        }
        start_process(java, args);
        return 0;
    } catch (const std::exception& e) {
        // todo: UI dialogs for errors
        std::cout << std::string(e.what()) << std::endl;
    } catch (...) {
        std::cout << "Error" << std::endl;
    }
}
