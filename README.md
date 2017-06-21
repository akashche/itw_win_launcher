Windows launcher for IcedTea-Web
--------------------------------

Buld with MSVC:

    rc javaws_win.rc
    cl /O1 javaws_win.cpp javaws_win.res shell32.lib ole32.lib comctl32.lib advapi32.lib /EHsc /MT /W4 /WX /link /subsystem:windows

Build with GCC (MinGW-64):

    windres javaws_win.rc -o javaws_win.res -O coff
    g++ -Os javaws_win.cpp javaws_win.res -mwindows -lshell32 -lole32 -lcomctl32 -ladvapi32 -o javaws_win.exe -Wall -Werror -Wextra

Build Rust version (`x86_64-pc-windows-gnu` toolchain):

    windres javaws_win.rc -o javaws_win.res -O coff
    cargo rustc -v --release -- -C "link-args=-mwindows javaws_win.res"
    
Run:

    javaws_win.exe test.jnlp