Windows launcher for IcedTea-Web
--------------------------------

Buld with MSVC:

    cl javaws_win.cpp shell32.lib ole32.lib /EHsc /MT

Build with GCC (MinGW-64):

    g++ javaws_win.cpp -lshell32 -lole32 -o javaws_win.exe

To run it current directory must contain:

 - `jdk`: jdk directory
 - `netx.jar`: NetX JAR from ITW
 - `test.jnlp`: JNLP file

 Work in progress, current limitations:

  - runs as CLI app and prints errors into console instead of GUI dialogs
  - no input/environment/config handling
