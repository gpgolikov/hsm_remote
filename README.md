
**Build process**
----------
* Install Conan package manager
* Install CMake tool version 3.6 or later
* Install Mingw32 with Dwarf exceptions type and Posix threads
* Install Python3 version interpreter and replace _pyconfig.h_ file by _contrib/python3_include_path/pyconfig.h_ (patch has been tested on python3 version 3.6.4)
* Execute next command at _contrib_ directory `conan install . --profile conanprofile --build missing`
* Create folder _cmake_build_ at root project directory
* Execute at _cmake_build_ directory `cmake.exe -DCMAKE_BUILD_TYPE=Release -G "CodeBlocks - MinGW Makefiles" ..`
* Execute at _cmake_build_ directory `cmake.exe --build . --target all`
* That's all. Find executable files at _cmake_build_ file system

**Executable files description**
----------
* _cmake_build/src/hsm_client/bin/libhsm_client.dll_ - shared library for writing clients (COM Interop supported)
* _cmake_build/src/hsm_server/bin/hsm_server.exe_ - server application, should be installed at HSM workstation side
* _cmake_build/test/test_hsm_lib/bin/test_hsm_lib.exe_ - testing tools of main HSM library
* _cmake_build/test/test_hsm_lib/bin/test_hsm_lib_client.exe_ - testing tools of client shared library

**How-To**
----------
* **How to export private key from HSM**: on HSM workstation in terminal apply next command `hsm_lib.exe [exportKeyOnly_HSM]`
