# Gekko
Easy-peasy lizard-squeezy sync tool.  

---

## Building Gekko
This section describes how to build Gekko.

### Windows
Prerequisites:
* `cmake`, which can be downloaded [here](https://cmake.org/download/).
* `mingw-w64`, which can be downloaded [here](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Personal%20Builds/mingw-builds/installer/mingw-w64-install.exe/download).
* `libssh2`, build your own, or use version 1.9.0 pre-built binary located at `platform/windows/libssh2`.
  
Build steps:
1. Simply configure and build using cmake.
  
### macOS
Prerequisites:
* `cmake`, which can be downloaded [here](https://cmake.org/download/).
* `homebrew`, to install `libssh2` pre-built binaries.
* `libssh2`, which can be installed by `brew install libssh2`.

Build steps:
1. Simply configure and build using cmake.