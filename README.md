# IEX-Tools
This is a work-in-progress tool for extracting information from historical IEX data.

## Compile

For compiling this tool you will need to have a C++20 compatible toolchain:

* GCC >= 8
* CMake >= 3.10 

Then run:

```
$ mkdir build && cd build
$ cmake ../iextoolslib
$ make
```

Executable will be placed under `build/iex-tools` 

## Run 
User must provide the input .pcap file and a directory where the tools will store the output.

```
$ iex-tools [FILE] [OUT_DIR]
```
