# mwcceppc-linux

Metrowerks C/C++ Compiler for Embedded PowerPC (CodeWarrior) ported to Linux. This repository contains scripts to extract the sections from `mwcceppc.exe` and link them into a native 32-bit x86 Linux executable, with Win32 API wrapper functions from [wibo](https://github.com/decompals/wibo).

### Tested with:

- mwcceppc.exe
  - `46cc62c8b1564e65f53c9185b7ea1c361611d832`
  - `310620c3b00fd05b9e3010e5af498f0bbd688583`
  - `0326c399a1ffb0870f819303e585447a2c8103ed`

## Building

Place `mwcceppc.exe` in the root of this repository, then run `make`. Python and the `pefile` library are required to build this repository.

## Usage

After building, run the resulting `mwcceppc` executable, with the same usage as `mwcceppc.exe`.
