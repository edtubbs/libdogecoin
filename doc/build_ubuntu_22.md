# Building Libdogecoin on Ubuntu 22.04 LTS

This guide provides step-by-step instructions for building libdogecoin on Ubuntu 22.04 LTS (Jammy Jellyfish).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installing Dependencies](#installing-dependencies)
- [Building with Autotools](#building-with-autotools)
- [Building with CMake](#building-with-cmake)
- [Running Tests](#running-tests)
- [Installing System-Wide](#installing-system-wide)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before building libdogecoin, ensure your system is up to date:

```bash
sudo apt update
sudo apt upgrade -y
```

## Installing Dependencies

### Core Build Dependencies

Install the essential build tools and libraries required for libdogecoin:

```bash
sudo apt install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    git
```

**Package descriptions:**
- `build-essential` - Includes GCC compiler, make, and other essential build tools
- `autoconf` - Generates configure scripts from configure.ac
- `automake` - Tool for generating Makefile.in files
- `libtool` - Generic library support script
- `pkg-config` - Helper tool for compiling applications and libraries
- `git` - Version control system (for cloning the repository)

### Network Support Dependencies (Optional)

If you plan to use networking features (SPV node, P2P client), install libevent:

```bash
sudo apt install -y libevent-dev
```

**Package descriptions:**
- `libevent-dev` - Event notification library (required for network features)

### CMake (Alternative Build System)

If you prefer to use CMake instead of autotools:

```bash
sudo apt install -y cmake
```

### Additional Tools (Optional)

For development and testing:

```bash
sudo apt install -y \
    valgrind \
    clang-format \
    python3 \
    python3-pip
```

**Package descriptions:**
- `valgrind` - Memory debugging and leak detection tool
- `clang-format` - Code formatting tool
- `python3` and `python3-pip` - For running Python-based tests

## Building with Autotools

### Step 1: Clone the Repository

```bash
git clone https://github.com/dogecoinfoundation/libdogecoin.git
cd libdogecoin
```

### Step 2: Generate Configuration Script

Run the autogen script to generate the configure script:

```bash
./autogen.sh
```

This will create the `configure` script using autoconf and automake.

### Step 3: Configure the Build

#### Basic Configuration (with networking enabled)

```bash
./configure
```

#### Configuration without Networking

If you don't need network features and want to avoid the libevent dependency:

```bash
./configure --disable-net --disable-tools
```

#### Configuration Options

You can customize the build with various flags:

```bash
# Disable networking features
./configure --disable-net

# Disable CLI tools
./configure --disable-tools

# Enable test password (for testing only)
./configure --enable-test-passwd

# Set custom installation prefix
./configure --prefix=/usr/local

# View all available options
./configure --help
```

### Step 4: Build the Library

Compile the library using make:

```bash
make
```

For faster compilation on multi-core systems:

```bash
make -j$(nproc)
```

### Step 5: Verify the Build

After building, the static library will be located at:
- `.libs/libdogecoin.a` - Static library
- `.libs/libdogecoin.so` - Shared library (if built)

Header files are in:
- `include/dogecoin/*.h` - Public API headers

## Building with CMake

### Step 1: Clone the Repository

```bash
git clone https://github.com/dogecoinfoundation/libdogecoin.git
cd libdogecoin
```

### Step 2: Create Build Directory

```bash
mkdir build
cd build
```

### Step 3: Configure with CMake

#### Basic Configuration

```bash
cmake ..
```

#### Configuration Options

```bash
# Disable networking
cmake -DWITH_NET=OFF ..

# Enable test password
cmake -DTEST_PASSWD=TRUE ..

# Set build type (Debug/Release)
cmake -DCMAKE_BUILD_TYPE=Release ..

# Custom installation prefix
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
```

### Step 4: Build

```bash
cmake --build .
```

Or with multiple cores:

```bash
cmake --build . -j$(nproc)
```

## Running Tests

### With Autotools

After building with autotools, run the test suite:

```bash
make check
```

This will compile and run all unit tests. Expected output:

```
PASSED - test_address()
PASSED - test_aes()
PASSED - test_base58()
PASSED - test_bip32()
PASSED - test_bip39()
PASSED - test_bip44()
PASSED - test_block()
PASSED - test_buffer()
PASSED - test_cstr()
PASSED - test_eckey()
PASSED - test_ecc()
PASSED - test_hash()
PASSED - test_key()
PASSED - test_mem()
PASSED - test_random()
PASSED - test_script()
PASSED - test_serialize()
PASSED - test_sign()
PASSED - test_transaction()
PASSED - test_tx()
PASSED - test_utils()
PASSED - test_vector()
PASSED - test_wallet()
PASSED - test_tool()
PASS: tests
```

### With CMake

From the build directory:

```bash
./tests
```

Or using CTest:

```bash
ctest --output-on-failure
```

## Installing System-Wide

### With Autotools

To install libdogecoin system-wide (typically to `/usr/local`):

```bash
sudo make install
```

This will install:
- Libraries to `/usr/local/lib/`
- Headers to `/usr/local/include/dogecoin/`
- CLI tools to `/usr/local/bin/` (if enabled)

Update the library cache:

```bash
sudo ldconfig
```

### With CMake

From the build directory:

```bash
sudo cmake --install .
```

## Using the Library

### Compiling Your Program

After building or installing libdogecoin, you can use it in your C programs:

```c
#include <dogecoin/libdogecoin.h>

int main() {
    dogecoin_ecc_start();
    
    // Your code here
    
    dogecoin_ecc_stop();
    return 0;
}
```

#### If Installed System-Wide

```bash
gcc myprogram.c -ldogecoin -levent_core -o myprogram
```

#### If Not Installed (Using Local Build)

```bash
gcc myprogram.c \
    -I/path/to/libdogecoin/include \
    -L/path/to/libdogecoin/.libs \
    -ldogecoin -levent_core \
    -o myprogram
```

## Troubleshooting

### "libevent headers missing" Error

If you see this error during configuration:

```
configure: error: libevent headers missing
```

Install libevent development package:

```bash
sudo apt install -y libevent-dev
```

Or disable networking:

```bash
./configure --disable-net
```

### "command not found: autogen.sh"

Ensure the script is executable:

```bash
chmod +x autogen.sh
./autogen.sh
```

### "aclocal: command not found"

Install automake:

```bash
sudo apt install -y automake
```

### "libtoolize: command not found"

Install libtool:

```bash
sudo apt install -y libtool
```

### Linker Errors with libevent

If you get linker errors related to libevent when compiling your program:

```bash
# Ensure libevent is installed
sudo apt install -y libevent-dev

# Update library cache
sudo ldconfig

# Link explicitly
gcc myprogram.c -ldogecoin -levent -levent_core -o myprogram
```

### Tests Hang at "test_tool()"

When running `make check` with networking enabled, tests may appear to hang briefly at `test_tool()`. This is normal - the test is running and will complete shortly.

### "error while loading shared libraries: libdogecoin.so.0"

After installing, if you get this error:

```bash
sudo ldconfig
```

Or add the library path to your environment:

```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

## Additional Resources

- [Getting Started Guide](getting_started.md) - General build instructions for all platforms
- [Tools Documentation](tools.md) - CLI tools documentation
- [API Documentation](../include/dogecoin/) - Header files with API documentation
- [Examples](../contrib/examples/) - Example programs

## Minimum Supported Version

Libdogecoin is tested and supported on Ubuntu 22.04 LTS. It should also work on:
- Ubuntu 20.04 LTS and later
- Debian 11 (Bullseye) and later
- Other Debian-based distributions with equivalent package versions

For Ubuntu versions older than 20.04, you may need to install newer versions of dependencies from backports or third-party repositories.

## Quick Reference

### Minimal Build (No Network Support)

```bash
sudo apt update
sudo apt install -y build-essential autoconf automake libtool git
git clone https://github.com/dogecoinfoundation/libdogecoin.git
cd libdogecoin
./autogen.sh
./configure --disable-net --disable-tools
make -j$(nproc)
make check
```

### Full Build (With Network Support)

```bash
sudo apt update
sudo apt install -y build-essential autoconf automake libtool libevent-dev git
git clone https://github.com/dogecoinfoundation/libdogecoin.git
cd libdogecoin
./autogen.sh
./configure
make -j$(nproc)
make check
sudo make install
sudo ldconfig
```

### CMake Build

```bash
sudo apt update
sudo apt install -y build-essential cmake libevent-dev git
git clone https://github.com/dogecoinfoundation/libdogecoin.git
cd libdogecoin
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc)
./tests
sudo cmake --install .
```

---

**Last Updated:** February 2026  
**Tested On:** Ubuntu 22.04 LTS (Jammy Jellyfish)
