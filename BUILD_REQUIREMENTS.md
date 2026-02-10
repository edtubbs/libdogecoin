# Build Requirements Investigation

## Question
Are the changes to `dogecoin.h` and `Package.swift` needed?

## Answer
**Only the change to `Package.swift` is needed.** The change to `dogecoin.h` is NOT required.

## Testing Results

### Test 1: Without sys/types.h include (dogecoin.h)
**Status:** ✅ **SUCCESS**

Removed the `#include <sys/types.h>` from `dogecoin.h` and the build completed successfully.

```bash
$ swift build
Build complete! (4.68s)
```

### Test 2: Without _GNU_SOURCE flag (Package.swift)
**Status:** ❌ **FAILED**

Removed `-D_GNU_SOURCE` from `Package.swift` and the build failed with 12 errors:

**Errors:**
1. `ssize_t` type not defined
2. Endian conversion functions not available:
   - `le16toh()`, `le32toh()`, `le64toh()`
   - `htole16()`, `htole32()`, `htole64()`
   - `be32toh()`, `be64toh()`
   - `htobe32()`, `htobe64()`

### Test 3: With only _GNU_SOURCE flag (Package.swift)
**Status:** ✅ **SUCCESS**

With `-D_GNU_SOURCE` defined but without the `sys/types.h` include in `dogecoin.h`:

```bash
$ swift build
Build complete! (3.10s)
```

## Conclusion

### Required Changes
✅ **Package.swift** - Add `-D_GNU_SOURCE` compiler flag

The `-D_GNU_SOURCE` flag enables POSIX and GNU extensions which automatically provide:
- `ssize_t` type (via `<sys/types.h>`)
- Endian conversion functions (via `<endian.h>`)

### Not Required
❌ **dogecoin.h** - No changes needed

The `#include <sys/types.h>` is NOT needed because:
1. When `-D_GNU_SOURCE` is defined, the necessary system headers are included automatically
2. The build works perfectly without this explicit include
3. Adding it creates unnecessary coupling to platform-specific headers

## Minimal Change Set

**Only modify:**
```swift
// Package.swift
.unsafeFlags([
    "-UHAVE_CONFIG_H",
    "-D_GNU_SOURCE",  // <-- This line is required
    "-Wno-shorten-64-to-32",
    // ...
])
```

**Do NOT modify:**
- `include/dogecoin/dogecoin.h` - No changes needed

## Verification

The Swift module builds and runs correctly with only the `Package.swift` change:

```bash
$ swift build
Build complete! (3.00s)

$ # Test program runs successfully
Testing libdogecoin Swift module...
✓ Generated keypair successfully
```

---

**Date:** February 10, 2026  
**Tested on:** Linux x86_64 with Swift 6.2.3
