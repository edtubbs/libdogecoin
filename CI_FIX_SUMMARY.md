# CI Build Failure Fix

**Date:** 2026-02-07  
**Issue:** Windows build failures in CI  
**Status:** ✅ FIXED

## Problem

CI workflow runs were failing on all Windows builds:
- x86_64-win-native-rel
- x86_64-win-native
- x86_64-win-native-notpm

**Error:**
```
spv.obj : error LNK2019: unresolved external symbol 
dogecoin_tx_extract_falcon512_commit referenced in function 
dogecoin_net_spv_post_cmd
```

**CI Link:** https://github.com/edtubbs/libdogecoin/actions/runs/21772074494

## Root Cause

In a previous commit, code was added to `src/spv.c` that calls `dogecoin_tx_extract_falcon512_commit()` to detect Falcon-512 commits in OP_RETURN outputs for off-chain verification.

The function is implemented in `src/pqc_falcon.c`, which was:
- ✅ **Included in Makefile.am** (used by Linux/autotools builds)
- ❌ **Missing from CMakeLists.txt** (used by Windows/CMake builds)

This caused a linker error on Windows: the function was declared but not defined.

## Solution

**File Modified:** `CMakeLists.txt`

Added `src/pqc_falcon.c` to the `TARGET_SOURCES` list at line 283:

```cmake
TARGET_SOURCES(${LIBDOGECOIN_NAME} PRIVATE
    src/address.c
    src/aes.c
    ...
    src/moon.c
    src/pqc_falcon.c    # <- ADDED
    src/qr.c
    ...
)
```

## Changes Made

**Commit:** 6834d6d  
**Message:** "Fix Windows build: Add pqc_falcon.c to CMakeLists.txt"

**Diff:**
```diff
diff --git a/CMakeLists.txt b/CMakeLists.txt
index bee845d..2018de1 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -280,6 +280,7 @@ TARGET_SOURCES(${LIBDOGECOIN_NAME} PRIVATE
     src/map.c
     src/mem.c
     src/moon.c
+    src/pqc_falcon.c
     src/qr.c
     src/qrengine.c
     src/pow.c
```

## Expected Outcome

When CI runs again:
1. ✅ `pqc_falcon.c` will be compiled in Windows builds
2. ✅ `dogecoin_tx_extract_falcon512_commit()` will be available
3. ✅ `spv.c` will link successfully
4. ✅ All Windows build jobs will succeed

## Cross-Platform Consistency

Both build systems now include the same source files:

| Build System | File | Status |
|--------------|------|--------|
| **Makefile.am** (Linux/autotools) | `src/pqc_falcon.c` | ✅ Included |
| **CMakeLists.txt** (Windows/CMake) | `src/pqc_falcon.c` | ✅ Included (now) |

## Technical Details

### Function Purpose
`dogecoin_tx_extract_falcon512_commit()` extracts Falcon-512 commit data from OP_RETURN outputs in transactions. This enables off-chain quantum-resistant signature verification.

### Where It's Called
In `src/spv.c` (line 684):
```c
// Check for Falcon commit in OP_RETURN for off-chain verification
uint8_t falcon_commit_data[32];
if (dogecoin_tx_extract_falcon512_commit(tx, falcon_commit_data)) {
    char commit_hex[65];
    utils_bin_to_hex(falcon_commit_data, 32, commit_hex);
    client->nodegroup->log_write_cb("[falcon-commit] Found at height=%d txpos=%u commit=%s\n", 
                                     pindex->height, i, commit_hex);
}
```

### Why Build Systems Differ
- **Linux builds** use autotools (`./configure && make`) which reads `Makefile.am`
- **Windows builds** use CMake which reads `CMakeLists.txt`
- Both must be kept in sync for cross-platform compatibility

## Verification

The fix has been:
- ✅ Identified through CI logs analysis
- ✅ Applied to CMakeLists.txt
- ✅ Committed with detailed explanation
- ✅ Ready for CI to verify on next run

## Conclusion

This was a simple but critical fix: ensuring that the same source file is included in both build system configurations. The Windows builds were missing `pqc_falcon.c`, which caused a linker error. Adding it to CMakeLists.txt resolves the issue and ensures cross-platform build consistency.
