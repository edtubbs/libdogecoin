# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT libdogecoin_t.h libdogecoin_t.c libdogecoin_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/libdogecoin.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/libdogecoin.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(enclave enc.c ${CMAKE_CURRENT_BINARY_DIR}/libdogecoin_t.c /include/ /home/runner/work/libdogecoin/libdogecoin/depends/x86_64-pc-linux-gnu/include/dogecoin/libdogecoin.h)

if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file libdogecoin_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR} /home/runner/work/libdogecoin/libdogecoin/depends/x86_64-pc-linux-gnu/include/dogecoin)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -ldogecoin -lunistring")

# Add custom library paths for -ldogecoin and -lunistring
target_link_directories(enclave PRIVATE /home/runner/work/libdogecoin/libdogecoin/depends/x86_64-pc-linux-gnu/lib)

# Link the libraries without -l prefix
target_link_libraries(enclave openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB} openenclave::oelibc dogecoin unistring)

if (LVI_MITIGATION MATCHES ControlFlow)
  # Helper to enable compiler options for LVI mitigation.
  apply_lvi_mitigation(enclave)
  # Link against LVI-mitigated libraries.
  target_link_libraries(
    enclave openenclave::oeenclave-lvi-cfg
    openenclave::oecrypto${OE_CRYPTO_LIB}-lvi-cfg openenclave::oelibc-lvi-cfg)
else ()
  target_link_libraries(
    enclave openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
    openenclave::oelibc)

endif ()
