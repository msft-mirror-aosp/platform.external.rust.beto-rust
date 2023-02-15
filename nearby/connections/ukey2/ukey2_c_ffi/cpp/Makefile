C_SRCS := ukey2.cc
CC = clang++
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
    FFI_LIB = ../../../../target/release/libukey2_c_ffi.dylib
else
    FFI_LIB = ../../../../target/release/libukey2_c_ffi.so
endif
ukey2:
	cargo build --release
	rm -rf build
	mkdir build
	$(CC) $(C_SRCS) $(FFI_LIB) -o build/ukey2
