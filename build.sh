#!/bin/sh
set -e

# https://wiki.osdev.org/Debugging_UEFI_applications_with_GDB
# https://sourceforge.net/p/ast-phoenix/code/ci/master/tree/kernel/boot/Makefile#l18

# determine architecture
# TODO: support other archs?
arch=$1
if [ x"$arch" = "xx86_64" ] || [ x"$arch" = "x" ]; then
	arch=x86_64
	efi_arch=x64
	ARCH_CFLAGS="-mssse3 -mno-mmx"
	OPT_CFLAGS="-ggdb -Os"
else
	echo "Error: unknown arch: $arch" > /dev/stderr
	exit 1
fi

GNUEFI=`pwd`/../third-party/gnu-efi

# Build gnu-efi on demand
if [ ! -f "${GNUEFI}/${arch}/gnuefi/reloc_${arch}.o" ]; then
	make -C ${GNUEFI}
fi

rm -rf bin && mkdir bin

cc -I/usr/include/efi -Wall -Wextra -Os -fwhole-program -o "bin/${arch}.util-pcr4.exe" util-pcr4.c -lcrypto
cc $ARCH_CFLAGS -ggdb -O0 -Wall -Wextra -fwhole-program -o "bin/${arch}.util-charm.exe" util-charm.c

# incase we need the current compilers version of libgcc or for the intrinsics headers
gcc_ver=`gcc --version | head -n 1 | cut -f 2 -d ')' | cut -f 2 -d ' ' | cut -f 1 -d '.'`

# compile
cc -I/usr/include/efi -I"/usr/include/efi/${arch}" -I"/usr/lib/gcc/${arch}-linux-gnu/${gcc_ver}/include" -I`pwd` \
   -DMACHINE_TYPE_NAME="${efi_arch}" -DEFI_FUNCTION_WRAPPER -DGNU_EFI_USE_MS_ABI \
   -Wall -Wextra -std=gnu90 -nostdinc -fpic -fshort-wchar -Wsign-compare \
   -nostdinc -ffreestanding -fno-strict-aliasing -fno-stack-protector \
   $ARCH_CFLAGS $OPT_CFLAGS -DSTUB_VERSION=`sha256sum *.c | sha256sum | head -c 4` \
   -c stub.c -o "bin/.${arch}.stub.o"

# link into .so file, include EFI crt
ld -shared -Bsymbolic -nostdlib -znocombreloc \
	-T "${GNUEFI}/gnuefi/elf_${arch}_efi.lds" \
	"${GNUEFI}/${arch}/gnuefi/crt0-efi-${arch}.o" \
	"${GNUEFI}/${arch}/gnuefi/reloc_${arch}.o" \
	"./bin/.${arch}.stub.o" \
	-o "./bin/.${arch}.stub.so"

# ensure no unresolved symbols exist in .so file
nm -D -u "bin/.${arch}.stub.so" | grep ' U ' && exit 1

# output to EFI PE executable
objcopy -j .text -j .sdata -j .data -j .dynamic \
		-j .dynsym -j .rel -j .rela -j .reloc \
		--target="efi-app-${arch}" "bin/.${arch}.stub.so" "bin/${arch}.stub.efi"

# create function dependency graph
# see: https://reverseengineering.stackexchange.com/a/14914
echo 'digraph G {' > "bin/.${arch}.stub.dot"
objdump -d "bin/${arch}.stub.efi" \
		| grep '<' \
		| sed -e 's/^[^<]*//' \
		| sed 's/<\([^+]*\)[^>]*>/\1/' \
		| awk 'BEGIN { FS = ":" } \
		       NF>1 { w=$1; } \
		       NF==1 && w != $1 { print "\"" w "\" -> \"" $0 "\";" }' \
		| sort -u >> "bin/.${arch}.stub.dot"
echo '}' >> "bin/.${arch}.stub.dot"

echo ""
strings -e l "bin/${arch}.stub.efi"

echo ""
ls -lah bin/${arch}*

# XXX: can compile with clang? currently this doesn't work
#CLANG_CFLAGS="-target x86_64-unknown-windows 
#        		  -ffreestanding 
#        		  -fshort-wchar 
#        		  -mno-red-zone
#        		  -Os
#        		  -I/usr/include/efi -I/usr/include/efi/${arch}"
#CLANG_LDFLAGS='-nostdlib 
#        		   -Wl,-entry:efi_main 
#        		   -Wl,-subsystem:efi_application 
#        		   -fuse-ld=lld-link'
#clang $CLANG_CFLAGS $CLANG_LDFLAGS -o bin/${arch}.clang.efi stub.c ../gnu-efi/lib/data.c ../gnu-efi/lib/str.c ../gnu-efi/lib/misc.c ../gnu-efi/lib/runtime/rtstr.c ../gnu-efi/lib/runtime/efirtlib.c ../gnu-efi/lib/dpath.c ../gnu-efi/lib/print.c ../gnu-efi/lib/guid.c ../gnu-efi/lib/error.c ../gnu-efi/lib/init.c  ../gnu-efi/lib/runtime/rtdata.c ../gnu-efi/lib/hand.c ../gnu-efi/lib/console.c ../gnu-efi/lib/event.c  ../gnu-efi/lib/${arch}/math.c ../gnu-efi/lib/${arch}/initplat.c
