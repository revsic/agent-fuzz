clang _sanity.c \
    ./workspace/lib/libcares.so \
    -I ./workspace/include \
    -g \
    -fno-omit-frame-pointer \
    -fsanitize=address,undefined \
    -fsanitize-address-use-after-scope \
    -fprofile-instr-generate \
    -fcoverage-mapping

LD_PRELOAD=./workspace/lib/libcares.so ./a.out

llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov export ./workspace/lib/libcares.so -format=lcov --instr-profile=default.profdata | grep ares_library_init
# llvm-cov export ./a.out -format=lcov --instr-profile=default.profdata | grep ares_library_init
