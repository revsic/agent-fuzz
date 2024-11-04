clang _sanity.c \
    ./workspace/lib/liblcms2.so \
    -I ./workspace/include \
    -g \
    -fno-omit-frame-pointer \
    -fsanitize=address,undefined \
    -fsanitize-address-use-after-scope \
    -fprofile-instr-generate \
    -fcoverage-mapping

LD_PRELOAD=./workspace/lib/liblcms2.so ./a.out

llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov export ./workspace/lib/liblcms2.so -format=lcov --instr-profile=default.profdata | grep cmsPipelineAlloc
# llvm-cov export ./a.out -format=lcov --instr-profile=default.profdata | grep ares_library_init
