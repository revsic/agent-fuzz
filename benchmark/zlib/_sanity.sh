rm a.* default.*

clang _sanity.c \
    ./workspace/lib/libz.a \
    -I ./workspace/include \
    -g \
    -fno-omit-frame-pointer \
    -fsanitize=address,undefined \
    -fsanitize-address-use-after-scope \
    -fprofile-instr-generate \
    -fcoverage-mapping

./a.out

llvm-profdata merge -sparse default.profraw -o default.profdata
llvm-cov export ./workspace/lib/libz.a -format=lcov --instr-profile=default.profdata | grep deflateInit
llvm-cov export ./a.out -format=lcov --instr-profile=default.profdata | grep deflateInit
