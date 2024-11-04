#include <ares.h>
#include <stdio.h>

int main() {
    int status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS){
        printf("ares_library_init: %s\n", ares_strerror(status));
        return 1;
    }
    ares_library_cleanup();
    return 0;
}
