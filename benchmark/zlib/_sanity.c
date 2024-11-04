#include <stdio.h>
#include "zlib.h"

#define COMPRESSION_LEVEL 9

int main() {
    z_stream stream = {0};
    if (deflateInit(&stream, COMPRESSION_LEVEL) != Z_OK) {
    	printf("deflateInit(...) failed!\n");
        return 1;
    }
    deflateEnd(&stream);
    return 0;
}
