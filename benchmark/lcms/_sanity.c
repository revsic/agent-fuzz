#include "lcms2.h"
#include <stdio.h>

int main() {
    cmsPipeline* AToB0 = cmsPipelineAlloc(0, 3, 3);
    cmsPipelineFree(AToB0);
    return 0;
}
