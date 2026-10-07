#include <stdio.h>

int main() {
    int args_size = 0;
    int limit = 512;
    int max_len = 128;
    int sz = 128;
    
    // Simulate loop in BPF
    for (int i = 0; i < 5; i++) {
        if (args_size <= limit - max_len) {
            int offset = args_size & (limit - max_len);
            printf("i=%d, size=%d, offset=%d (args_size & %d)\n", i, args_size, offset, limit - max_len);
            args_size += sz;
        } else {
            printf("i=%d, loop broken (size %d > %d)\n", i, args_size, limit - max_len);
            break;
        }
    }
    return 0;
}
