#include <stdio.h>
#include <string.h>

int main() {
    int args_size = 0;
    int limit = 512;
    int max_len = 128;
    
    char args[512];
    memset(args, 0, 512);

    const char* my_args[] = {"git", "rev-parse", "--show-toplevel", "extra", "arg", NULL};
    
    for (int i = 0; i < 5; i++) {
        if (my_args[i] == NULL) break;
        
        int offset = args_size & (limit - max_len);
        // Simulate bpf_probe_read_user_str
        int sz = strlen(my_args[i]) + 1; // +1 for null byte
        if (sz > max_len) sz = max_len;
        
        memcpy(&args[offset], my_args[i], sz);
        args[offset + sz - 1] = '\0';
        
        printf("i=%d, copying '%s' (sz=%d) to offset %d\n", i, my_args[i], sz, offset);
        
        args_size += sz;
    }
    
    printf("\nTotal args_size: %d\n", args_size);
    printf("Buffer hex:\n");
    for (int i=0; i<args_size; i++) {
        if (args[i] == '\0') printf("\\0 ");
        else printf("%c", args[i]);
    }
    printf("\n");
    
    return 0;
}
