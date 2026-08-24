//
//  common.h
//  tvos-injection
//
//  Created by user on 6/18/23.
//

#ifndef common_h
#define common_h

extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

#define serial_println(msg, ...) \
    do { \
        int fd = open("/dev/console", O_RDWR | O_NOCTTY | O_SYNC | O_NONBLOCK); \
        if (fd > 0) { \
            char buffer[1024 * 2]; \
            char process_name[1024]; \
            pid_t pid = getpid(); \
            int ret = proc_pidpath(pid, process_name, sizeof(process_name)); \
            if (ret > 0) { \
                char* base_name = strrchr(process_name, '/'); \
                if (base_name) \
                    base_name++; \
                else \
                    base_name = process_name; \
                snprintf(buffer, sizeof(buffer), "\033[32;1m[%s]\033[0m " msg "\n", base_name, ##__VA_ARGS__); \
                write(fd, buffer, strlen(buffer)); \
            } \
            close(fd); \
        } \
    } while (0)

#endif /* common_h */
