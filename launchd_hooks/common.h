#ifndef common_h
#define common_h

extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

// Logging disabled to prevent any I/O overhead or locking inside posix_spawn
#define serial_println(msg, ...) do {} while (0)

#endif /* common_h */
