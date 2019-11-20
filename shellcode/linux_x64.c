// -fno-stack-protector -no-pie

/*
https://github.com/nsxz/ReflectiveELFLoader/blob/master/ReflectiveElfLoader.c
https://github.com/odzhan/shellcode/blob/master/os/linux/c/routines.c
*/


__attribute__((always_inline)) inline long
_open(const char *path, unsigned long flags, long mode) {
    long ret;
    __asm__ volatile(
      "mov %0, %%rdi\n"
      "mov %1, %%rsi\n"
      "mov %2, %%rdx\n"
      "mov $2, %%rax\n"
      "syscall" : : "g"(path), "g"(flags), "g"(mode));
    asm ("mov %%rax, %0" : "=r"(ret));              

    return ret;
}

__attribute__((always_inline)) inline int
_close(unsigned int fd) {
    long ret;
    __asm__ volatile(
      "mov %0, %%rdi\n"
      "mov $3, %%rax\n"
      "syscall" : : "g"(fd));
    asm("mov %%rax, %0" : "=r"(ret));

    return (int)ret;
}

__attribute__((always_inline)) inline int
_write(long fd, char *buf, unsigned long len) {
  long ret;

  __asm__ volatile(
      "mov %0, %%rdi\n"
      "mov %1, %%rsi\n"
      "mov %2, %%rdx\n"
      "mov $1, %%rax\n"
      "syscall" : : "g"(fd), "g"(buf), "g"(len));
    asm("mov %%rax, %0" : "=r"(ret));

  return (int)ret;
}

__attribute__((always_inline)) inline int
_read(long fd, char *buf, unsigned long len) {
     long ret;
     
    __asm__ volatile(
      "mov %0, %%rdi\n"
      "mov %1, %%rsi\n"
      "mov %2, %%rdx\n"
      "mov $0, %%rax\n"
      "syscall" : : "g"(fd), "g"(buf), "g"(len));
    asm("mov %%rax, %0" : "=r"(ret));

    return (int)ret;
}


int main() {
  char m[] = {'/', 'p', 'r', 'o', 'c', '/', 's', 'e', 'l', 'f', '/', 'm', 'a', 'p', 's', 0};
  long f = _open(m, 0, 777);
  char buf[100];
  _read(f, buf, 99);
  _close(f);
  buf[99] = 0;
  _write(0, buf, 100);
}
