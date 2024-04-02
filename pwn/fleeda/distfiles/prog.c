// gcc prog.c -o prog -no-pie -O3
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

void myread(char *buf, size_t n) {
  ssize_t rc;
  size_t nread = 0;

  while (nread+1 < n) {
    int c = fgetc(stdin);
    if (c == EOF || c == '\n') { 
      buf[nread] = '\0';
      return;
    }

    buf[nread++] = c;
  }
  
  buf[n-1] = '\0';
  return;
}

int main(void) {
  setbuf(stdout, NULL);

  char buf[16];
  myread(buf, 200);
  puts(buf);
}
