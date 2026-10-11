#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* keeps system@plt in the binary (never actually called) */
void unused(void) { system("echo never called"); }

/* a hand-planted "pop rdi ; ret" gadget, so the demo is self-contained.
   On a real target you take this from libc (after a leak) or use ret2csu. */
__attribute__((naked)) void gadget_pop_rdi_ret(void) { __asm__ volatile("pop %rdi\n ret\n"); }

char *mygets(char *s) { int i = 0; char c;                    /* unbounded, like gets() */
    while (read(0, &c, 1) == 1 && c != '\n') s[i++] = c;
    s[i] = 0; return s; }

void vuln(void) { char buf[64]; mygets(buf); puts("bye"); }

int main(void) { setvbuf(stdout, 0, _IONBF, 0); setvbuf(stdin, 0, _IONBF, 0);
                 puts("[*] rop demo - give me a line:"); vuln(); return 0; }
