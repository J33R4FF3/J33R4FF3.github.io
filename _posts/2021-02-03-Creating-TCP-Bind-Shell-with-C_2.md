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
<h3>Creating a socket</h3>

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


