---
title: "Implementing a password protected bind shell in Linux 64-bit Assembly shellcode - Part 2"
categories:
  - blog
---

Now that we have the finalized code in C, we can begin the process of "converting" the code to Linux 64-bit Assembly code. The reason that we first wrote the program in C should become apparent as we go through the process.

<h3>Background</h3>

We need to do a little bit of homework before we can just jump into coding in Assembly and I will try my best to explain the needed background on the workings of Assembly, syscalls, registers and the stack.

<h2>What is Assembly</h2>

Assembly is, in very basic terms, a low level programming language and is as close as you can get to actual machine language. Every type of computer architecture or even operating system will have its own assembly language due to the differences in instructions, registers and how it uses the stack. This blog specifically focuses on Linux x86_64 assembly.

<h2>What are Registers</h2>

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

There are other registers too, R8 - R15 for instance, but we will not be working with these so much.

It is also important to understand the structure of a register, especially when working with 64 bit registers. The reason why will become clearer when we reach the last phase of our process for generating shellcode. 

{% include figure image_path="/assets/images/registers.jpg" caption="64 bit register sizes." %}
