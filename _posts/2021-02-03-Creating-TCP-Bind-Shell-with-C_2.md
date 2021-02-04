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

