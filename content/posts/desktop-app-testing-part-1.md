+++
date = '2025-03-05T13:21:10-03:00'
draft = true
title = 'Desktop App Testing Part 1'
+++

In a recent engagement I was in a engagement to look for a desktop application, and since I could not find any reference to how to approach it to find vulnerabilities I wrote it as to be as future reference.

This blog post will be focused on a simple yet effective techniques to find vulnerabilities that can be reproduced by anyone with minimal setup, and with main focus on windows applications.

Also the steps above expects that the analyzed application doesn't have any form of obfuscation or packing.

## **Why would I assess a desktop application?**

In the age of mobile applications, cloud and web applications desktop application are usually forgot and left in the dust, leaving an interesting attack vector that can be leveraged by adversaries and threat actors, such as the recent [solarwind](https://whatis.techtarget.com/feature/SolarWinds-hack-explained-Everything-you-need-to-know) supply chain incident, or even to [find](https://www.veracode.com/sites/default/files/Resources/Whitepapers/static-detection-of-backdoors-1.0.pdf) [backdoors](https://pierrekim.github.io/blog/2021-01-12-fiberhome-ont-0day-vulnerabilities.html).

This kind of test can also be used by red teamers during targeted exercises, you won't believe what kind of credentials you can find in a some applications or discover new avenues for exploitation

When starting to search for methodologies, tools and howtos eventually you will find terms used interchangely as decompilers, disassemblers and such, I like the definition made by Daniel Miessler from the seclist project in his [blog](https://danielmiessler.com/blog/programming-decompiler-vs-disassembler/):

> A *decompiler* takes one from a binary to source code–or something similarly high-level that can easily be read by humans. A *disassembler* takes one from binary to assembler–which is much lower level and is more difficult to read for humans.

> Decompilers get you to source code; disassemblers get you to assembly.

Preferably we are looking for *decompilers*, but sometimes things are what they are.

## Methodology

The steps involved into looking into desktop applications are very similiar to the ones when doing malware reverse engineering or reversing of general software (assuming a black-box assessment, no source code available), so the steps can be split into two main phases:

* Static analysis
* Dynamic analysis

## Static analysis

Static analysis typically involves the exercise of reverse engineer the application and try to recover parts of interest inside the source code. The idea is not to fully recover the source code, but attempt to retrieve parts from important functions of the applications, such as authentication, file upload features, communications and conectivity, etc.

Since there are a mirad of possible languagues and frameworks avaliable to develop desktop applications, and each of them have their specifics the tools that I generally use are direct dependent of the programming language used to construct the application, a couple of examples are:

**General applications**

* Ghidra
* radare2 + cutter
* IDA
* Binary Ninja
* Hopper (Linux/MacOS)
* CFFExplorer

**dotNET**

* dnSpy
* iLspy
* dotPeek

**Java/Android**

* jd-gui
* jadx
* jeb
* dex2jar
* Recaf

**NodeJS**

* asar

**Python**

* uncompyle6
* [decompile3](https://github.com/rocky/python-decompile3)

**Delphi**

* Interactive Delphi Reconstructor

As a rule of thumb every scripted language (ruby, python, perl) can be decompiled, so always google for "LANGUAGE decompilers" after triaging and see if you found a useful tool that is not listed.

In this phase what you are looking for is essentially:

* Hard-coded credentials/SSL certificates
* Connection endpoints (URLs, UNC paths, database local files and remote connections)
* Logic flaws and hidden funcionalities

Since my target application was a windows .exe I'm using a default windows 10 with the tools of [retoolkit](https://github.com/mentebinaria/retoolkit/releases/tag/2021c)  by [@Merces](https://twitter.com/mer0x36), and then installling the other tools as I need.

There is a bunch of how-tos on installing and configuring a virtual machine to do malware analysis, you can pick any and follow.

## Triage

First to identificate what language was used, which compiler/version and linker the app was built I like to use DIE (Detect It Easy), since it automagically reads the .rscr section of the PE and retrieve this information. Its usage is pretty simple, just drag and drop the binary into it and voila:

![](/images/die.png)

Another simple but useful tool to do the initial recon is ExeInfo:

![](/images/exeinfo.png)

**grep2win**

A good start is to hunt is look at the strings inside the binary. This will give you an idea of what the application does under the hood, what system calls are made, etc.

To do this we can use DIE, disassemblers like ghidra, IDA, etc. Interesting low hanging keywords to look for are:

* Credentials: `password`, `user`, `pwd`
* Connections: `url`, `http(s)`, `sql`, `smb`, `ftp`, `telnet`, `conn`, `proxy`, `address`
* Databases: `.sql`, `.fdb`, `.sqlite`

In ghidra you can use the script manager to search using regex, so for connection you could use something like `(https?|winrm|smb|ftp|telnet)?:\/\/.*` to find maybe more results.

## Dynamic analysis

Now here is where we do the heavy analysis. First of all, my tools of choice are:

* API Monitor
* Debugger x(86|64)dbg, Immunity debugger
* Procmon / Process Hacker
* Wireshark
* Burp Suite / Fiddler

Since the main objective here is to find vulnerabilities I tend to focus on flaws as:

* Analyze WinAPI calls to the classic DLL/EXE Hijacking
* Look for misconfiguration in permission on the folder structure where the binaries are installed
* Look for utilization of windows storage functionalities - Registry hives

So the main workflow is something like this:

1. Run API Monitor / Wireshark
2. Start program from inside API Monitor and watch the API calls flow.
3. Run regshot to create a dump of current registry, use all functionality on the app, then take another registry dump and do diffing.
4. Create a memory dump of the process and search for sensitive info
5. Check for permissions of folders and files using icalcs/get-acl

## Example vulnerable app

To demonstrate some vulnerabilities I'm developing a vulnerable app, so in the parts 2 I will cover how to do static and dynamic analysis and fuzzing, stay tuned.