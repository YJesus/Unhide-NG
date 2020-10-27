**-Unhide-NG**

IMPORTANT NOTE : 
Unhide-NG is not (yet) the updated version of Unhide.
Unhide-NG is a lab project that in an indeterminate future may replace Unhide.

               http://www.unhide-forensics.info

Unhide is a forensic tool to find hidden processes and TCP/UDP ports by rootkits / LKMs
or by another hiding technique.

Authors: Yago Jesus, Patrick Gouin & David Reguera Garcia aka Dreg

* WARNING: if unhide process crash you can have a rootkit in the system with some bugs

new official release: 

unhide_20200120
 
https://github.com/YJesus/Unhide/releases

// Unhide (unhide-linux or unhide-posix)
// -------------------------------------

Detecting hidden processes. Implements some techniques:

1- Compare /proc vs /bin/ps output

2- Compare info gathered from /bin/ps with info gathered by walking thru the procfs. ONLY for unhide-linux version

3- Compare info gathered from /bin/ps with info gathered from syscalls (syscall scanning).

4- Full PIDs space ocupation (PIDs bruteforcing). ONLY for unhide-linux version

5- Compare /bin/ps output vs /proc, procfs walking and syscall. ONLY for unhide-linux version
   Reverse search, verify that all thread seen by ps are also seen in the kernel.

6- Quick compare /proc, procfs walking and syscall vs /bin/ps output. ONLY for unhide-linux version
  It's about 20 times faster than tests 1+2+3 but maybe give more false positives.
  
7- Low level stuff, ex: assembly direct calls vs API calls. ONLY for unhide-linux version

      --altsysinfo           use alternate sysinfo test in meta-test
  -l, --logfile              log result into unhide-linux.log file
      --morecheck            more checks (available only with procfs,
                             checkopendir & checkchdir commands
  -v, --verbose              verbose
      --brute                bruteforce the all process IDs
      --brutedoublecheck     bruteforce the all process IDs with double check
      --low                  assembly direct calls vs API calls, this option
                             only works in dynamic form, use unhide-linux-dyn
      --proc                 compare /proc with the output of /bin/ps.
      --procall              combinates --proc and --procfs
      --procfs               compare information gathered from /bin/ps with
                             information gathered by walking in the procfs.
                             With --morecheck option, this test makes more
                             checks
      --quick                combines the --proc, --procfs and --sys in a quick
                             way. It's about 20 times faster but may give more
                             false positives
      --reverse              Verify that all threads seen by ps are also seen
                             in procfs and by system calls
      --sys                  compare information gathered from /bin/ps with
                             information gathered from system calls
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version


// Unhide-TCP
// ----------

Identify TCP/UDP ports that are listening but not listed in sbin/ss or /bin/netstat.
It use two methods: 
- brute force of all TCP/UDP ports availables and compare with SS/netstat output.
- probe of all TCP/UDP ports not reported by netstat.

  -f, --show-fuser           show fuser output for hidden ports
  -l, --logfile              log result into unhide-tcp.log file
  -n, --use-netstat          use netstat instead of ss
  -o, --show-lsof            show lsof output for hidden ports
  -s, --use-quickver         use very quick version for server with lot of
                             opened ports
  -v, --verbose              verbose
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

// Unhide-gids
// -----------

A lot of rootkits uses a MAGIC GID (a random GID generated) to hide processes and files. 
This tool find rootkits bruteforcing all GIDs possible in the system.

unhide-gids should be your last option. it can take many hours/days. but this is the only 
one that does not need a hidden process running to detect a rootkit.

Processes: Full GIDs process occupation (processes GID bruteforcing)

Files: Full GIDs file occupation (files GID bruteforcing)

It also can detect some rootkits safe-guards and strange things in the hooked code.

      --files-gids-readdir   bruteforce files GIDs via readdir, very slow
      --files-gids-stat      bruteforce files GIDs via stat
  -l, --logfile              log result into unhide-gids.log file
      --max-gid[=COUNT]      max GID
      --min-gid[=COUNT]      min GID
      --processes-gids-jail  bruteforce processes GIDs and detected setgid jail

      --processes-gids-readdir   bruteforce processes GIDs via readdir, very
                             slow
      --processes-gids-stat  bruteforce processes GIDs via stat
  -v, --verbose              verbose
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version


Its possible combine args of same type ex: 
./unhide-gids --processes-gids-jail --processes-gids-stat


// Unhide_rb
// ---------

It's a back port in C language of the ruby unhide.rb
As the original unhide.rb, it is roughly equivalent to "unhide-linux quick reverse" :
- it makes three tests less (kill, opendir and chdir),
- it only run /bin/ps once at start and once for the double check,
- also, its tests are less accurate (e.g.. testing return value instead of errno),
- processes are only identified by their exe link (unhide-linux also use cmdline and
  "sleeping kernel process" name),
- there's little protection against failures (failed fopen or popen by example),
- there's no logging capability.
It is very quick, about 80 times quicker than "unhide-linux quick reverse"


// Files
// -----

unhide-linux.c      -- Hidden processes, for Linux >= 2.6
unhide-linux.h

unhide-gids.c       -- GIDs bruteforce

unhide-tcp.c        -- Hidden TCP/UDP Ports
unhide-tcp-fast.c
unhide-tcp.h

unhide-output.c     -- Common routines of unhide tools
unhide-output.h

unhide_rb.c         -- C port of unhide.rb (a very light version of unhide-linux in ruby)

unhide-posix.c      -- Hidden processes, for generic Unix systems (*BSD, Solaris, linux 2.2 / 2.4)
                       It doesn't implement PIDs brute forcing check yet. Needs more testing
                       Warning : This version is somewhat outdated and may generate false positive.
                                 Prefer unhide-linux.c if you can use it.

changelog           -- As the name implied log of the change to unhide

COPYING             -- License file, GNU GPL V3

README.txt          -- This file

sanity.sh           -- unhide-linux testsuite file

TODO                -- Evolutions to do (any volunteers ?)

man/unhide.8        -- English man page of unhide

man/unhide-tcp.8    -- English man page of unhide-tcp

// Compiling
// ---------

If you ARE using a Linux kernel >= 2.6
      gcc -Wall -O2 --static -pthread unhide-linux*.c unhide-output.c -o unhide-linux
      gcc -Wall -O2 -pthread unhide-linux*.c unhide-output.c -o unhide-linux-dyn
      gcc unhide-gids.c unhide-output.c -o unhide-gids 
      gcc -Wall -O2 --static unhide_rb.c -o unhide_rb
      gcc -Wall -O2 --static unhide-tcp.c unhide-tcp-fast.c unhide-output.c -o unhide-tcp
      ln -s unhide unhide-linux
      ln -s unhide-dyn unhide-linux-dyn

Else (Linux < 2.6, *BSD, Solaris and other Unice)
      gcc --static unhide-posix.c -o unhide-posix
      ln -s unhide unhide-posix

// Using
// -----
You MUST be root to use unhide-linux, unhide-gids and unhide-tcp.

Examples:
 # ./unhide-linux --brute --procall 
 # ./unhide_rb
 # ./unhide-gids --files-gids-stat --files-gids-readdir
 # ./unhide-tcp --show-fuser --show-lsof --logfile
 # ./unhide-linux-dyn --low 
 
 (--low option only works in dynamic form, use unhide-linux-dyn, for others options use static form)
 
 	 
// Anti-unhide prevention
// -----------------------
Some rootkits detects unhide checking its name. Just copy the original executable with a random name, example:

# cp unhide $RANDOM
# cp unhide-gids $RANDOM
# cp unhide-linux-dyn $RANDOM
# ls
        13313  19251  19384  unhide  unhide-gids  unhide-linux-dyn

// License
// -------

GPL V.3 (http://www.gnu.org/licenses/gpl-3.0.html)

// Greets
// ------

A. Ramos (aramosf@unsec.net) for some regexps

unspawn (unspawn@rootshell.be) CentOS support

Martin Bowers (Martin.Bowers@freescale.com) CentOS support

Lorenzo Martinez (lorenzo@lorenzomartinez.homeip.net) Some ideas to improve and betatesting

Francois Marier (francois@debian.org) Author of the man pages and Debian support

Johan Walles (johan.walles@gmail.com) Find and fix a very nasty race condition bug

Jan Iven (jan.iven@cern.ch) Because of his great improvements, new tests and bugfixing

P. Gouin (patrick-g@users.sourceforge.net) Because of his incredible work fixing bugs and improving the performance

François Boisson for his idea of a double check in brute test

Leandro Lucarella (leandro.lucarella@sociomantic.com) for the fast scan method and his factorization work for unhide-tcp
