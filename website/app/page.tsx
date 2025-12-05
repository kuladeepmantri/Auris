'use client'

import { useState, useEffect } from 'react'
import ThemeToggle from './components/ThemeToggle'
import AnimatedTerminal from './components/AnimatedTerminal'

export default function Home() {
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const handleScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  return (
    <div className="min-h-screen bg-[var(--bg)]">
      {/* Minimal fixed header */}
      <header className={`fixed top-0 w-full z-50 transition-all duration-300 ${
        scrolled ? 'bg-[var(--bg)]/95 backdrop-blur-sm border-b border-[var(--border)]' : ''
      }`}>
        <div className="max-w-4xl mx-auto px-6 h-14 flex items-center justify-between">
          <a href="#" className="font-medium text-[var(--text)]">Auris</a>
          <div className="flex items-center gap-4">
            <a 
              href="https://github.com/kuladeepmantri/Auris" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-sm text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors"
            >
              GitHub
            </a>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-6 pt-32 pb-24">
        {/* Hero - The Name */}
        <section className="mb-24">
          <p className="text-sm text-[var(--text-muted)] mb-4 tracking-wide">ARM64 Linux Security Toolkit</p>
          <h1 className="text-5xl sm:text-6xl font-light text-[var(--text)] mb-6 tracking-tight">
            Auris
          </h1>
          <p className="text-xl text-[var(--text-secondary)] leading-relaxed max-w-2xl">
            From the Latin word for <em>ear</em>—Auris listens to every syscall your processes make. 
            It hears what programs do, learns their behavior, and can either protect against anomalies 
            or exploit the same mechanisms for offensive security research.
          </p>
          <p className="text-lg text-[var(--text-muted)] mt-6">
            Version 2.0 · Dual-purpose: defense and offense
          </p>
        </section>

        {/* The Duality */}
        <section className="mb-24">
          <div className="grid md:grid-cols-2 gap-8">
            <div className="p-6 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
              <div className="text-sm font-medium text-blue-500 dark:text-blue-400 mb-3">Blue Team</div>
              <h3 className="text-lg font-medium text-[var(--text)] mb-3">Defensive Operations</h3>
              <p className="text-[var(--text-secondary)] text-sm leading-relaxed mb-4">
                Trace syscalls, build behavioral profiles, detect anomalies, enforce security policies. 
                Understand what normal looks like, then catch deviations.
              </p>
              <div className="text-xs text-[var(--text-muted)] font-mono">
                learn · profile · compare · policy · enforce
              </div>
            </div>
            <div className="p-6 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
              <div className="text-sm font-medium text-red-500 dark:text-red-400 mb-3">Red Team</div>
              <h3 className="text-lg font-medium text-[var(--text)] mb-3">Offensive Operations</h3>
              <p className="text-[var(--text-secondary)] text-sm leading-relaxed mb-4">
                Inject shellcode, find ROP gadgets, manipulate process memory. The same ptrace 
                infrastructure that enables monitoring also enables exploitation.
              </p>
              <div className="text-xs text-[var(--text-muted)] font-mono">
                inject list · shellcode · gadgets · dump
              </div>
            </div>
          </div>
        </section>

        {/* How It Works */}
        <section className="mb-24">
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">How It Works</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            Auris uses <code className="text-sm bg-[var(--bg-secondary)] px-1.5 py-0.5 rounded">ptrace</code>—the 
            same mechanism debuggers use. When attached to a process, the kernel notifies Auris before 
            every syscall. On ARM64, syscall numbers live in register x8, arguments in x0-x5.
          </p>
          
          <div className="p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-sm text-[var(--terminal-text)]">
            <pre className="overflow-x-auto">{`// The core loop
while (1) {
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    
    syscall_nr = regs.regs[8];  // x8 = syscall number
    arg0 = regs.regs[0];        // x0 = first argument
    
    // Record, analyze, or manipulate...
    
    ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
}`}</pre>
          </div>
        </section>

        {/* Defense: Learning Behavior */}
        <section className="mb-24">
          <div className="text-sm font-medium text-blue-500 dark:text-blue-400 mb-3">Defense</div>
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">Learning Normal Behavior</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            Run a program under Auris to capture its syscall trace. Then build a behavioral profile—a 
            statistical fingerprint of what the program normally does. Later, compare new executions 
            against this baseline to detect anomalies.
          </p>
          
          <AnimatedTerminal
            title="behavioral profiling"
            command="auris learn -- /bin/ls -la && auris profile -t trace-001"
            output={`[ptrace] Attached to process 2847
[trace] Intercepting syscalls...
  execve("/bin/ls", [...]) = 0
  openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY) = 3
  mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7fff...
  close(3) = 0
  ...

[trace] Captured 127 syscalls in 14.2ms
Trace ID: trace-001

[profile] Computing statistics...
[profile] Shannon entropy: 3.41 bits
[profile] Behavior: file_io=yes, network=no, children=no
Profile ID: profile-001`}
          />
        </section>

        {/* Defense: Anomaly Detection */}
        <section className="mb-24">
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">Detecting Anomalies</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            Once you have a baseline, Auris can compare new executions against it. Significant 
            deviations—new syscalls, unexpected file access, network activity where there was 
            none—trigger alerts or blocks.
          </p>
          
          <AnimatedTerminal
            title="anomaly detection"
            command="auris compare -p profile-001 -- ./suspicious_binary"
            output={`[compare] Loading baseline profile-001...
[compare] Tracing ./suspicious_binary...
[compare] Analyzing behavioral differences...

Comparison Result
=================
Similarity Score: 0.34 (ANOMALOUS)

New Syscalls Detected:
  + socket (not in baseline)
  + connect (not in baseline)
  + sendto (not in baseline)

Sensitive File Access:
  ! /etc/passwd (not in baseline)
  ! ~/.ssh/id_rsa (CRITICAL - not in baseline)

Verdict: SUSPICIOUS - network activity and credential access`}
          />
        </section>

        {/* Defense: Policy Enforcement */}
        <section className="mb-24">
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">Enforcing Policies</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            Generate security policies from profiles, then enforce them. In alert mode, violations 
            are logged. In block mode, the offending syscall is prevented and the process terminated.
          </p>
          
          <AnimatedTerminal
            title="policy enforcement"
            command="auris enforce -P policy-001 -m block -- ./untrusted"
            output={`[enforce] Loading policy policy-001...
[enforce] Mode: BLOCK (violations will terminate process)
[enforce] Tracing ./untrusted...

[enforce] VIOLATION: socket() not in allowed syscalls
[enforce] Action: BLOCKED
[enforce] Process terminated with SIGKILL

Enforcement Summary
===================
Syscalls allowed: 45
Syscalls blocked: 1
Result: Process terminated due to policy violation`}
          />
        </section>

        {/* Offense: The Other Side */}
        <section className="mb-24">
          <div className="text-sm font-medium text-red-500 dark:text-red-400 mb-3">Offense</div>
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">Process Injection</h2>
          
          <div className="p-4 mb-8 rounded-lg border border-yellow-500/30 bg-yellow-500/5">
            <p className="text-sm text-yellow-700 dark:text-yellow-300">
              For authorized security research and penetration testing only. Unauthorized use is illegal.
            </p>
          </div>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            The same ptrace calls that let Auris observe syscalls also let it write to process 
            memory and modify registers. This enables shellcode injection, ROP chain execution, 
            and other offensive techniques—useful for red team exercises and security research.
          </p>
          
          <AnimatedTerminal
            title="target discovery"
            command="auris inject list"
            output={`Injectable Processes (47 found):
PID      NAME             UID      PATH
---      ----             ---      ----
1842     nginx            www-data /usr/sbin/nginx
2103     python3          user     /usr/bin/python3
2847     node             user     /usr/bin/node
3201     sleep            user     /bin/sleep
...`}
          />
        </section>

        {/* Offense: Shellcode */}
        <section className="mb-24">
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">Shellcode Injection</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            Inject pre-built ARM64 shellcode into a running process. Auris attaches via ptrace, 
            saves the current state, writes shellcode to executable memory, redirects execution, 
            then optionally restores the original state.
          </p>
          
          <div className="mb-6 text-sm text-[var(--text-secondary)]">
            <span className="font-mono text-red-400">exec_sh</span> · 
            <span className="font-mono text-red-400 ml-2">reverse</span> · 
            <span className="font-mono text-red-400 ml-2">bind</span> · 
            <span className="font-mono text-red-400 ml-2">exec_cmd</span>
          </div>
          
          <AnimatedTerminal
            title="shellcode injection"
            command="auris inject shellcode -p 3201 -t exec_sh"
            output={`Shellcode: exec_sh
Description: Execute /bin/sh
Size: 76 bytes

Injecting into PID 3201...
[ptrace] Attached to process 3201 (sleep)
[inject] Saving registers...
[inject] Writing shellcode at 0x5555555551a0
[inject] Redirecting PC...
[inject] Executing...

Injection successful!
Return value: 0x0
Execution time: 1247 ns`}
          />
        </section>

        {/* Offense: ROP */}
        <section className="mb-24">
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">ROP Gadget Finder</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            When DEP/NX prevents code injection, Return-Oriented Programming chains existing code 
            snippets. Auris scans binaries for useful gadgets—instructions ending in RET that 
            load registers, make syscalls, or pivot the stack.
          </p>
          
          <AnimatedTerminal
            title="rop gadgets"
            command="auris inject gadgets -b /lib/aarch64-linux-gnu/libc.so.6"
            output={`Finding ROP gadgets in libc.so.6...
[rop] Scanning executable segments...
[rop] Found 25655 gadgets

0x00027430: svc #0 [SVC]
0x00027640: ret [RET]
0x00045678: ldr x0, [sp, #8]; ldp x29, x30, [sp], #16; ret [X0 RET]
0x00067890: mov x8, #221; svc #0 [SVC]
0x00089abc: add sp, sp, #64; ret [PIVOT RET]
...

Useful Gadgets Summary:
  Load X0: 0x45678
  Syscall: 0x67890
  Stack Pivot: 0x89abc`}
          />
        </section>

        {/* Memory Operations */}
        <section className="mb-24">
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">Memory Operations</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            Read and analyze process memory. Useful for understanding memory layout before 
            injection, extracting runtime data, or forensic analysis.
          </p>
          
          <AnimatedTerminal
            title="memory dump"
            command="auris inject dump -p 2847 -a 0x555555555000 -n 64"
            output={`[ptrace] Attached to process 2847
Memory dump at 0x555555555000 (64 bytes):

0000555555555000  7f 45 4c 46 02 01 01 00  |.ELF....|
0000555555555008  00 00 00 00 00 00 00 00  |........|
0000555555555010  03 00 b7 00 01 00 00 00  |........|
0000555555555018  00 10 00 00 00 00 00 00  |........|
0000555555555020  40 00 00 00 00 00 00 00  |@.......|
0000555555555028  c8 a2 01 00 00 00 00 00  |........|
0000555555555030  00 00 00 00 40 00 38 00  |....@.8.|
0000555555555038  0b 00 40 00 1e 00 1d 00  |..@.....|`}
          />
        </section>

        {/* Setup */}
        <section className="mb-24">
          <h2 className="text-2xl font-light text-[var(--text)] mb-6">Getting Started</h2>
          <p className="text-[var(--text-secondary)] leading-relaxed mb-8">
            Auris requires ARM64 Linux and CAP_SYS_PTRACE capability. Docker is the easiest way 
            to run it on any machine with ARM64 support.
          </p>
          
          <div className="p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-sm text-[var(--terminal-text)] mb-8">
            <pre className="overflow-x-auto">{`# Build
docker build --platform linux/arm64 -t auris .

# Run with ptrace capability
docker run --platform linux/arm64 \\
  --cap-add=SYS_PTRACE \\
  --security-opt seccomp=unconfined \\
  -it auris

# Inside container
./build/auris help
./build/auris learn -- /bin/ls
./build/auris inject list`}</pre>
          </div>
          
          <p className="text-[var(--text-secondary)] leading-relaxed mb-4">
            For native builds on ARM64 Linux:
          </p>
          
          <div className="p-5 rounded-lg border border-[var(--border)] bg-[var(--terminal-bg)] font-mono text-sm text-[var(--terminal-text)]">
            <pre className="overflow-x-auto">{`apt install build-essential cmake \\
  libcurl4-openssl-dev libssl-dev libjson-c-dev

mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)

sudo ./auris learn -- /bin/ls`}</pre>
          </div>
        </section>

        {/* Footer */}
        <footer className="pt-12 border-t border-[var(--border)]">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <span className="text-sm text-[var(--text)]">Auris</span>
              <span className="text-sm text-[var(--text-muted)]"> · </span>
              <a 
                href="https://github.com/kuladeepmantri" 
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-[var(--text-secondary)] hover:text-[var(--text)] transition-colors"
              >
                Kuladeep Mantri
              </a>
            </div>
            <div className="text-sm text-[var(--text-muted)]">
              MIT License · v2.0.0
            </div>
          </div>
        </footer>
      </main>
    </div>
  )
}
