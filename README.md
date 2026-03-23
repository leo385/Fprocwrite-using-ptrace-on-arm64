# Fprocwrite-using-ptrace-on-arm64
Modification program's memory using ptrace unix built-in tool in C.

This version is an alternative to the version done by using python.
For more information about this program go to the reference link:<br> https://github.com/leo385/Procwrite-on-arm64

In this version, I have used some C unix built-in libraries:
<ul>
<li>-> stdio.h, to use popen() due to read output from pip stream:</li>
       <li>-> popen() helped me with getting process's PID and get base address of memory where main is being executed.</li>
<li>-> stdint.h for using 32-bit integer type for memory addresses on ARM64.</li>
<li>-> stdlib.h for converting string to unsigned long long.</li>
<li>-> errno.h for handling input errors.</li>
<li>-> sys/ptrace.h to use ptrace function due to observing the other process's memory.</li>
<li>-> sys/wait.h to use waitpid to wait for attaching correct PID, before we use PTRACE_PEEKTEXT.</li>
<li>-> sched.h to use pid_t type needed for ptrace methods.</li>
<li>-> string.h to use memcpy.</li>
<li>-> inttypes.h to save hexadecimal address in buffer array.</li>
</ul>

<h1>Thank you for reading this laboratory knowledge:</h1>
I was basing on knowledge from the book "Practical Reverse Engineering - Gynvael Coldwind".
