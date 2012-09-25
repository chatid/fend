include "sys/types"

ffi.cdef [[
typedef __sig_atomic_t sig_atomic_t;

typedef __sigset_t sigset_t;
typedef union sigval
  {
    int sival_int;
    void *sival_ptr;
  } sigval_t;
typedef struct siginfo
  {
    int si_signo;
    int si_errno;
    int si_code;
    union
      {
 int _pad[((128 / sizeof (int)) - 4)];
 struct
   {
     __pid_t si_pid;
     __uid_t si_uid;
   } _kill;
 struct
   {
     int si_tid;
     int si_overrun;
     sigval_t si_sigval;
   } _timer;
 struct
   {
     __pid_t si_pid;
     __uid_t si_uid;
     sigval_t si_sigval;
   } _rt;
 struct
   {
     __pid_t si_pid;
     __uid_t si_uid;
     int si_status;
     __clock_t si_utime;
     __clock_t si_stime;
   } _sigchld;
 struct
   {
     void *si_addr;
   } _sigfault;
 struct
   {
     long int si_band;
     int si_fd;
   } _sigpoll;
      } _sifields;
  } siginfo_t;
enum
{
  SI_ASYNCNL = -60,
  SI_TKILL = -6,
  SI_SIGIO,
  SI_ASYNCIO,
  SI_MESGQ,
  SI_TIMER,
  SI_QUEUE,
  SI_USER,
  SI_KERNEL = 0x80
};
enum
{
  ILL_ILLOPC = 1,
  ILL_ILLOPN,
  ILL_ILLADR,
  ILL_ILLTRP,
  ILL_PRVOPC,
  ILL_PRVREG,
  ILL_COPROC,
  ILL_BADSTK
};
enum
{
  FPE_INTDIV = 1,
  FPE_INTOVF,
  FPE_FLTDIV,
  FPE_FLTOVF,
  FPE_FLTUND,
  FPE_FLTRES,
  FPE_FLTINV,
  FPE_FLTSUB
};
enum
{
  SEGV_MAPERR = 1,
  SEGV_ACCERR
};
enum
{
  BUS_ADRALN = 1,
  BUS_ADRERR,
  BUS_OBJERR
};
enum
{
  TRAP_BRKPT = 1,
  TRAP_TRACE
};
enum
{
  CLD_EXITED = 1,
  CLD_KILLED,
  CLD_DUMPED,
  CLD_TRAPPED,
  CLD_STOPPED,
  CLD_CONTINUED
};
enum
{
  POLL_IN = 1,
  POLL_OUT,
  POLL_MSG,
  POLL_ERR,
  POLL_PRI,
  POLL_HUP
};
typedef struct sigevent
  {
    sigval_t sigev_value;
    int sigev_signo;
    int sigev_notify;
    union
      {
 int _pad[((64 / sizeof (int)) - 4)];
 __pid_t _tid;
 struct
   {
     void (*_function) (sigval_t);
     void *_attribute;
   } _sigev_thread;
      } _sigev_un;
  } sigevent_t;
enum
{
  SIGEV_SIGNAL = 0,
  SIGEV_NONE,
  SIGEV_THREAD,
  SIGEV_THREAD_ID = 4
};
typedef void (*__sighandler_t) (int);
extern __sighandler_t __sysv_signal (int __sig, __sighandler_t __handler)
     __attribute__ ((__nothrow__ , __leaf__));

extern __sighandler_t signal (int __sig, __sighandler_t __handler)
     __attribute__ ((__nothrow__ , __leaf__));

extern int kill (__pid_t __pid, int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern int killpg (__pid_t __pgrp, int __sig) __attribute__ ((__nothrow__ , __leaf__));

extern int raise (int __sig) __attribute__ ((__nothrow__ , __leaf__));

extern __sighandler_t ssignal (int __sig, __sighandler_t __handler)
     __attribute__ ((__nothrow__ , __leaf__));
extern int gsignal (int __sig) __attribute__ ((__nothrow__ , __leaf__));
extern void psignal (int __sig, __const char *__s);
extern void psiginfo (__const siginfo_t *__pinfo, __const char *__s);
extern int __sigpause (int __sig_or_mask, int __is_sig);
extern int sigblock (int __mask) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
extern int sigsetmask (int __mask) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
extern int siggetmask (void) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
typedef __sighandler_t sig_t;
extern int sigemptyset (sigset_t *__set) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigfillset (sigset_t *__set) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigaddset (sigset_t *__set, int __signo) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigdelset (sigset_t *__set, int __signo) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigismember (__const sigset_t *__set, int __signo)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
struct sigaction
  {
    union
      {
 __sighandler_t sa_handler;
 void (*sa_sigaction) (int, siginfo_t *, void *);
      }
    __sigaction_handler;
    __sigset_t sa_mask;
    int sa_flags;
    void (*sa_restorer) (void);
  };
extern int sigprocmask (int __how, __const sigset_t *__restrict __set,
   sigset_t *__restrict __oset) __attribute__ ((__nothrow__ , __leaf__));
extern int sigsuspend (__const sigset_t *__set) __attribute__ ((__nonnull__ (1)));
extern int sigaction (int __sig, __const struct sigaction *__restrict __act,
        struct sigaction *__restrict __oact) __attribute__ ((__nothrow__ , __leaf__));
extern int sigpending (sigset_t *__set) __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__nonnull__ (1)));
extern int sigwait (__const sigset_t *__restrict __set, int *__restrict __sig)
     __attribute__ ((__nonnull__ (1, 2)));
extern int sigwaitinfo (__const sigset_t *__restrict __set,
   siginfo_t *__restrict __info) __attribute__ ((__nonnull__ (1)));
extern int sigtimedwait (__const sigset_t *__restrict __set,
    siginfo_t *__restrict __info,
    __const struct timespec *__restrict __timeout)
     __attribute__ ((__nonnull__ (1)));
extern int sigqueue (__pid_t __pid, int __sig, __const union sigval __val)
     __attribute__ ((__nothrow__ , __leaf__));
extern __const char *__const _sys_siglist[65];
extern __const char *__const sys_siglist[65];
struct sigvec
  {
    __sighandler_t sv_handler;
    int sv_mask;
    int sv_flags;
  };
extern int sigvec (int __sig, __const struct sigvec *__vec,
     struct sigvec *__ovec) __attribute__ ((__nothrow__ , __leaf__));
struct _fpreg
{
  unsigned short significand[4];
  unsigned short exponent;
};
struct _fpxreg
{
  unsigned short significand[4];
  unsigned short exponent;
  unsigned short padding[3];
};
struct _xmmreg
{
  __uint32_t element[4];
};
struct _fpstate
{
  __uint16_t cwd;
  __uint16_t swd;
  __uint16_t ftw;
  __uint16_t fop;
  __uint64_t rip;
  __uint64_t rdp;
  __uint32_t mxcsr;
  __uint32_t mxcr_mask;
  struct _fpxreg _st[8];
  struct _xmmreg _xmm[16];
  __uint32_t padding[24];
};
struct sigcontext
{
  unsigned long r8;
  unsigned long r9;
  unsigned long r10;
  unsigned long r11;
  unsigned long r12;
  unsigned long r13;
  unsigned long r14;
  unsigned long r15;
  unsigned long rdi;
  unsigned long rsi;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long rdx;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rsp;
  unsigned long rip;
  unsigned long eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  unsigned long err;
  unsigned long trapno;
  unsigned long oldmask;
  unsigned long cr2;
  struct _fpstate * fpstate;
  unsigned long __reserved1 [8];
};
extern int sigreturn (struct sigcontext *__scp) __attribute__ ((__nothrow__ , __leaf__));
typedef long unsigned int size_t;
extern int siginterrupt (int __sig, int __interrupt) __attribute__ ((__nothrow__ , __leaf__));
struct sigstack
  {
    void *ss_sp;
    int ss_onstack;
  };
enum
{
  SS_ONSTACK = 1,
  SS_DISABLE
};
typedef struct sigaltstack
  {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
  } stack_t;
typedef long int greg_t;
typedef greg_t gregset_t[23];
struct _libc_fpxreg
{
  unsigned short int significand[4];
  unsigned short int exponent;
  unsigned short int padding[3];
};
struct _libc_xmmreg
{
  __uint32_t element[4];
};
struct _libc_fpstate
{
  __uint16_t cwd;
  __uint16_t swd;
  __uint16_t ftw;
  __uint16_t fop;
  __uint64_t rip;
  __uint64_t rdp;
  __uint32_t mxcsr;
  __uint32_t mxcr_mask;
  struct _libc_fpxreg _st[8];
  struct _libc_xmmreg _xmm[16];
  __uint32_t padding[24];
};
typedef struct _libc_fpstate *fpregset_t;
typedef struct
  {
    gregset_t gregs;
    fpregset_t fpregs;
    unsigned long __reserved1 [8];
} mcontext_t;
typedef struct ucontext
  {
    unsigned long int uc_flags;
    struct ucontext *uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    __sigset_t uc_sigmask;
    struct _libc_fpstate __fpregs_mem;
  } ucontext_t;
extern int sigstack (struct sigstack *__ss, struct sigstack *__oss)
     __attribute__ ((__nothrow__ , __leaf__)) __attribute__ ((__deprecated__));
extern int sigaltstack (__const struct sigaltstack *__restrict __ss,
   struct sigaltstack *__restrict __oss) __attribute__ ((__nothrow__ , __leaf__));
typedef unsigned long int pthread_t;
typedef union
{
  char __size[56];
  long int __align;
} pthread_attr_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_mutexattr_t;
typedef union
{
  struct
  {
    int __lock;
    unsigned int __futex;
    __extension__ unsigned long long int __total_seq;
    __extension__ unsigned long long int __wakeup_seq;
    __extension__ unsigned long long int __woken_seq;
    void *__mutex;
    unsigned int __nwaiters;
    unsigned int __broadcast_seq;
  } __data;
  char __size[48];
  __extension__ long long int __align;
} pthread_cond_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_condattr_t;
typedef unsigned int pthread_key_t;
typedef int pthread_once_t;
typedef union
{
  struct
  {
    int __lock;
    unsigned int __nr_readers;
    unsigned int __readers_wakeup;
    unsigned int __writer_wakeup;
    unsigned int __nr_readers_queued;
    unsigned int __nr_writers_queued;
    int __writer;
    int __shared;
    unsigned long int __pad1;
    unsigned long int __pad2;
    unsigned int __flags;
  } __data;
  char __size[56];
  long int __align;
} pthread_rwlock_t;
typedef union
{
  char __size[8];
  long int __align;
} pthread_rwlockattr_t;
typedef volatile int pthread_spinlock_t;
typedef union
{
  char __size[32];
  long int __align;
} pthread_barrier_t;
typedef union
{
  char __size[4];
  int __align;
} pthread_barrierattr_t;
extern int pthread_sigmask (int __how,
       __const __sigset_t *__restrict __newmask,
       __sigset_t *__restrict __oldmask)__attribute__ ((__nothrow__ , __leaf__));
extern int pthread_kill (pthread_t __threadid, int __signo) __attribute__ ((__nothrow__ , __leaf__));
extern int __libc_current_sigrtmin (void) __attribute__ ((__nothrow__ , __leaf__));
extern int __libc_current_sigrtmax (void) __attribute__ ((__nothrow__ , __leaf__));
]]

SIGHUP = 1 --  Hangup (POSIX).
SIGINT = 2 --  Interrupt (ANSI).
SIGQUIT = 3 --  Quit (POSIX).
SIGILL = 4 --  Illegal instruction (ANSI).
SIGTRAP = 5 --  Trace trap (POSIX).
SIGABRT = 6 --  Abort (ANSI).
SIGIOT = 6 --  IOT trap (4.2 BSD).
SIGBUS = 7 --  BUS error (4.2 BSD).
SIGFPE = 8 --  Floating-point exception (ANSI).
SIGKILL = 9 --  Kill, unblockable (POSIX).
SIGUSR1 = 10 --  User-defined signal 1 (POSIX).
SIGSEGV = 11 --  Segmentation violation (ANSI).
SIGUSR2 = 12 --  User-defined signal 2 (POSIX).
SIGPIPE = 13 --  Broken pipe (POSIX).
SIGALRM = 14 --  Alarm clock (POSIX).
SIGTERM = 15 --  Termination (ANSI).
SIGSTKFLT = 16 --  Stack fault.
SIGCHLD = 17 --  Child status has changed (POSIX).
SIGCLD = SIGCHLD --  Same as SIGCHLD (System V).
SIGCONT = 18 --  Continue (POSIX).
SIGSTOP = 19 --  Stop, unblockable (POSIX).
SIGTSTP = 20 --  Keyboard stop (POSIX).
SIGTTIN = 21 --  Background read from tty (POSIX).
SIGTTOU = 22 --  Background write to tty (POSIX).
SIGURG = 23 --  Urgent condition on socket (4.2 BSD).
SIGXCPU = 24 --  CPU limit exceeded (4.2 BSD).
SIGXFSZ = 25 --  File size limit exceeded (4.2 BSD).
SIGVTALRM = 26 --  Virtual alarm clock (4.2 BSD).
SIGPROF = 27 --  Profiling alarm clock (4.2 BSD).
SIGWINCH = 28 --  Window size change (4.3 BSD, Sun).
SIGIO = 29 --  I/O now possible (4.2 BSD).
SIGPOLL = SIGIO --  Pollable event occurred (System V).
SIGPWR = 30 --  Power failure restart (System V).
SIGSYS = 31 --  Bad system call.
SIGUNUSED = 31

_NSIG = 65 -- Biggest signal number + 1 (including real-time signals).

SA_NOCLDSTOP = 1 -- Don't send SIGCHLD when children stop.
SA_NOCLDWAIT = 2 -- Don't create zombie on child death.
SA_SIGINFO = 4 -- Invoke signal-catching function with three arguments instead of one.
SA_ONSTACK = 0x08000000 -- Use signal stack by using `sa_restorer'.
SA_RESTART = 0x10000000 -- Restart syscall on signal return.
SA_NODEFER = 0x40000000 -- Don't automatically block the signal when its handler is being executed.
SA_RESETHAND = 0x80000000 --  Reset to SIG_DFL on entry to handler.
SA_INTERRUPT = 0x20000000 --  Historical no-op.

SA_NOMASK = SA_NODEFER
SA_ONESHOT = SA_RESETHAND
SA_STACK = SA_ONSTACK

SIG_BLOCK = 0 --  Block signals.
SIG_UNBLOCK = 1 --  Unblock signals.
SIG_SETMASK = 2 --  Set the set of blocked signals.
