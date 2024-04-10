// This file is part of the mkcheck project.
// Licensing information can be found in the LICENSE file.
// (C) 2017 Nandor Licker. All rights reserved.

#include "syscall.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "proc.h"
#include "trace.h"
#include "util.h"



// -----------------------------------------------------------------------------
static void sys_read(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddInput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_write(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddOutput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_open(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));
  const uint64_t flags = args[1];
  const int fd = args.Return;

  if (args.Return >= 0) {
    proc->MapFd(fd, path);
    proc->SetCloseExec(fd, flags & O_CLOEXEC);
  }
}

// -----------------------------------------------------------------------------
static void sys_close(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->CloseFd(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_stat(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));
  if (args.Return >= 0) {
    proc->AddTouched(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_fstat(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddTouched(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_lstat(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));

  if (args.Return >= 0) {
    proc->AddTouched(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_mmap(Process *proc, const Args &args)
{
  const int prot = args[2];
  const int flags = args[3];
  const int fd = args[4];

  if (args.Return != MAP_ANON && fd != -1) {
    // Writes are only carried out to the file in shared, writable mappings.
    if ((flags & MAP_SHARED) && (prot & PROT_WRITE)) {
      proc->AddOutput(fd);
    } else {
      proc->AddInput(fd);
    }
  }
}

// -----------------------------------------------------------------------------
static void sys_pread64(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddInput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_readv(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddInput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_writev(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddInput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_access(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));

  if (args.Return >= 0) {
    proc->AddTouched(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_pipe(Process *proc, const Args &args)
{
  int fds[2];
  ReadBuffer(args.PID, fds, args[0], 2 * sizeof(int));
  if (args.Return >= 0) {
    proc->Pipe(fds[0], fds[1]);
  }
}

// -----------------------------------------------------------------------------
static void sys_dup(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->DupFd(args[0], args.Return);
  }
}

// -----------------------------------------------------------------------------
static void sys_dup2(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->DupFd(args[0], args.Return);
  }
}

// -----------------------------------------------------------------------------
static void sys_socket(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->MapFd(args.Return, "/proc/network");
  }
}

// -----------------------------------------------------------------------------
static void sys_fcntl(Process *proc, const Args &args)
{
  const int fd = args[0];
  const int cmd = args[1];

  if (args.Return >= 0) {
    switch (cmd) {
      case F_DUPFD: {
        proc->DupFd(args[0], args.Return);
        break;
      }
      case F_DUPFD_CLOEXEC: {
        proc->DupFd(args[0], args.Return);
        proc->SetCloseExec(args.Return, false);
        break;
      }
      case F_SETFD: {
        const int arg = args[2];
        proc->SetCloseExec(fd, arg & FD_CLOEXEC);
        break;
      }
      case F_GETFD:
      case F_GETFL:
      case F_SETFL: {
        break;
      }
      case F_GETLK:
      case F_SETLK:
      case F_SETLKW: {
        break;
      }
      case F_OFD_GETLK:
      case F_OFD_SETLK:
      case F_OFD_SETLKW: {
        break;
      }
      case F_SETPIPE_SZ:
      case F_GETPIPE_SZ: {
        break;
      }
      default: {
        throw std::runtime_error(
            "Unknown fnctl (cmd = " + std::to_string(cmd) + ")"
        );
      }
    }
  }
}

// -----------------------------------------------------------------------------
static void sys_truncate(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));
    proc->AddOutput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_ftruncate(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddOutput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_getdents(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddInput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_chdir(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));

  if (args.Return >= 0) {
    proc->SetCwd(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_fchdir(Process *proc, const Args &args)
{
  const int fd = args[0];
  if (args.Return >= 0) {
    proc->SetCwd(proc->GetFd(fd));
  }
}

// -----------------------------------------------------------------------------
static void sys_rename(Process *proc, const Args &args)
{
  const fs::path src = proc->Normalise(ReadString(args.PID, args[0]));
  const fs::path dst = proc->Normalise(ReadString(args.PID, args[1]));

  if (args.Return >= 0) {
    proc->Rename(src, dst);
  }
}

// -----------------------------------------------------------------------------
static void sys_mkdir(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));

  if (args.Return >= 0) {
    proc->AddOutput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_rmdir(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));

  if (args.Return >= 0) {
    proc->Remove(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_link(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    const fs::path srcRel = ReadString(args.PID, args[0]);
    const fs::path dstRel = ReadString(args.PID, args[1]);

    const fs::path src = proc->Normalise(srcRel);
    const fs::path dstParent = proc->Normalise(dstRel.parent_path());

    proc->Link(src, dstParent / dstRel.filename());
  }
}

// -----------------------------------------------------------------------------
static void sys_creat(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));
  const uint64_t flags = args[1];
  
  if (args.Return >= 0) {
    const int fd = args.Return;
    proc->MapFd(fd, path);
    proc->SetCloseExec(fd, flags & O_CLOEXEC);
  }
}

// -----------------------------------------------------------------------------
static void sys_unlink(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));

  if (args.Return >= 0) {
    proc->Remove(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_symlink(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    const fs::path src = ReadString(args.PID, args[0]);
    const fs::path dst = ReadString(args.PID, args[1]);

    const fs::path parent = proc->Normalise(dst.parent_path());
    const fs::path srcPath = proc->Normalise(src, parent);
    const fs::path dstPath = parent / dst.filename();

    // configure seems to create links pointing to themselves, which we ignore.
    if (srcPath != dstPath) {
      proc->Link(srcPath, dstPath);
    }
  }
}
// // -----------------------------------------------------------------------------
// static void sys_symlinkat1(Process *proc, const Args &args)
// {
//   if (args.Return >= 0) {
//     const fs::path src = ReadString(args.PID, args[0]);
//     const int dirfd = args[1];
//     const fs::path dst = ReadString(args.PID, args[2]);

//     const fs::path parent = proc->Normalise(dirfd, dst.parent_path());
//     const fs::path srcPath = proc->Normalise(src, parent);
//     const fs::path dstPath = parent / dst.filename();

//     // configure seems to create links pointing to themselves, which we ignore.
//     if (srcPath != dstPath) {
//       proc->Link(srcPath, dstPath);
//     }
//   }
// }

// -----------------------------------------------------------------------------
static void sys_symlinkat(Process *proc, const Args &args)
{
  const int newdirfd = args[1];
  const fs::path src = ReadString(args.PID, args[0]);
  const fs::path dst = ReadString(args.PID, args[2]);

  if (args.Return >= 0) {
    const fs::path parent = proc->Normalise(newdirfd, dst.parent_path());
    const fs::path srcPath = proc->Normalise(src, parent);
    const fs::path dstPath = parent / dst.filename();

    // configure seems to create links pointing to themselves, which we ignore.
    if (srcPath != dstPath) {
      proc->Link(srcPath, dstPath);
    }
  }
}

// -----------------------------------------------------------------------------
static void sys_readlink(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));
  if (args.Return >= 0) {
    proc->AddInput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_utime(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddOutput(proc->Normalise(ReadString(args.PID, args[0])));
  }
}

// -----------------------------------------------------------------------------
static void sys_linkat(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    const fs::path srcRel = ReadString(args.PID, args[1]);
    const fs::path dstRel = ReadString(args.PID, args[3]);

    const fs::path src = proc->Normalise(args[0], srcRel);
    const fs::path dstParent = proc->Normalise(args[2], dstRel.parent_path());

    proc->Link(src, dstParent / dstRel.filename());
  }
}

// -----------------------------------------------------------------------------
static void sys_fsetxattr(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddOutput(proc->GetFd(args[0]));
  }
}

// -----------------------------------------------------------------------------
static void sys_getxattr(Process *proc, const Args &args)
{
  const fs::path path = ReadString(args.PID, args[0]);
  const fs::path parent = proc->Normalise(path.parent_path());
  if (args.Return >= 0) {
      proc->AddInput(parent / path.filename());
  }
}

// -----------------------------------------------------------------------------
static void sys_lgetxattr(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));
  if (args.Return >= 0) {
      proc->AddInput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_llistxattr(Process *proc, const Args &args)
{
  const fs::path path = proc->Normalise(ReadString(args.PID, args[0]));
  if (args.Return >= 0) {
      proc->AddInput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_flistxattr(Process *proc, const Args &args)
{
  throw std::runtime_error("not implemented");
}


// -----------------------------------------------------------------------------
static void sys_epoll_create(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->MapFd(args.Return, "/proc/" + std::to_string(args.PID) + "/epoll");
  }
}

// -----------------------------------------------------------------------------
static void sys_getdents64(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddInput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_openat(Process *proc, const Args &args)
{
  const int dirfd = args[0];
  const fs::path path = proc->Normalise(dirfd, ReadString(args.PID, args[1]));
  const uint64_t flags = args[2];
  if (args.Return >= 0) {
    const int fd = args.Return;
    proc->MapFd(fd, path);
    proc->SetCloseExec(fd, flags & O_CLOEXEC);
  }
}

// -----------------------------------------------------------------------------
static void sys_mkdirat(Process *proc, const Args &args)
{
  const int dirfd = args[0];
  const fs::path path = proc->Normalise(dirfd, ReadString(args.PID, args[1]));

  if (args.Return >= 0) {
    proc->AddOutput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_newfstatat(Process *proc, const Args &args)
{
  const int dirfd = args[0];
  const fs::path path = proc->Normalise(dirfd, ReadString(args.PID, args[1]));

  if (args.Return >= 0) {
    proc->AddTouched(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_renameat(Process *proc, const Args &args)
{
  const int odirfd = args[0];
  const fs::path opath = proc->Normalise(odirfd, ReadString(args.PID, args[1]));
  const int ndirfd = args[2];
  const fs::path npath = proc->Normalise(ndirfd, ReadString(args.PID, args[3]));

  if (args.Return >= 0) {
    proc->Rename(opath, npath);
  }
}

// -----------------------------------------------------------------------------
static void sys_unlinkat(Process *proc, const Args &args)
{
  const int fd = args[0];
  const fs::path path = proc->Normalise(fd, ReadString(args.PID, args[1]));

  if (args.Return >= 0) {
    proc->Remove(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_readlinkat(Process *proc, const Args &args)
{
  const int fd = args[0];
  const fs::path path = proc->Normalise(fd, ReadString(args.PID, args[1]));
  if (args.Return >= 0) {
    proc->AddInput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_faccessat(Process *proc, const Args &args)
{
  const int fd = args[0];
  const fs::path path = proc->Normalise(fd, ReadString(args.PID, args[1]));

  if (args.Return >= 0) {
    proc->AddInput(path);
  }
}

// -----------------------------------------------------------------------------
static void sys_splice(Process *proc, const Args &args)
{
  throw std::runtime_error("not implemented");
}

// -----------------------------------------------------------------------------
static void sys_fallocate(Process *proc, const Args &args)
{
  if (args.Return >= 0) {
    proc->AddOutput(args[0]);
  }
}

// -----------------------------------------------------------------------------
static void sys_eventfd2(Process *proc, const Args &args)
{
  const int flags = args[1];
  const int fd = args.Return;

  if (args.Return >= 0) {
    proc->MapFd(fd, "/proc/" + std::to_string(args.PID) + "/event");
    proc->SetCloseExec(fd, flags & EFD_CLOEXEC);
  }
}

// -----------------------------------------------------------------------------
static void sys_dup3(Process *proc, const Args &args)
{
  const int oldfd = args[0];
  const int newfd = args[1];
  const int flags = args[2];

  if (args.Return >= 0) {
    proc->DupFd(oldfd, newfd);
  }

  proc->SetCloseExec(newfd, flags & O_CLOEXEC);
}

// -----------------------------------------------------------------------------
static void sys_pipe2(Process *proc, const Args &args)
{
  int fds[2];
  ReadBuffer(args.PID, fds, args[0], 2 * sizeof(int));
  const int flags = args[1];

  if (args.Return >= 0) {
    proc->Pipe(fds[0], fds[1]);

    const bool closeExec = flags & O_CLOEXEC;
    proc->SetCloseExec(fds[0], closeExec);
    proc->SetCloseExec(fds[1], closeExec);
  }
}

// -----------------------------------------------------------------------------
static void sys_ignore(Process *proc, const Args &args)
{
}

typedef void (*HandlerFn) (Process *proc, const Args &args);

static const HandlerFn kHandlers[] =
{
  /* 0x000 */ [SYS_read              ] = sys_read,
  /* 0x001 */ [SYS_write             ] = sys_write,
  /* 0x002 */ [SYS_open              ] = sys_open,
  /* 0x003 */ [SYS_close             ] = sys_close,
  /* 0x004 */ [SYS_stat              ] = sys_stat,
  /* 0x005 */ [SYS_fstat             ] = sys_fstat,
  /* 0x006 */ [SYS_lstat             ] = sys_lstat,
  /* 0x007 */ [SYS_poll              ] = sys_ignore,
  /* 0x008 */ [SYS_lseek             ] = sys_ignore,
  /* 0x009 */ [SYS_mmap              ] = sys_mmap,
  /* 0x00A */ [SYS_mprotect          ] = sys_ignore,
  /* 0x00B */ [SYS_munmap            ] = sys_ignore,
  /* 0x00C */ [SYS_brk               ] = sys_ignore,
  /* 0x00D */ [SYS_rt_sigaction      ] = sys_ignore,
  /* 0x00E */ [SYS_rt_sigprocmask    ] = sys_ignore,
  /* 0x00F */ [SYS_rt_sigreturn      ] = sys_ignore,
  /* 0x010 */ [SYS_ioctl             ] = sys_ignore,
  /* 0x011 */ [SYS_pread64           ] = sys_pread64,
  /* 0x012 */ [SYS_pwrite64          ] = sys_ignore,
  /* 0x013 */ [SYS_readv             ] = sys_readv,
  /* 0x014 */ [SYS_writev            ] = sys_writev,
  /* 0x015 */ [SYS_access            ] = sys_access,
  /* 0x016 */ [SYS_pipe              ] = sys_pipe,
  /* 0x017 */ [SYS_select            ] = sys_ignore,
  /* 0x018 */ [SYS_sched_yield       ] = sys_ignore,
  /* 0x019 */ [SYS_mremap            ] = sys_ignore,
  /* 0x01a */ [SYS_msync             ] = sys_ignore,
  /* 0x01b */ [SYS_mincore           ] = sys_ignore,
  /* 0x01c */ [SYS_madvise           ] = sys_ignore,
  /* 0x01d */ [SYS_shmget            ] = sys_ignore,
  /* 0x01e */ [SYS_shmat             ] = sys_ignore,
  /* 0x01f */ [SYS_shmctl            ] = sys_ignore,
  /* 0x020 */ [SYS_dup               ] = sys_dup,
  /* 0x021 */ [SYS_dup2              ] = sys_dup2,
  /* 0x022 */ [SYS_pause             ] = sys_ignore,
  /* 0x023 */ [SYS_nanosleep         ] = sys_ignore,
  /* 0x024 */ [SYS_getitimer         ] = sys_ignore,
  /* 0x025 */ [SYS_alarm             ] = sys_ignore,
  /* 0x026 */ [SYS_setitimer         ] = sys_ignore,
  /* 0x027 */ [SYS_getpid            ] = sys_ignore,
  /* 0x028 */ [SYS_sendfile          ] = sys_ignore,
  /* 0x029 */ [SYS_socket            ] = sys_socket,
  /* 0x02A */ [SYS_connect           ] = sys_ignore,
  /* 0x02B */ [SYS_accept            ] = sys_ignore,
  /* 0x02C */ [SYS_sendto            ] = sys_ignore,
  /* 0x02D */ [SYS_recvfrom          ] = sys_ignore,
  /* 0x02E */ [SYS_sendmsg           ] = sys_ignore,
  /* 0x02F */ [SYS_recvmsg           ] = sys_ignore,
  /* 0x030 */ [SYS_shutdown          ] = sys_ignore,
  /* 0x031 */ [SYS_bind              ] = sys_ignore,
  /* 0x032 */ [SYS_listen            ] = sys_ignore,
  /* 0x033 */ [SYS_getsockname       ] = sys_ignore,
  /* 0x034 */ [SYS_getpeername       ] = sys_ignore,
  /* 0x035 */ [SYS_socketpair        ] = sys_ignore,
  /* 0x036 */ [SYS_setsockopt        ] = sys_ignore,
  /* 0x037 */ [SYS_getsockopt        ] = sys_ignore,
  /* 0x038 */ [SYS_clone             ] = sys_ignore,
  /* 0x039 */ [SYS_fork              ] = sys_ignore,
  /* 0x03A */ [SYS_vfork             ] = sys_ignore,
  /* 0x03B */ [SYS_execve            ] = sys_ignore,
  /* 0x03C */ [SYS_exit              ] = sys_ignore,
  /* 0x03D */ [SYS_wait4             ] = sys_ignore,
  /* 0x03E */ [SYS_kill              ] = sys_ignore,
  /* 0x03F */ [SYS_uname             ] = sys_ignore,
  /* 0x040 */ [SYS_semget            ] = sys_ignore,
  /* 0x041 */ [SYS_semop             ] = sys_ignore,
  /* 0x042 */ [SYS_semctl            ] = sys_ignore,
  /* 0x043 */ [SYS_shmdt             ] = sys_ignore,
  /* 0x044 */ [SYS_msgget            ] = sys_ignore,
  /* 0x045 */ [SYS_msgsnd            ] = sys_ignore,
  /* 0x046 */ [SYS_msgrcv            ] = sys_ignore,
  /* 0x047 */ [SYS_msgctl            ] = sys_ignore,
  /* 0x048 */ [SYS_fcntl             ] = sys_fcntl,
  /* 0x049 */ [SYS_flock             ] = sys_ignore,
  /* 0x04A */ [SYS_fsync             ] = sys_ignore,
  /* 0x04B */ [SYS_fdatasync         ] = sys_ignore,
  /* 0x04C */ [SYS_truncate          ] = sys_truncate,
  /* 0x04D */ [SYS_ftruncate         ] = sys_ftruncate,
  /* 0x04E */ [SYS_getdents          ] = sys_getdents,
  /* 0x04F */ [SYS_getcwd            ] = sys_ignore,
  /* 0x050 */ [SYS_chdir             ] = sys_chdir,
  /* 0x051 */ [SYS_fchdir            ] = sys_fchdir,
  /* 0x052 */ [SYS_rename            ] = sys_rename,
  /* 0x053 */ [SYS_mkdir             ] = sys_mkdir,
  /* 0x054 */ [SYS_rmdir             ] = sys_rmdir,
  /* 0x055 */ [SYS_creat             ] = sys_creat,
  /* 0x056 */ [SYS_link              ] = sys_link,
  /* 0x057 */ [SYS_unlink            ] = sys_unlink,
  /* 0x058 */ [SYS_symlink           ] = sys_symlink,
  /* 0x059 */ [SYS_readlink          ] = sys_readlink,
  /* 0x05A */ [SYS_chmod             ] = sys_ignore,
  /* 0x05B */ [SYS_fchmod            ] = sys_ignore,
  /* 0x05C */ [SYS_chown             ] = sys_ignore,
  /* 0x05D */ [SYS_fchown            ] = sys_ignore,
  /* 0x05E */ [SYS_lchown            ] = sys_ignore,
  /* 0x05F */ [SYS_umask             ] = sys_ignore,
  /* 0x060 */ [SYS_gettimeofday      ] = sys_ignore,
  /* 0x061 */ [SYS_getrlimit         ] = sys_ignore,
  /* 0x062 */ [SYS_getrusage         ] = sys_ignore,
  /* 0x063 */ [SYS_sysinfo           ] = sys_ignore,
  /* 0x064 */ [SYS_times             ] = sys_ignore,
  /* 0x065 */ [SYS_ptrace            ] = sys_ignore,
  /* 0x066 */ [SYS_getuid            ] = sys_ignore,
  /* 0x067 */ [SYS_syslog            ] = sys_ignore,
  /* 0x068 */ [SYS_getgid            ] = sys_ignore,
  /* 0x069 */ [SYS_setuid            ] = sys_ignore,
  /* 0x06A */ [SYS_setgid            ] = sys_ignore,
  /* 0x06B */ [SYS_geteuid           ] = sys_ignore,
  /* 0x06C */ [SYS_getegid           ] = sys_ignore,
  /* 0x06D */ [SYS_setpgid           ] = sys_ignore,
  /* 0x06E */ [SYS_getppid           ] = sys_ignore,
  /* 0x06F */ [SYS_getpgrp           ] = sys_ignore,
  /* 0x070 */ [SYS_setsid            ] = sys_ignore,
  /* 0x071 */ [SYS_setreuid          ] = sys_ignore,
  /* 0x072 */ [SYS_setregid          ] = sys_ignore,
  /* 0x073 */ [SYS_getgroups         ] = sys_ignore,
  /* 0x074 */ [SYS_setgroups         ] = sys_ignore,
  /* 0x075 */ [SYS_setresuid         ] = sys_ignore,
  /* 0x076 */ [SYS_getresuid         ] = sys_ignore,
  /* 0x077 */ [SYS_setresgid         ] = sys_ignore,
  /* 0x078 */ [SYS_getresgid         ] = sys_ignore,
  /* 0x079 */ [SYS_getpgid           ] = sys_ignore,
  /* 0x07A */ [SYS_setfsuid          ] = sys_ignore,
  /* 0x07B */ [SYS_setfsgid          ] = sys_ignore,
  /* 0x07C */ [SYS_getsid            ] = sys_ignore,
  /* 0x07D */ [SYS_capget            ] = sys_ignore,
  /* 0x07E */ [SYS_capset            ] = sys_ignore,
  /* 0x07F */ [SYS_rt_sigpending     ] = sys_ignore,
  /* 0x080 */ [SYS_rt_sigtimedwait   ] = sys_ignore,
  /* 0x081 */ [SYS_rt_sigqueueinfo   ] = sys_ignore,
  /* 0x082 */ [SYS_rt_sigsuspend     ] = sys_ignore,
  /* 0x083 */ [SYS_sigaltstack       ] = sys_ignore,
  /* 0x084 */ [SYS_utime             ] = sys_utime,
  /* 0x085 */ [SYS_mknod             ] = sys_ignore, //TODO: makes a filesystem node
  /* 0x086 */ [SYS_uselib            ] = sys_ignore,
  /* 0x087 */ [SYS_personality       ] = sys_ignore,
  /* 0x088 */ [SYS_ustat             ] = sys_ignore,
  /* 0x089 */ [SYS_statfs            ] = sys_ignore,
  /* 0x08A */ [SYS_fstatfs           ] = sys_ignore,
  /* 0x08B */ [SYS_sysfs             ] = sys_ignore,
  /* 0x08C */ [SYS_getpriority       ] = sys_ignore,
  /* 0x08D */ [SYS_setpriority       ] = sys_ignore,
  /* 0x08E */ [SYS_sched_setparam    ] = sys_ignore,
  /* 0x08F */ [SYS_sched_getparam    ] = sys_ignore,
  /* 0x090 */ [SYS_sched_setscheduler] = sys_ignore,
  /* 0x091 */ [SYS_sched_getscheduler] = sys_ignore,
  /* 0x092 */ [SYS_sched_get_priority_max] = sys_ignore,
  /* 0x093 */ [SYS_sched_get_priority_min] = sys_ignore,
  /* 0x094 */ [SYS_sched_rr_get_interval] = sys_ignore,
  /* 0x095 */ [SYS_mlock             ] = sys_ignore,
  /* 0x096 */ [SYS_munlock           ] = sys_ignore,
  /* 0x097 */ [SYS_mlockall          ] = sys_ignore,
  /* 0x098 */ [SYS_munlockall        ] = sys_ignore,
  /* 0x099 */ [SYS_vhangup           ] = sys_ignore,
  /* 0x09A */ [SYS_modify_ldt        ] = sys_ignore,
  /* 0x09B */ [SYS_pivot_root        ] = sys_ignore,
  /* 0x09C */ [SYS__sysctl           ] = sys_ignore,
  /* 0x09D */ [SYS_prctl             ] = sys_ignore,
  /* 0x09E */ [SYS_arch_prctl        ] = sys_ignore,
  /* 0x09F */ [SYS_adjtimex          ] = sys_ignore,
  /* 0x0A0 */ [SYS_setrlimit         ] = sys_ignore,
  /* 0x0A1 */ [SYS_chroot            ] = sys_ignore,
  /* 0x0A2 */ [SYS_sync              ] = sys_ignore,
  /* 0x0A3 */ [SYS_acct              ] = sys_ignore,
  /* 0x0A4 */ [SYS_settimeofday      ] = sys_ignore,
  /* 0x0A5 */ [SYS_mount             ] = sys_ignore,
  /* 0x0A6 */ [SYS_umount2           ] = sys_ignore,
  /* 0x0A7 */ [SYS_swapon            ] = sys_ignore,
  /* 0x0A8 */ [SYS_swapoff           ] = sys_ignore,
  /* 0x0A9 */ [SYS_reboot            ] = sys_ignore,
  /* 0x0AA */ [0x0AA                 ] = sys_ignore,
  /* 0x0AB */ [0x0AB                 ] = sys_ignore,
  /* 0x0AC */ [0x0AC                 ] = sys_ignore,
  /* 0x0AD */ [0x0AD                 ] = sys_ignore,
  /* 0x0AE */ [0x0AE                 ] = sys_ignore,
  /* 0x0AF */ [0x0AF                 ] = sys_ignore,
  /* 0x0B0 */ [0x0B0                 ] = sys_ignore,
  /* 0x0B1 */ [0x0B1                 ] = sys_ignore,
  /* 0x0B2 */ [0x0B2                 ] = sys_ignore,
  /* 0x0B3 */ [0x0B3                 ] = sys_ignore,
  /* 0x0B4 */ [0x0B4                 ] = sys_ignore,
  /* 0x0B5 */ [0x0B5                 ] = sys_ignore,
  /* 0x0B6 */ [0x0B6                 ] = sys_ignore,
  /* 0x0B7 */ [0x0B7                 ] = sys_ignore,
  /* 0x0B8 */ [0x0B8                 ] = sys_ignore,
  /* 0x0B9 */ [0x0B9                 ] = sys_ignore,
  /* 0x0BA */ [SYS_gettid            ] = sys_ignore,
  /* 0x0BB */ [0x0BB                 ] = sys_ignore,
  /* 0x0BC */ [0x0BC                 ] = sys_ignore,
  /* 0x0BD */ [0x0BD                 ] = sys_ignore,
  /* 0x0BE */ [SYS_fsetxattr         ] = sys_fsetxattr,
  /* 0x0BF */ [SYS_getxattr          ] = sys_getxattr,
  /* 0x0C0 */ [SYS_lgetxattr         ] = sys_lgetxattr,
  /* 0x0C1 */ [0x0C1                 ] = sys_ignore,
  /* 0x0C2 */ [0x0C2                 ] = sys_ignore,
  /* 0x0C3 */ [SYS_llistxattr        ] = sys_llistxattr,
  /* 0x0C4 */ [SYS_flistxattr        ] = sys_flistxattr,
  /* 0x0C5 */ [0x0C5                 ] = sys_ignore,
  /* 0x0C6 */ [0x0C6                 ] = sys_ignore,
  /* 0x0C7 */ [0x0C7                 ] = sys_ignore,
  /* 0x0C8 */ [0x0C8                 ] = sys_ignore,
  /* 0x0C9 */ [SYS_time              ] = sys_ignore,
  /* 0x0CA */ [SYS_futex             ] = sys_ignore,
  /* 0x0CB */ [SYS_sched_setaffinity ] = sys_ignore,
  /* 0x0CC */ [SYS_sched_getaffinity ] = sys_ignore,
  /* 0x0CD */ [0x0CD                 ] = sys_ignore,
  /* 0x0CE */ [0x0CE                 ] = sys_ignore,
  /* 0x0CF */ [0x0CF                 ] = sys_ignore,
  /* 0x0D0 */ [0x0D0                 ] = sys_ignore,
  /* 0x0D1 */ [0x0D1                 ] = sys_ignore,
  /* 0x0D2 */ [0x0D2                 ] = sys_ignore,
  /* 0x0D3 */ [0x0D3                 ] = sys_ignore,
  /* 0x0D4 */ [0x0D4                 ] = sys_ignore,
  /* 0x0D5 */ [SYS_epoll_create      ] = sys_epoll_create,
  /* 0x0D6 */ [0x0D6                 ] = sys_ignore,
  /* 0x0D7 */ [0x0D7                 ] = sys_ignore,
  /* 0x0D8 */ [0x0D8                 ] = sys_ignore,
  /* 0x0D9 */ [SYS_getdents64        ] = sys_getdents64,
  /* 0x0DA */ [SYS_set_tid_address   ] = sys_ignore,
  /* 0x0DB */ [SYS_restart_syscall   ] = sys_ignore,
  /* 0x0DC */ [0x0DC                 ] = sys_ignore,
  /* 0x0DD */ [SYS_fadvise64         ] = sys_ignore,
  /* 0x0DE */ [SYS_timer_create      ] = sys_ignore,
  /* 0x0DF */ [SYS_timer_settime     ] = sys_ignore,
  /* 0x0E0 */ [SYS_timer_gettime     ] = sys_ignore,
  /* 0x0E1 */ [SYS_timer_getoverrun  ] = sys_ignore,
  /* 0x0E2 */ [SYS_timer_delete      ] = sys_ignore,
  /* 0x0E3 */ [0x0E3                 ] = sys_ignore,
  /* 0x0E4 */ [SYS_clock_gettime     ] = sys_ignore,
  /* 0x0E5 */ [SYS_clock_getres      ] = sys_ignore,
  /* 0x0E6 */ [0x0E6                 ] = sys_ignore,
  /* 0x0E7 */ [SYS_exit_group        ] = sys_ignore,
  /* 0x0E8 */ [SYS_epoll_wait        ] = sys_ignore,
  /* 0x0E9 */ [SYS_epoll_ctl         ] = sys_ignore,
  /* 0x0EA */ [SYS_tgkill            ] = sys_ignore,
  /* 0x0EB */ [SYS_utimes            ] = sys_ignore,
  /* 0x0EC */ [0x0EC                 ] = sys_ignore,
  /* 0x0ED */ [0x0ED                 ] = sys_ignore,
  /* 0x0EE */ [0x0EE                 ] = sys_ignore,
  /* 0x0EF */ [0x0EF                 ] = sys_ignore,
  /* 0x0F0 */ [0x0F0                 ] = sys_ignore,
  /* 0x0F1 */ [0x0F1                 ] = sys_ignore,
  /* 0x0F2 */ [0x0F2                 ] = sys_ignore,
  /* 0x0F3 */ [0x0F3                 ] = sys_ignore,
  /* 0x0F4 */ [0x0F4                 ] = sys_ignore,
  /* 0x0F5 */ [0x0F5                 ] = sys_ignore,
  /* 0x0F6 */ [0x0F6                 ] = sys_ignore,
  /* 0x0F7 */ [SYS_waitid            ] = sys_ignore,
  /* 0x0F8 */ [0x0F8                 ] = sys_ignore,
  /* 0x0F9 */ [0x0F9                 ] = sys_ignore,
  /* 0x0FA */ [0x0FA                 ] = sys_ignore,
  /* 0x0FB */ [0x0FB                 ] = sys_ignore,
  /* 0x0FC */ [0x0FC                 ] = sys_ignore,
  /* 0x0FD */ [0x0FD                 ] = sys_ignore,
  /* 0x0FE */ [0x0FE                 ] = sys_ignore,
  /* 0x0FF */ [0x0FF                 ] = sys_ignore,
  /* 0x100 */ [0x100                 ] = sys_ignore,
  /* 0x101 */ [SYS_openat            ] = sys_openat,
  /* 0x102 */ [SYS_mkdirat           ] = sys_mkdirat,
  /* 0x103 */ [0x103                 ] = sys_ignore,
  /* 0x104 */ [0x104                 ] = sys_ignore,
  /* 0x105 */ [0x105                 ] = sys_ignore,
  /* 0x106 */ [SYS_newfstatat        ] = sys_newfstatat,
  /* 0x107 */ [SYS_unlinkat          ] = sys_unlinkat,
  /* 0x108 */ [SYS_renameat          ] = sys_renameat,
  /* 0x109 */ [SYS_linkat            ] = sys_linkat,
  /* 0x10A */ [SYS_symlinkat         ] = sys_symlink,
  /* 0x10B */ [SYS_readlinkat        ] = sys_readlinkat,
  /* 0x10C */ [SYS_fchmodat          ] = sys_ignore,
  /* 0x10D */ [SYS_faccessat         ] = sys_faccessat,
  /* 0x10E */ [SYS_pselect6          ] = sys_ignore,
  /* 0x10F */ [SYS_ppoll             ] = sys_ignore,
  /* 0x110 */ [0x110                 ] = sys_ignore,
  /* 0x111 */ [SYS_set_robust_list   ] = sys_ignore,
  /* 0x112 */ [0x112                 ] = sys_ignore,
  /* 0x113 */ [SYS_splice            ] = sys_splice,
  /* 0x114 */ [0x114                 ] = sys_ignore,
  /* 0x115 */ [0x115                 ] = sys_ignore,
  /* 0x116 */ [0x116                 ] = sys_ignore,
  /* 0x117 */ [0x117                 ] = sys_ignore,
  /* 0x118 */ [SYS_utimensat         ] = sys_ignore,
  /* 0x119 */ [SYS_epoll_pwait       ] = sys_ignore,
  /* 0x11A */ [0x11A                 ] = sys_ignore,
  /* 0x11B */ [0x11B                 ] = sys_ignore,
  /* 0x11C */ [0x11C                 ] = sys_ignore,
  /* 0x11D */ [SYS_fallocate         ] = sys_fallocate,
  /* 0x11E */ [SYS_timerfd_settime   ] = sys_ignore,
  /* 0x11F */ [SYS_timerfd_gettime   ] = sys_ignore,
  /* 0x120 */ [SYS_accept4           ] = sys_ignore,
  /* 0x121 */ [SYS_signalfd4         ] = sys_ignore,
  /* 0x122 */ [SYS_eventfd2          ] = sys_eventfd2,
  /* 0x123 */ [SYS_epoll_create1     ] = sys_ignore,
  /* 0x124 */ [SYS_dup3              ] = sys_dup3,
  /* 0x125 */ [SYS_pipe2             ] = sys_pipe2,
  /* 0x126 */ [SYS_inotify_init1     ] = sys_ignore,
  /* 0x127 */ [SYS_preadv            ] = sys_ignore,
  /* 0x128 */ [SYS_pwritev           ] = sys_ignore,
  /* 0x129 */ [SYS_rt_tgsigqueueinfo ] = sys_ignore,
  /* 0x12A */ [SYS_perf_event_open   ] = sys_ignore,
  /* 0x12B */ [SYS_recvmmsg          ] = sys_ignore,
  /* 0x12C */ [SYS_fanotify_init     ] = sys_ignore,
  /* 0x12D */ [SYS_fanotify_mark     ] = sys_ignore,
  /* 0x12E */ [SYS_prlimit64         ] = sys_ignore,
  /* 0x12F */ [SYS_name_to_handle_at ] = sys_ignore,
  /* 0x130 */ [SYS_open_by_handle_at ] = sys_ignore,
  /* 0x131 */ [SYS_clock_adjtime     ] = sys_ignore,
  /* 0x132 */ [SYS_syncfs            ] = sys_ignore,
  /* 0x133 */ [SYS_sendmmsg          ] = sys_ignore,
  /* 0x134 */ [SYS_setns             ] = sys_ignore,
  /* 0x135 */ [SYS_getcpu            ] = sys_ignore,
  /* 0x136 */ [SYS_process_vm_readv  ] = sys_ignore,
  /* 0x137 */ [SYS_process_vm_writev ] = sys_ignore,
  /* 0x138 */ [SYS_kcmp              ] = sys_ignore,
  /* 0x139 */ [SYS_finit_module      ] = sys_ignore,
  /* 0x13A */ [SYS_sched_setattr     ] = sys_ignore,
  /* 0x13B */ [SYS_sched_getattr     ] = sys_ignore,
  /* 0x13C */ [SYS_renameat2         ] = sys_ignore,
  /* 0x13D */ [SYS_seccomp           ] = sys_ignore,
  /* 0x13E */ [SYS_getrandom         ] = sys_ignore,
  /* 0x13F */ [0x13F                 ] = sys_ignore,
  /* 0x140 */ [0x140                 ] = sys_ignore,
  /* 0x141 */ [0x141                 ] = sys_ignore,
  /* 0x142 */ [0x142                 ] = sys_ignore,
  /* 0x143 */ [0x143                 ] = sys_ignore,
  /* 0x144 */ [0x144                 ] = sys_ignore,
  /* 0x145 */ [0x145                 ] = sys_ignore,
  /* 0x146 */ [0x146                 ] = sys_ignore,
  /* 0x147 */ [0x147                 ] = sys_ignore,
  /* 0x148 */ [0x148                 ] = sys_ignore,
  /* 0x149 */ [0x149                 ] = sys_ignore,
  /* 0x14A */ [0x14A                 ] = sys_ignore,
  /* 0x14B */ [0x14B                 ] = sys_ignore,
  /* 0x14C */ [SYS_statx             ] = sys_ignore,
  /* 0x14D */ [0x14D                 ] = sys_ignore,
  /* 0x14E */ [SYS_rseq              ] = sys_ignore,
  /* 0x14F */ [0x14F                 ] = sys_ignore,
  /* 0x150 */ [0x150                 ] = sys_ignore,
  /* 0x151 */ [0x151                 ] = sys_ignore,
  /* 0x152 */ [0x152                 ] = sys_ignore,
  /* 0x153 */ [0x153                 ] = sys_ignore,
  /* 0x154 */ [0x154                 ] = sys_ignore,
  /* 0x155 */ [0x155                 ] = sys_ignore,
  /* 0x156 */ [0x156                 ] = sys_ignore,
  /* 0x157 */ [0x157                 ] = sys_ignore,
  /* 0x158 */ [0x158                 ] = sys_ignore,
  /* 0x159 */ [0x159                 ] = sys_ignore,
  /* 0x15A */ [0x15A                 ] = sys_ignore,
  /* 0x15B */ [0x15B                 ] = sys_ignore,
  /* 0x15C */ [0x15C                 ] = sys_ignore,
  /* 0x15D */ [0x15D                 ] = sys_ignore,
  /* 0x15E */ [0x15E                 ] = sys_ignore,
  /* 0x15F */ [0x15F                 ] = sys_ignore,
  /* 0x160 */ [0x160                 ] = sys_ignore,
  /* 0x161 */ [0x161                 ] = sys_ignore,
  /* 0x162 */ [0x162                 ] = sys_ignore,
  /* 0x163 */ [0x163                 ] = sys_ignore,
  /* 0x164 */ [0x164                 ] = sys_ignore,
  /* 0x165 */ [0x165                 ] = sys_ignore,
  /* 0x166 */ [0x166                 ] = sys_ignore,
  /* 0x167 */ [0x167                 ] = sys_ignore,
  /* 0x168 */ [0x168                 ] = sys_ignore,
  /* 0x169 */ [0x169                 ] = sys_ignore,
  /* 0x16A */ [0x16A                 ] = sys_ignore,
  /* 0x16B */ [0x16B                 ] = sys_ignore,
  /* 0x16C */ [0x16C                 ] = sys_ignore,
  /* 0x16D */ [0x16D                 ] = sys_ignore,
  /* 0x16E */ [0x16E                 ] = sys_ignore,
  /* 0x16F */ [0x16F                 ] = sys_ignore,
  /* 0x170 */ [0x170                 ] = sys_ignore,
  /* 0x171 */ [0x171                 ] = sys_ignore,
  /* 0x172 */ [0x172                 ] = sys_ignore,
  /* 0x173 */ [0x173                 ] = sys_ignore,
  /* 0x174 */ [0x174                 ] = sys_ignore,
  /* 0x175 */ [0x175                 ] = sys_ignore,
  /* 0x176 */ [0x176                 ] = sys_ignore,
  /* 0x177 */ [0x177                 ] = sys_ignore,
  /* 0x178 */ [0x178                 ] = sys_ignore,
  /* 0x179 */ [0x179                 ] = sys_ignore,
  /* 0x17A */ [0x17A                 ] = sys_ignore,
  /* 0x17B */ [0x17B                 ] = sys_ignore,
  /* 0x17C */ [0x17C                 ] = sys_ignore,
  /* 0x17D */ [0x17D                 ] = sys_ignore,
  /* 0x17E */ [0x17E                 ] = sys_ignore,
  /* 0x17F */ [0x17F                 ] = sys_ignore,
  /* 0x180 */ [0x180                 ] = sys_ignore,
  /* 0x181 */ [0x181                 ] = sys_ignore,
  /* 0x182 */ [0x182                 ] = sys_ignore,
  /* 0x183 */ [0x183                 ] = sys_ignore,
  /* 0x184 */ [0x184                 ] = sys_ignore,
  /* 0x185 */ [0x185                 ] = sys_ignore,
  /* 0x186 */ [0x186                 ] = sys_ignore,
  /* 0x187 */ [0x187                 ] = sys_ignore,
  /* 0x188 */ [0x188                 ] = sys_ignore,
  /* 0x189 */ [0x189                 ] = sys_ignore,
  /* 0x18A */ [0x18A                 ] = sys_ignore,
  /* 0x18B */ [0x18B                 ] = sys_ignore,
  /* 0x18C */ [0x18C                 ] = sys_ignore,
  /* 0x18D */ [0x18D                 ] = sys_ignore,
  /* 0x18E */ [0x18E                 ] = sys_ignore,
  /* 0x18F */ [0x18F                 ] = sys_ignore,
  /* 0x190 */ [0x190                 ] = sys_ignore,
  /* 0x191 */ [0x191                 ] = sys_ignore,
  /* 0x192 */ [0x192                 ] = sys_ignore,
  /* 0x193 */ [0x193                 ] = sys_ignore,
  /* 0x194 */ [0x194                 ] = sys_ignore,
  /* 0x195 */ [0x195                 ] = sys_ignore,
  /* 0x196 */ [0x196                 ] = sys_ignore,
  /* 0x197 */ [0x197                 ] = sys_ignore,
  /* 0x198 */ [0x198                 ] = sys_ignore,
  /* 0x199 */ [0x199                 ] = sys_ignore,
  /* 0x19A */ [0x19A                 ] = sys_ignore,
  /* 0x19B */ [0x19B                 ] = sys_ignore,
  /* 0x19C */ [0x19C                 ] = sys_ignore,
  /* 0x19D */ [0x19D                 ] = sys_ignore,
  /* 0x19E */ [0x19E                 ] = sys_ignore,
  /* 0x19F */ [0x19F                 ] = sys_ignore,
  /* 0x1A0 */ [0x1A0                 ] = sys_ignore,
  /* 0x1A1 */ [0x1A1                 ] = sys_ignore,
  /* 0x1A2 */ [0x1A2                 ] = sys_ignore,
  /* 0x1A3 */ [0x1A3                 ] = sys_ignore,
  /* 0x1A4 */ [0x1A4                 ] = sys_ignore,
  /* 0x1A5 */ [0x1A5                 ] = sys_ignore,
  /* 0x1A6 */ [0x1A6                 ] = sys_ignore,
  /* 0x1A7 */ [0x1A7                 ] = sys_ignore,
  /* 0x1A8 */ [0x1A8                 ] = sys_ignore,
  /* 0x1A9 */ [0x1A9                 ] = sys_ignore,
  /* 0x1AA */ [0x1AA                 ] = sys_ignore,
  /* 0x1AB */ [0x1AB                 ] = sys_ignore,
  /* 0x1AC */ [0x1AC                 ] = sys_ignore,
  /* 0x1AD */ [0x1AD                 ] = sys_ignore,
  /* 0x1AE */ [0x1AE                 ] = sys_ignore,
  /* 0x1AF */ [0x1AF                 ] = sys_ignore,
  /* 0x1B0 */ [0x1B0                 ] = sys_ignore,
  /* 0x1B1 */ [0x1B1                 ] = sys_ignore,
  /* 0x1B2 */ [0x1B2                 ] = sys_ignore,
  /* 0x1B3 */ [SYS_clone3            ] = sys_ignore,
  /* 0x1B4 */ [0x1B4                 ] = sys_ignore,
  /* 0x1B5 */ [0x1B5                 ] = sys_ignore,
  /* 0x1B6 */ [0x1B6                 ] = sys_ignore,
  /* 0x1B7 */ [SYS_faccessat2        ] = sys_ignore,
};

// -----------------------------------------------------------------------------
void Handle(Trace *trace, int64_t sno, const Args &args)
{
  if (sno < 0) {
    return;
  }

  if (sno > sizeof(kHandlers) / sizeof(kHandlers[0]) || !kHandlers[sno]) {
    throw std::runtime_error(
        "Unknown syscall " + std::to_string(sno) + " in " +
        trace->GetFileName(trace->GetTrace(args.PID)->GetImage())
    );
  }

  auto *proc = trace->GetTrace(args.PID);

  try {
    kHandlers[sno](proc, args);
  } catch (std::exception &ex) {
    throw std::runtime_error(
        "Exception while handling syscall " + std::to_string(sno) +
        " in process " + std::to_string(proc->GetUID()) + " (" +
        trace->GetFileName(proc->GetImage()) +
        "): " +
        ex.what()
    );
  }
}
