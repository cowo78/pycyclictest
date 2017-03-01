#!/usr/bin/python

import ctypes
import errno
import os, os.path
import resource
import sys
import time

MCL_CURRENT = 1
MCL_FUTURE  = 2

M_TRIM_THRESHOLD    = -1
M_TOP_PAD           = -2
M_MMAP_THRESHOLD    = -3
M_MMAP_MAX          = -4
M_CHECK_ACTION      = -5
M_PERTURB           = -6
M_ARENA_TEST        = -7
M_ARENA_MAX         = -8

_SC_PAGESIZE        = 30

SOMESIZE = (100*1024*1024)

SCHED_OTHER = 0
SCHED_FIFO  = 1
SCHED_RR    = 2

CLOCK_REALTIME              = 0
CLOCK_MONOTONIC             = 1
CLOCK_PROCESS_CPUTIME_ID    = 2

INTERVAL_NS = 100 * 1000
INTERVAL_S  = INTERVAL_NS * 1e-9

CYCLES = 1 * 1000 * 1000

class _sched_param(ctypes.Structure):
    _fields_ = [("priority", ctypes.c_int32)]

class _struct_timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_ulong), ("tv_nsec", ctypes.c_long)]

libc = ctypes.CDLL('libc.so.6', use_errno=True)

def clock_nanosleep(clock_id, nanoseconds):
    request = _struct_timespec(tv_sec=0, tv_nsec=nanoseconds)
    r = libc.clock_nanosleep(clock_id, 0, ctypes.byref(request), None)
    if (r == errno.EINTR):
        raise OSError("Interrupted system call")

def mlockall(flags=MCL_CURRENT|MCL_FUTURE):
    result = libc.mlockall(flags)
    if result != 0:
        raise Exception("cannot lock memmory, errno=%s" % ctypes.get_errno())

def munlockall():
    result = libc.munlockall()
    if result != 0:
        raise Exception("cannot lock memmory, errno=%s" % ctypes.get_errno())

def mallopt(param, value):
    result = libc.mallopt(param, value)
    if result == 0:
        raise Exception("mallopt call failed, errno=%s" % ctypes.get_errno())

def sysconf(name):
    result = libc.sysconf(name)

    if (result == -1) and (ctypes.get_errno() == errno.EINVAL):
        raise Exception("invalid sysconf option %d" % name)
    return result


def check_privs():
    policy = libc.sched_getscheduler(0)
    if policy < 0:
        raise OSError(ctypes.get_errno(),"sched_getscheduler")

    # if we're already running a realtime scheduler
    # then we *should* be able to change things later
    if (policy == SCHED_FIFO or policy == SCHED_RR):
        return

    param = _sched_param()
    old_param = _sched_param()
    # first get the current parameters */
    if (libc.sched_getparam(0, ctypes.byref(old_param))):
        raise OSError(ctypes.get_errno(),"sched_getparam")

    param.priority = 10
    # try to change to SCHED_FIFO
    if (-1 == libc.sched_setscheduler(0, SCHED_FIFO, ctypes.byref(param))):
        raise OSError(ctypes.get_errno(), "sched_setscheduler")

    # we're good; change back and return success
    if (-1 == libc.sched_setscheduler(0, policy, ctypes.byref(old_param))):
        raise OSError(ctypes.get_errno(), "sched_setscheduler")

def set_latency_target():
    if not os.path.exists("/dev/cpu_dma_latency"):
        print("WARN: /dev/cpu_dma_latency does not exist")
        return None

    latency_target_fd = open("/dev/cpu_dma_latency", "wb")
    latency_target_fd.write(b'\x00\x00\x00\x00')
    print("# /dev/cpu_dma_latency set to 0 us\n")
    return latency_target_fd


def check_timer():
    precision = time.clock_getres(time.CLOCK_MONOTONIC)
    return precision <= 1e-4


if __name__ == '__main__':
    check_privs()

    mlockall(MCL_CURRENT | MCL_FUTURE)

    latency_target_fd = set_latency_target()

    if (check_timer()):
        print("High resolution timers not available")

    # Turn off malloc trimming.
    mallopt (M_TRIM_THRESHOLD, -1)

    # Turn off mmap usage.
    mallopt (M_MMAP_MAX, 0)

    page_size = sysconf(_SC_PAGESIZE)
    print("Page size: %d" % page_size)

    buffer = ctypes.create_string_buffer(SOMESIZE)

    usage = resource.getrusage(resource.RUSAGE_SELF)
    print("Major-pagefaults:%d, Minor Pagefaults:%d" % (usage.ru_majflt, usage.ru_minflt))

    # Touch page to prove there will be no page fault later
    i = 0
    while (i < SOMESIZE):
        # Each write to this buffer will *not* generate a pagefault.
        # Even if nothing has been written to the newly allocated memory, the physical page
        #  is still provisioned to the process because mlockall() has been called with
        #  the MCL_FUTURE flag
        buffer[i] = b'0';
        i += page_size

    # print the number of major and minor pagefaults this application has triggered
    usage = resource.getrusage(resource.RUSAGE_SELF)
    print("Major-pagefaults:%d, Minor Pagefaults:%d" % (usage.ru_majflt, usage.ru_minflt))

    del (buffer)
    # buffer is now released. As glibc is configured such that it never gives back memory to
    # the kernel, the memory allocated above is locked for this process. All malloc() and new()
    # calls come from the memory pool reserved and locked above. Issuing free() and delete()
    # does NOT make this locking undone. So, with this locking mechanism we can build C++ applications
    # that will never run into a major/minor pagefault, even with swapping enabled.
    buffer = ctypes.create_string_buffer(SOMESIZE)
    usage = resource.getrusage(resource.RUSAGE_SELF)
    print("Major-pagefaults:%d, Minor Pagefaults:%d" % (usage.ru_majflt, usage.ru_minflt))

    # Raise priority and set SCHED_FIFO
    param = _sched_param(priority=10)
    if (-1 == libc.sched_setscheduler(0, SCHED_FIFO, ctypes.byref(param))):
        raise OSError(ctypes.get_errno(), "sched_setscheduler")

    min_diff = 1e10
    max_diff = mean_diff = 0.0

    for i in range(0, CYCLES):
        ts1 = time.clock_gettime(CLOCK_MONOTONIC)
        clock_nanosleep(CLOCK_MONOTONIC, INTERVAL_NS)
        ts2 = time.clock_gettime(CLOCK_MONOTONIC)
        expected_ts = ts1 + INTERVAL_S

        current_diff = abs(expected_ts - ts2)
        if current_diff < min_diff:
            min_diff = current_diff

        if current_diff > max_diff:
            max_diff = current_diff

        mean_diff += current_diff


    if (latency_target_fd):
        latency_target_fd.close()

    mean_diff /= CYCLES
    print("MAX {} MIN {} AVG {}".format(max_diff, min_diff, mean_diff))

    sys.exit(0)
