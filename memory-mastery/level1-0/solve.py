#!/bin/python 

import os
import sys
import time
import argparse
import pwn as p


SCANF_INPUT_SIZE = 1024

p.context.arch = 'amd64'
args = None
proc, elf, libc = (None, None, None)


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


    def prompt_cmd(self, cmd):
        if len(cmd) > SCANF_INPUT_SIZE:
            print("!WARNING! Length of cmd is larger than input max size.")
            cmd = cmd[:SCANF_INPUT_SIZE]
        if isinstance(cmd, str):
            cmd = cmd.encode()

        self.clean()
        self.sendline(cmd)


    def send_idx(self, idx):
        self.sendline(str(idx).encode())


    def printf(self, idx: int):
        self.prompt_cmd("printf")
        self.send_idx(idx)
        self.recvuntil(b"MESSAGE: ")
        return self.recvline(drop=True)


    def malloc(self, idx: int):
        self.prompt_cmd(b"malloc")
        self.send_idx(idx)


    def scanf(self, idx: int, msg):
        self.prompt_cmd(b"scanf")
        self.send_idx(idx)
        self.prompt_cmd(msg)


    def free(self, idx):
        self.prompt_cmd(b"free")
        self.send_idx(idx)


    def send_flag(self):
        self.prompt_cmd(b"send_flag")
        if self.recvuntil(b"pwn.", timeout=2) != b"":
            return self.recv(55)
        return b""


# We malloc, scanf 16 random bytes to buffer and then race:
# thd1: strlen(buf) => returns 8 bytes
# thd2: free(buf)   => get metadata into buf
# thd1: write(1, buf, stlren) => syscall writing out the metadata
def tcache_leak(th1: thread_comm, thd2: thread_comm):
    pass


def exploit():
    pass


def main():
    parser = argparse.ArgumentParser(usage="Usage: ./script.py [binary]")
    parser.add_argument('binary')
    parser.add_argument('-g', "--gef",   action='store_true')
    parser.add_argument('-p', "--pwndbg",   action='store_true')
    parser.add_argument('-n', "--noaslr", action='store_true')
    parser.add_argument('-l', "--log-level", default='info', type=str)
    args = parser.parse_args()

    p.context.log_level = args.log_level

    get_server()

    exploit()
    proc.interactive()


if __name__ == '__main__':
    main()
