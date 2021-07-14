from pwn import *
from internalblue.adbcore import ADBCore
from pwnlib.asm import asm
from binascii import unhexlify
from IPython import embed

context.arch = 'thumb'
context.endian = 'little'

# it is the hci dispatcher func identified from analysis.py
HOOK_HCI_DISPATCHER = 0x99dc
ASM_LOCATION_HCI = 0x00211900

with open("./gatt.txt", "r") as f:
    WHITELIST = f.readlines()
# mark the end
WHITELIST.append('ffff')
WHITELIST = [x.strip() for x in WHITELIST]
WHITELIST = [hex(int(x, base=16))[2:] for x in WHITELIST]
WHITELIST = ['0' + x if len(x) == 3 else x for x in WHITELIST]

# print(WHITELIST)

code = """
        // save regs
        push {r2, r3, r4}

        ldr r2, =whitelist
        ldr r3, =0xffff

        // go through HCI whitelist and see if we find the opcode.
        whitelist_loop:
        ldrh r4, [r2, 0x0]
        cmp r0, r4
        beq return
        cmp r3, r4
        beq unsupported
        adds r2, 2
        b whitelist_loop

        // we did not find the opcode: set unsupported values and return:
        unsupported:
        ldr r0, =0x1008
        b return

        // restore regs and return
        return:
        ubfx r1, r0, 0x0, 0xa
        pop {r2, r3, r4}
        b 0x99e0

        // HCI whilelist
        whitelist:
        %s
        """ % ''.join([".hword 0x%s\n" % x for x in WHITELIST])

# print(code)

with open("test.txt", "w") as f:
    f.write(code)

internalblue = ADBCore()
internalblue.interface = internalblue.device_list()[0][1]  # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)

log.info("Installing patches for nexus 5")

log.info("Writing ASM snippet.")
codeBytes = asm(code, vma=ASM_LOCATION_HCI)

if not internalblue.writeMem(address=ASM_LOCATION_HCI, data=codeBytes, progress_log=None):
    log.critical("error!")
    exit(-1)

log.info("Installing hook patch...")
patch = asm("b 0x%x" % ASM_LOCATION_HCI, vma=HOOK_HCI_DISPATCHER)
if not internalblue.patchRom(HOOK_HCI_DISPATCHER, patch):
    log.critical("error!")
    exit(-1)

# shut down
internalblue.shutdown()
exit(-1)
log.info("Debloated hci commands")
