from pwn import *
from internalblue.hcicore import HCICore

internalblue = HCICore()
internalblue.interface = internalblue.device_list()[0][
    1]  # just use the first device

# setup sockets
if not internalblue.connect():
    log.critical("No connection to target device.")
    exit(-1)

log.info("Installing patches for a2dp")

code = b"""
        @ save regs
        push {r0, r1, r2, r3, r4, r5, r6, r7}

        @ create opcode and store it in r0
        mov r0, r2, lsl #8
        add r0, r3

        @ go through HCI jmptable and see if we find the opcode.
        ldr r7, =0xffff
        ldr r6, =jmptable
        ldr r2, =0
        ldr r4, =10

        loop:
        mul r3, r2, r4
        ldrh r5, [r6, r3]
        cmp r0, r5
        beq found
        cmp r7, r5
        beq unsupported
        add r2, r2, 1
        b loop

        @ we did not find the opcode: set dummy values and return
        unsupported:
        ldr r5, =0
        str r5, [r1, #0x0]
        str r5, [r1, #0x4]
        b return

        @we found the opcode: set fptr and someValue
        found:
        add r3, r3, 2  @ get fptr
        ldr r5, [r6, r3]
        str r5, [r1, #0x0]
        add r3, r3, 4  @ get someValue
        ldr r5, [r6, r3]
        str r5, [r1, #0x4]

        @ restore regs and return
        return:
        pop {r0, r1, r2, r3, r4, r5, r6, r7}
        bx lr

        @ HCI whilelist
        jmptable:
            .hword 0x1101
            .word 0x0002eb3d
            .word 0x00000005
            .hword 0x2e3f
            .word 0x0009ffcd
            .word 0x00070008
            .hword 0x4e3f
            .word 0x000a0171
            .word 0x00000008
            .hword 0x573f
            .word 0x000a0269
            .word 0x00060011
            .hword 0x273f
            .word 0x0009fd8d
            .word 0x00060006
            .hword 0x0f01
            .word 0x0002ea49
            .word 0x00000007
            .hword 0x1303
            .word 0x00013cfb
            .word 0x000600fb
            .hword 0x0501
            .word 0x0002e347
            .word 0x00000010
            .hword 0x1203
            .word 0x00013c93
            .word 0x0008000a
            .hword 0x0601
            .word 0x0002e3f7
            .word 0x00000006
            .hword 0x0402
            .word 0x0001377b
            .word 0x00000005
            .hword 0x3303
            .word 0x0001400f
            .word 0x0006000a
            .hword 0x2b01
            .word 0x0002f039
            .word 0x000c000c
            .hword 0x0101
            .word 0x0002e28b
            .word 0x00000008
            .hword 0x0201
            .word 0x0002e2e5
            .word 0x00060003
            .hword 0x0c01
            .word 0x0002e99f
            .word 0x00000009
            .hword 0x0904
            .word 0x000274dd
            .word 0x000c0003
            .hword 0x0504
            .word 0x00027489
            .word 0x000d0003
            .hword 0x1f01
            .word 0x0002ef2d
            .word 0x00000005
            .hword 0x0404
            .word 0x0002743f
            .word 0x00100004
            .hword 0x1403
            .word 0x00013d2b
            .word 0x00fe0003
            .hword 0x0204
            .word 0x000272dd
            .word 0x00460003
            .hword 0x0104
            .word 0x000272b9
            .word 0x000e0003
            .hword 0x1c01
            .word 0x0002ee17
            .word 0x00000006
            .hword 0x1b01
            .word 0x0002edd1
            .word 0x00000005
            .hword 0x1d01
            .word 0x0002eed1
            .word 0x00000005
            .hword 0x1901
            .word 0x0002ec5b
            .word 0x0000000d
            .hword 0x0303
            .word 0x00013a8f
            .word 0x00000003
            .hword 0x1301
            .word 0x0002eb79
            .word 0x00000006
            .hword 0x0503
            .word 0x00013b03
            .word 0x00060000
            .hword 0x0103
            .word 0x00013a7d
            .word 0x0006000b
            .hword 0x0302
            .word 0x000136cd
            .word 0x0000000d
            .hword 0x1102
            .word 0x000139df
            .word 0x0008000b
            .hword 0x2c01
            .word 0x0002f0ed
            .word 0x000c0009
            .hword 0x2403
            .word 0x00013ef9
            .word 0x00060006
            .hword 0x3a03
            .word 0x0001413f
            .word 0x00060000
            .hword 0x0f02
            .word 0x00013937
            .word 0x00060005
            .hword 0x5203
            .word 0x000142cd
            .word 0x000600f4
            .hword 0x4503
            .word 0x00014207
            .word 0x00060004
            .hword 0x1e03
            .word 0x00013e25
            .word 0x00060007
            .hword 0x4303
            .word 0x000141dd
            .word 0x00060004
            .hword 0x0d02
            .word 0x000138f5
            .word 0x00080007
            .hword 0x3703
            .word 0x000140db
            .word 0x00080007
            .hword 0x4703
            .word 0x0001423b
            .word 0x00060004
            .hword 0x1803
            .word 0x00013d61
            .word 0x00060005
            .hword 0x1a03
            .word 0x00013d7f
            .word 0x00060004
            .hword 0x5603
            .word 0x00014347
            .word 0x00060004
            .hword 0x2603
            .word 0x00013f1d
            .word 0x00060005
            .hword 0xffff
        """

# write code1 into SRAM
codeBytes = asm(code, vma=0x2006d0)
internalblue.writeMem(0x2006d0, codeBytes)

# patch pointer to bthci_cmd_GetCmdHandle
internalblue.writeMem(0x206b04, struct.pack("<I", 0x2006d1))

# shut down
internalblue.shutdown()
exit(-1)
log.info("Debloated hci commands")
