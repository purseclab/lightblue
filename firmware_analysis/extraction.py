import sys
import angr
import struct
import logging
from IPython import embed
logging.disable(logging.CRITICAL)

# dev board
dev_bin_path = "../firmware/CYPRESS920735Q60EVB-01.bin"
dev_addr = 0x18741
dev_ogf_reg = "r7"
dev_ocf_reg = "r6"
dev_handler_addr = 0x18841
dev_handler_reg = "r3"

# rasp 
rasp_bin_path = "../firmware/BCM2837 (Raspberry pi 3).bin"
rasp_addr = 0x1bf39
rasp_ogf_reg = "r9"
rasp_ocf_reg = "r8"
rasp_handler_addr = 0x1bffd
rasp_handler_reg = "r3"

# nexus 
nexus_bin_path = "../firmware/BCM4339 (Nexus 5).bin"
nexus_addr = 0x99e1
nexus_ogf_reg = "r0"
nexus_ocf_reg = "r1"
nexus_handler_addr = 0x9a13
nexus_handler_reg = "r0"


# bluetooth opcode
opcode_list = [(0x1, 0x45), (0x2, 0x11), (0x3, 0x83), (0x4, 0x0f), (0x5, 0x0d),
               (0x6, 0x0a), (0x8, 0x7a), (0x3f, 0xff)]


def get_entry_point(path):
    '''
    we assume arch = ARM Cortex-M (little endian)
    For all Cortex M, the second word (at address 0x4) 
    indicates the address of entry point
    '''
    with open(path, mode='rb') as bin:
        bin_content = bin.read()
        return hex(struct.unpack('<L', bin_content[4:8])[0])


def main(argv):
    if argv[0] == "dev":
        bin_path = dev_bin_path
        start_addr = dev_addr
        ogf_reg = dev_ogf_reg
        ocf_reg = dev_ocf_reg
        handler_addr = dev_handler_addr
        handler_reg = dev_handler_reg
    elif argv[0] == "rasp":
        bin_path = rasp_bin_path
        start_addr = rasp_addr
        ogf_reg = rasp_ogf_reg
        ocf_reg = rasp_ocf_reg
        handler_addr = rasp_handler_addr
        handler_reg = rasp_handler_reg
    elif argv[0] == "nexus":
        bin_path = nexus_bin_path
        start_addr = nexus_addr
        ogf_reg = nexus_ogf_reg
        ocf_reg = nexus_ocf_reg
        handler_addr = nexus_handler_addr
        handler_reg = nexus_handler_reg
    else:
        raise ValueError('mode error!')

    entry_point = get_entry_point(bin_path)
    print("entry point: ", entry_point)
    proj = angr.Project(bin_path,
                        main_opts={
                            'arch': 'thumb',
                            'backend': 'blob',
                            'entry_point': int(entry_point, 16)
                        })

    def step_func(lsm):
        lsm.stash(filter_func=lambda state: state.addr == handler_addr,
                  from_stash='active',
                  to_stash="found")
        return lsm

    handler_dic = {}

    # it takes a while
    for op_pair in opcode_list:
        ogf = op_pair[0]
        handler_dic[ogf] = {}

        for ocf in range(0x1, op_pair[1]):
            handler_dic[ogf][ocf] = []

            # setup
            state = proj.factory.blank_state(addr=start_addr)
            exec("state.regs." + ogf_reg + " = " + str(ogf))
            exec("state.regs." + ocf_reg + " = " + str(ocf))
            simgr = proj.factory.simgr(state)

            # SE
            step_count = 0
            while step_count < 500:
                step_count = step_count + 1
                simgr.step(num_inst=1, step_func=step_func)

            print("finish SE for (%x, %x)" % (ogf, ocf))

            # get handler
            for state in simgr.found:
                exec("handler = state.regs." + handler_reg + ".args[0]")
                if handler not in handler_dic[ogf][ocf]:
                    handler_dic[ogf][ocf].append(handler)

            print("(%x, %x) :" % (ogf, ocf))
            for item in handler_dic[ogf][ocf]:
                print(hex(item))
            print()

        ogf_common_list = set()
        for ocf in handler_dic[ogf]:
            ogf_common_list = ogf_common_list.union(handler_dic[ogf][ocf])
        # print("(%x): %d" % (ogf, len(ogf_list)))

        for ocf in range(0x1, op_pair[1]):
            new_list = []
            for item in handler_dic[ogf][ocf]:
                if item not in ogf_common_list:
                    new_list.append(item)
            handler_dic[ogf][ocf] = new_list
            print("(%x, %x) : " % (ogf, ocf), handler_dic[ogf][ocf])


if __name__ == "__main__":
    main(sys.argv[1:])
