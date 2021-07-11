import sys
import angr
import claripy
import monkeyhex
import pyvex
import logging
import struct
import pickle
from tqdm import tqdm

# make the angr quite
logging.disable(logging.CRITICAL)

# mode
MODE = None
'''
BD_ADDR handler address, they are acquired by
    1. searching BDADDR in the firmware binary
    2. locating the func that reference BDADDR
'''
DEV_BDADDR_HANDLER_ADDR = 0x3ec59
RASP_BDADDR_HANDLER_ADDR = 0x259b5
NEXUS_BDADDR_HANDLER_ADDR = 0x651bf


def get_entry_point(path):
    '''
    we assume arch = ARM Cortex-M (little endian)
    For all Cortex M, the second word (at address 0x4) 
    indicates the address of entry point
    '''
    with open(path, mode='rb') as bin:
        bin_content = bin.read()
        return hex(struct.unpack('<L', bin_content[4:8])[0])


def naive_scanning(funcs, hci_cmd_disp_cand):
    '''
    Search for "shift" and "and" operators, 
    which are usually used for bit extraction
    '''
    print("---naive scanning---")
    for f_n in tqdm(funcs):
        OGF_flag = False
        OCF_flag = False
        OGF_src = 0
        OCF_src = 0
        for bb in funcs[f_n].blocks:
            try:
                irsb = bb.vex
                for stmt in irsb.statements:
                    if isinstance(stmt, pyvex.stmt.WrTmp):
                        if isinstance(stmt.data, pyvex.expr.Binop):
                            # OGF pattern
                            if stmt.data.op == "Iop_And32":
                                if isinstance(stmt.data.args[1],
                                              pyvex.expr.Const):
                                    if stmt.data.args[1].con.value == 0xfc00:
                                        OGF_src = stmt.data.args[0]
                                        OGF_flag = True
                            if stmt.data.op == "Iop_Shr32":
                                if isinstance(stmt.data.args[1],
                                              pyvex.expr.Const):
                                    if stmt.data.args[1].con.value == 0x0a:
                                        OGF_src = stmt.data.args[0]
                                        OGF_flag = True
                            # OCF pattern
                            if stmt.data.op == "Iop_And32":
                                if isinstance(stmt.data.args[1],
                                              pyvex.expr.Const):
                                    if stmt.data.args[1].con.value == 0x3ff:
                                        OCF_src = stmt.data.args[0]
                                        OCF_flag = True
                            if stmt.data.op == "Iop_Shl32":
                                if isinstance(stmt.data.args[1],
                                              pyvex.expr.Const):
                                    if stmt.data.args[1].con.value == 0x06:
                                        OCF_src = stmt.data.args[0]
                                        OCF_flag = True
            except:
                pass

        if OGF_flag and OCF_flag:
            if OGF_src == OCF_src:
                # print("---------------------------")
                # print(hex(f_n))
                # print("OGF src: ", OGF_src)
                # print("OCF src: ", OCF_src)
                # hci_cmd_disp_cand.append((f_n, OGF_src))
                hci_cmd_disp_cand.append(f_n)

    return hci_cmd_disp_cand


def is_in_func(func_addr, addr, funcs):
    '''
    check if addr is in range of func@func_addr
    '''
    for bb in funcs[func_addr].blocks:
        if addr > bb.addr and addr < bb.addr + bb.size:
            return True
    return False


def check_symbolic_pattern(state):
    '''
    Check if there exist 3 registers x, y, z, 
    where x[0:9] == y and x[10:15] == z
    For ARM, R0-R10 are used for general purpose

    @ ret: [if pattern exist, opcode reg, ogf reg, ocf reg]
    '''

    # push all registers into regs
    regs = []
    regs.append(state.regs.r0)
    regs.append(state.regs.r1)
    regs.append(state.regs.r2)
    regs.append(state.regs.r3)
    regs.append(state.regs.r4)
    regs.append(state.regs.r5)
    regs.append(state.regs.r6)
    regs.append(state.regs.r7)
    regs.append(state.regs.r8)
    regs.append(state.regs.r9)
    regs.append(state.regs.r10)

    for x_idx in range(len(regs)):
        for y_idx in range(len(regs)):
            for z_idx in range(len(regs)):

                if x_idx == y_idx or x_idx == z_idx or y_idx == z_idx:
                    continue

                x_val = regs[x_idx]  # opcode
                y_val = regs[y_idx]  # OGF
                z_val = regs[z_idx]  # OCF

                # check OGF
                sol = claripy.Solver()
                sol.add(x_val[15:10].zero_extend(26) != y_val)
                OGF_pattern = not sol.satisfiable()

                # check OCF
                sol = claripy.Solver()
                sol.add(x_val[9:0].zero_extend(22) != z_val)
                OCF_pattern = not sol.satisfiable()

                if (OGF_pattern and OCF_pattern):
                    return True, x_idx, y_idx, z_idx

    return False, None, None, None


def symbolic_scanning(proj, funcs, hci_cmd_disp_cand):
    '''
    For each func, check the state of depth at most STEP_LIMIT 
    '''
    print("---symbolic scanning---")
    hci_cmd_disp_cand_ret = []
    for f_n in tqdm(hci_cmd_disp_cand):
        target_entry_state = proj.factory.blank_state(addr=f_n)
        target_simgr = proj.factory.simgr(target_entry_state)

        func_flag = False

        step = 0
        STEP_LIMIT = 10

        while step < STEP_LIMIT:

            target_simgr.step(num_inst=1)
            step += 1

            for state in target_simgr.active:
                if not is_in_func(f_n, state.addr, funcs):
                    continue
                check_result = check_symbolic_pattern(state)
                if check_result[0]:
                    func_flag = True
                    hci_cmd_disp_cand_ret.append(
                        (f_n, state.addr, check_result[1], check_result[2],
                         check_result[3]))
                    break
                else:
                    continue

            # this func has already been marked as candidate
            if func_flag:
                break

    return hci_cmd_disp_cand_ret


def symbolic_verification(proj, hci_cmd_disp_cand):
    hci_cmd_disp_cand_verified = []

    for cand in hci_cmd_disp_cand:
        target_entry_state = proj.factory.blank_state(addr=cand[1])

        OGF_src_name = "target_entry_state.regs.r" + str(cand[3])
        OCF_src_name = "target_entry_state.regs.r" + str(cand[4])
        exec(OGF_src_name + " = 0x04")
        exec(OCF_src_name + " = 0x09")
        simgr = proj.factory.simgr(target_entry_state)

        def step_func(lsm):
            if MODE == 'DEV':
                lsm.stash(filter_func=lambda state: state.addr ==
                          DEV_BDADDR_HANDLER_ADDR,
                          from_stash='active',
                          to_stash="found")
            if MODE == 'RASP':
                lsm.stash(filter_func=lambda state: state.addr ==
                          RASP_BDADDR_HANDLER_ADDR,
                          from_stash='active',
                          to_stash="found")
            if MODE == 'NEXUS':
                lsm.stash(filter_func=lambda state: state.addr ==
                          NEXUS_BDADDR_HANDLER_ADDR,
                          from_stash='active',
                          to_stash="found")
            return lsm

        step_count = 0
        STEP_LIMIT = 500
        pbar = tqdm(total=STEP_LIMIT, position=0, leave=True)
        while step_count < STEP_LIMIT:
            step_count = step_count + 1
            pbar.update(1)
            simgr.step(num_inst=1, step_func=step_func)
            if len(simgr.found) > 0:
                print('reach!')
                break

        simgr.move(from_stash='active',
                   to_stash='found',
                   filter_func=lambda s: True)
        simgr.move(from_stash='found',
                   to_stash='active',
                   filter_func=lambda s: s.addr == 0x3ec59)

        # at the same time, we know where to find handler addr
        hci_cmd_disp_cand_verified.append(cand)

    return hci_cmd_disp_cand_verified


def identification(proj, cfg, funcs):
    '''
    HCI command dispatcher candidate identification
    we have two steps:
        1. Naive scanning
            a naive pattern-matching, which only checks certain operators
        2. Symbolic scanning
            a more precise filter, but with significantly larger overhead
        3. Verification
            feed a special opcode, check if expected value is visited
    '''
    hci_cmd_disp_cand = []

    # Naive scanning (optional)
    hci_cmd_disp_cand = naive_scanning(funcs, hci_cmd_disp_cand)
    assert len(hci_cmd_disp_cand) >= 1

    # Symbolic scanning
    hci_cmd_disp_cand = symbolic_scanning(proj, funcs, hci_cmd_disp_cand)
    assert len(hci_cmd_disp_cand) >= 1

    # TODO: src tracing

    # Verification
    hci_cmd_disp_cand = symbolic_verification(proj, hci_cmd_disp_cand)
    assert len(hci_cmd_disp_cand) >= 1

    if len(hci_cmd_disp_cand) > 1:
        # TODO: more than one func is identified
        print("More than one func is identified!")
    return hci_cmd_disp_cand[0]


def main(argv):
    global MODE

    if argv[0] == "dev":
        MODE = "DEV"
        bin_path = "../firmware/CYPRESS920735Q60EVB-01.bin"
    elif argv[0] == "rasp":
        MODE = "RASP"
        bin_path = "../firmware/BCM2837 (Raspberry pi 3).bin"
    elif argv[0] == "nexus":
        MODE = "NEXUS"
        bin_path = "../firmware/BCM4339 (Nexus 5).bin"
    else:
        raise ValueError('mode error!')


    entry_point = int(get_entry_point(bin_path), 16)
    if MODE == "DEV":
        assert entry_point == 0x03bd
    elif MODE == "NEXUS":
        assert entry_point == 0x0201

    proj = angr.Project(bin_path,
                        main_opts={
                            'arch': 'thumb',
                            'backend': 'blob',
                            'entry_point': entry_point
                        })

    # Building CFG, it takes around 10 mins (on my desktop)
    # if it takes too long for you, you can try pypy: https://github.com/angr/angr-dev
    cfg = proj.analyses.CFGFast(show_progressbar=True)
    # cfg = pickle.load(open("cfg.p", "rb"))
    funcs = cfg.kb.functions

    # hci command dispatcher identification
    hci_cmd_disp = identification(proj, cfg, funcs)


if __name__ == "__main__":
    main(sys.argv[1:])
