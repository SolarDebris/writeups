import angr
import claripy
import sys
from pwn import *



def main(argv):
    binary_path = './armgrad-400'


    good_strings = [b'Good', b'good',  b'Succ', b'succ', b'ongrat']
    bad_strings = [b'Fail',b'fail',  b'Try', b'enied', b'ncorrect', b'pay']

    #start_addr =

    FLAG_LEN=32
    flag_chars = [claripy.BVS("x", 8) for i in range(FLAG_LEN)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])


    proj = angr.Project(binary_path)
    state = proj.factory.entry_state(
            stdin=flag,
            #addr=start_addr,
            add_options = {
                angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            }
    )
    #good_address = proj.loader.find_symbol('win').rebased_addr
    #bad_address =


    for k in flag_chars:
        state.solver.add(
            claripy.Or(
                claripy.And(k >= ord('0'), k <= ord('9')),
                claripy.And(k >= ord('a'), k <= ord('f'))
            )
        )


    def is_successful(state):
        output = state.posix.dumps(sys.stdout.fileno())
        for i in good_strings:
            if i in output:
                return True

    def should_abort(state):
        output = state.posix.dumps(sys.stdout.fileno())
        for i in bad_strings:
            if i in output:
                return True

    sim = proj.factory.simgr(state)


    sim.explore(find=is_successful, avoid=should_abort)
    #sim.explore(find=good_address, avoid=bad_address)

    if sim.found:
        print("[+] Success found a solution")
        solve = sim.found[0]
        output = solve.posix.dumps(sys.stdin.fileno())
        #p = process(binary_path)
        #p.sendline(output)
        #p.interactive()
        for solve in sim.found:
            print(solve.posix.dumps(sys.stdin.fileno()).decode('utf-8'))
    else:
        raise Exception("[-] Couldn't find a solution")


if __name__=="__main__":
    main(sys.argv)
