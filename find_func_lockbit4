# Used for reverse lockbit 4.0. IDA don't automaticly create function this script solve me the problem.

import idaapi
import idc

def create_funcs_after_int3(min_len=1):
    """
    Scan executable segments for runs of 0xCC (INT3).
    When a run of length >= min_len is found, attempt to create a function
    at the first byte after the run.
    """
    print("Scanning executable segments for INT3/0xCC runs")

    # iterate all segments and pick executable ones
    seg = idaapi.get_first_seg()
    if not seg:
        print("No segments found")
        return

    while seg:
        # prefer executable segments; fallback to .text if perms constant is missing
        try:
            is_exec = bool(seg.perm & idaapi.SEGPERM_EXEC)
        except Exception:
            is_exec = (idaapi.get_segm_name(seg) == ".text")
        if is_exec:
            start = seg.start_ea
            end = seg.end_ea
            ea = start
            while ea < end:
                b = idc.get_wide_byte(ea)
                if b == 0xCC:
                    run_start = ea
                    while ea < end and idc.get_wide_byte(ea) == 0xCC:
                        ea += 1
                    run_len = ea - run_start
                    if run_len >= min_len:
                        func_start = ea  # first byte after INT3 run
                        # don't create if already in a function
                        if idaapi.get_func(func_start) is None:
                            # try to create an instruction at func_start to ensure code flow
                            created = idc.create_insn(func_start)
                            try:
                                # attempt to add function; ignore failures
                                idaapi.add_func(func_start)
                                print("Added function at 0x{:X} (INT3 run at 0x{:X}, len={})".format(func_start, run_start, run_len))
                            except Exception as e:
                                # if add_func fails, continue scanning
                                print("add_func failed at 0x{:X}: {}".format(func_start, e))
                else:
                    ea += 1
        seg = idaapi.get_next_seg(seg.start_ea)

    print("Done")

# example: set min_len=1 to catch single INT3 followed by code (as in your sample)
create_funcs_after_int3(min_len=1)
