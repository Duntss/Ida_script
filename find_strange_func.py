#Find werid call dwords in IDA based on ida_find_func.py
import idaapi
import idc
import idautils

def Find_suspicious():
    msg("=== Suspicious CALLs to dword_* ===\n")
    for function in idautils.Functions():
        # Ignore function from LIB or THUNK
        flags = get_func_attr(function, FUNCATTR_FLAGS)
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            continue

        # Goes in every instruction of the function
        for x in idautils.FuncItems(function):
            # filter for call
            if idc.print_insn_mnem(x) == "call":
                # Direct call via memory operand
                if idc.get_operand_type(x, 0) == o_mem:
                    dest = get_operand_value(x, 0)
                    name = get_name(dest, GN_LONG)
                    if name and name.startswith("dword_"):
                        msg("0x%08X  ->  %s\n" % (x, name))     
        
        
    
def FindUnknownFunctions():
    print("Looking for unknown functions – passe 1")
    seg = idaapi.get_segm_by_name(".text")
    start = seg.start_ea
    BAD = idaapi.BADADDR

    ea = idaapi.find_not_func(start, idaapi.SEARCH_DOWN)
    while ea != BAD:
        idaapi.add_func(ea)
        ea = idaapi.find_not_func(ea + 1, idaapi.SEARCH_DOWN)

    print("Looking for unknown functions – passe 2")
    ea = idaapi.find_not_func(start, idaapi.SEARCH_DOWN)
    while ea != BAD:
        end_ea = idaapi.find_data(ea, idaapi.SEARCH_DOWN)
        if end_ea == BAD or end_ea > seg.end_ea:
            end_ea = seg.end_ea
        idaapi.add_func(ea, end_ea)
        ea = idaapi.find_not_func(ea + 1, idaapi.SEARCH_DOWN)

    print("Done!")

FindUnknownFunctions()
Find_suspicious()
