# Usefull for detecting EOP in packed PE. Give an output for xdbg

import idaapi
import idc
import idautils

bp = []

def Find_suspicious():
    msg("=== Suspicious CALLs to dword_* ===\n")
    for function in idautils.Functions():
        
        flags = get_func_attr(function, FUNCATTR_FLAGS)
        if flags & FUNC_LIB or flags & FUNC_THUNK:
            continue

        
        for x in idautils.FuncItems(function):
            
            if idc.print_insn_mnem(x) == "call":
            
                # CALL as memory ref
                if idc.get_operand_type(x, 0) == o_mem:
                    dest = get_operand_value(x, 0)
                    name = get_name(dest, GN_LONG)
                    if name and name.startswith("dword_"):
                        idc.set_color(x,CIC_ITEM,0xA1A600) 
                        idc.set_color(x,CIC_FUNC,0xB1C813)
                        msg(hex(x) + " " + idc.generate_disasm_line(x,0)) 
                        bp.append(x)  
                
                #CALL REG
                elif idc.get_operand_type(x,0) == o_reg:
                    idc.set_color(x,CIC_ITEM,0xA1A600) 
                    idc.set_color(x,CIC_FUNC,0xB1C813)
                    print(hex(x) + " " + idc.generate_disasm_line(x,0))
                    bp.append(x)
                
                #CALL [REG]
                elif idc.get_operand_type(x,0) == o_phrase:
                    brackets = idc.print_operand(x,0)
                    brackets = brackets[brackets.index('[')+1 : brackets.index(']')]
                    if "+" not in brackets:
                        idc.set_color(x, CIC_ITEM,0xA1A600)
                        idc.set_color(x,CIC_FUNC,0xB1C813)
                        print(hex(x) + " " + idc.generate_disasm_line(x,0))
                        bp.append(x)
                        
                
            elif idc.print_insn_mnem(x) == "jmp":
                # JMP as memory ref
                if idc.get_operand_type(x, 0) == o_mem:
                    dest = get_operand_value(x, 0)
                    name = get_name(dest, GN_LONG)
                    if name and name.startswith("dword_"):
                        idc.set_color(x,CIC_ITEM,0xA1A600) 
                        idc.set_color(x,CIC_FUNC,0xB1C813)
                        msg(hex(x) + " " + idc.generate_disasm_line(x,0))  
                        bp.append(x)                          
                
                #JMP REG
                elif idc.get_operand_type(x,0) == o_reg:
                    idc.set_color(x,CIC_ITEM,0xA1A600) 
                    idc.set_color(x,CIC_FUNC,0xB1C813)
                    print(hex(x) + " " + idc.generate_disasm_line(x,0)) 
                    bp.append(x)
                    
                #JMP [REG]
                elif idc.get_operand_type(x,0) == o_phrase:
                    brackets = idc.print_operand(x,0)
                    brackets = brackets[brackets.index('[')+1 : brackets.index(']')]
                    if "+" not in brackets:
                        idc.set_color(x, CIC_ITEM,0xA1A600)
                        idc.set_color(x,CIC_FUNC,0xB1C813)
                        print(hex(x) + " " + idc.generate_disasm_line(x,0))
                        bp.append(x)
                    
            elif idc.print_insn_mnem(x) == "cpuid":
                    idc.set_color(x,CIC_ITEM,0xA1A600) 
                    idc.set_color(x,CIC_FUNC,0xB1C813)
                    print(hex(x) + " " + idc.generate_disasm_line(x,0)) 
                    #bp.append(x) 
                    
            elif idc.print_insn_mnem(x) == "rdtsc":
                    idc.set_color(x,CIC_ITEM,0xA1A600) 
                    idc.set_color(x,CIC_FUNC,0xB1C813)
                    print(hex(x) + " " + idc.generate_disasm_line(x,0)) 
                    #bp.append(x) 
                            
    
def FindUnknownFunctions():
    print("Looking for unknown functions – passe 1")
    seg = idaapi.get_segm_by_name(".text")
    start = seg.start_ea
    BAD = idaapi.BADADDR

    # First method
    ea = idaapi.find_not_func(start, idaapi.SEARCH_DOWN)
    while ea != BAD:
        idaapi.add_func(ea)
        ea = idaapi.find_not_func(ea + 1, idaapi.SEARCH_DOWN)

    print("Looking for unknown functions – passe 2")
    # Second method define each functions end
    ea = idaapi.find_not_func(start, idaapi.SEARCH_DOWN)
    while ea != BAD:
        end_ea = idaapi.find_data(ea, idaapi.SEARCH_DOWN)
        if end_ea == BAD or end_ea > seg.end_ea:
            end_ea = seg.end_ea
        idaapi.add_func(ea, end_ea)
        ea = idaapi.find_not_func(ea + 1, idaapi.SEARCH_DOWN)

    

FindUnknownFunctions()
Find_suspicious()
print("\n\n---------------------------------- start xdbg script ---------------------------------- \n\n")
for mybp in bp:
    print("bp "+ hex(mybp))
print("---------------------------------- end xdbg script ----------------------------------")
print("Done!")
