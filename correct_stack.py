import idaapi
import idc
import idautils
import re

def extract_stack_offsets_from_pseudocode(func_ea):
    """
    Extract every STACK offset from pseudo-code 
    """
    stack_offsets = {} 
    
    try:
        cfunc = idaapi.decompile(func_ea)
        text = str(cfunc)
        
        # Extract STACK[0x...]
        for match in re.finditer(r'STACK\[0x([0-9A-Fa-f]+)\]', text):
            offset = int(match.group(1), 16)
            stack_offsets[offset] = stack_offsets.get(offset, 0) + 1

        # Extract from lvars
        lvars = cfunc.get_lvars()
        for lvar in lvars:
            if lvar.is_stk_var():
                offset = lvar.get_stkoff()
                if offset >= 0:
                    stack_offsets[offset] = stack_offsets.get(offset, 0) + 1
        
    except Exception as e:
        print(f"  [!] Error: {e}")
    
    return stack_offsets

def find_esp_instruction_at_address(ea):
    """
    Extract offset ESP of a given instruction
    """
    try:
        disasm = idc.GetDisasm(ea).lower()
        
        # Method 1 : Via API
        for i in range(idaapi.UA_MAXOP):
            op_type = idc.get_operand_type(ea, i)
            if op_type in [idc.o_displ, idc.o_phrase]:
                op_str = idc.print_operand(ea, i).lower()
                if 'esp' in op_str or 'rsp' in op_str:
                    offset = idc.get_operand_value(ea, i)
                    # Normalize negative offsets
                    if offset > 0x7FFFFFFF:
                        offset = offset - 0x100000000
                    return offset

        # Method 2: Regex on disasm
        match = re.search(r'\[esp[\+\-]([0-9A-Fa-f]+)h?\]', disasm, re.IGNORECASE)
        if match:
            offset = int(match.group(1), 16)
            if '-' in match.group(0):
                offset = -offset
            return offset
            
    except:
        pass
    
    return None

def force_align_stack_offsets(func_ea, dry_run=True):
    """
    Force alignment between assembler and pseudo-code

    1. Find all STACK[X] from pseudo-code
    2. For each [esp+Y] from assembler, find the closest STACK[X]
    3. Force SP delta so that esp+Y points to STACK[X]
    """
    print(f"\n{'[DRY RUN] ' if dry_run else ''}[*] FORCE ALIGNMENT - Function 0x{func_ea:X}")

    func = idaapi.get_func(func_ea)
    if not func:
        print("[!] No function")
        return 0
    
    func_name = idc.get_func_name(func_ea)
    frame_size = idc.get_func_attr(func_ea, idc.FUNCATTR_FRSIZE)
    
    print(f"[*] Function: {func_name}")
    print(f"[*] Frame size: 0x{frame_size:X} ({frame_size} bytes)\n")

    # 1. Extract STACK offsets from pseudo-code
    stack_offsets = extract_stack_offsets_from_pseudocode(func_ea)
    
    if not stack_offsets:
        print("[!] No STACK offset found in pseudo-code")
        return 0
    
    sorted_offsets = sorted(stack_offsets.keys())
    print(f"[*] {len(sorted_offsets)} unique STACK offset(s):")

    # Show most frequent offsets
    frequent = sorted(stack_offsets.items(), key=lambda x: x[1], reverse=True)[:10]
    for offset, count in frequent:
        print(f"    STACK[0x{offset:X}] ({offset}) - {count}x")
    print()

    # 2. Scan all [esp+X] instructions
    alignments = []  # List of (ea, esp_offset, target_stack_offset, new_sp)

    for head in idautils.Heads(func.start_ea, func.end_ea):
        esp_offset = find_esp_instruction_at_address(head)
        if esp_offset is None:
            continue
        
        disasm = idc.GetDisasm(head)
        mnem = idc.print_insn_mnem(head)
        current_sp = idc.get_spd(head)

        # Find closest STACK offset
        best_stack_offset = min(sorted_offsets, key=lambda x: abs(x - (esp_offset - current_sp)))

        # Calculate new SP needed
        new_sp = esp_offset - best_stack_offset

        # Check if a change is needed
        current_result = esp_offset - current_sp

        # Always force alignment if a corresponding STACK is found
        # even if the current result seems "correct"
        if abs(new_sp - current_sp) > 2:  # Tolerance of 2 bytes
            alignments.append({
                'ea': head,
                'esp_offset': esp_offset,
                'current_sp': current_sp,
                'current_result': current_result,
                'target_stack': best_stack_offset,
                'new_sp': new_sp,
                'mnem': mnem,
                'disasm': disasm
            })
    
    if not alignments:
        print("[+] All ESP offsets are already aligned!")
        return 0

    # 3. Show alignments to be made
    print(f"[*] {len(alignments)} alignment(s) to be made:\n")

    for a in alignments[:10]:
        print(f"0x{a['ea']:X}: {a['disasm']}")
        print(f"  [esp+0x{a['esp_offset']:X}] (esp_offset={a['esp_offset']})")
        print(f"  Current: SP={a['current_sp']:5d} -> offset {a['current_result']:5d}")
        print(f"  Target:  STACK[0x{a['target_stack']:X}] ({a['target_stack']})")
        print(f"  New SP:  {a['new_sp']:5d} -> STACK[0x{a['target_stack']:X}] ✓")
        print()
    
    if len(alignments) > 10:
        print(f"  ... and {len(alignments) - 10} more\n")

    # 4. Apply fixes
    if not dry_run:
        print(f"[*] Applying {len(alignments)} alignment(s)...\n")
        applied = 0
        
        for a in alignments:
            try:
                idc.add_user_stkpnt(a['ea'], a['new_sp'])
                applied += 1
                if applied <= 10:  # Afficher les 10 premiers
                    print(f"  [+] 0x{a['ea']:X}: SP {a['current_sp']} -> {a['new_sp']}")
            except Exception as e:
                print(f"  [!] 0x{a['ea']:X}: Error: {e}")
        
        if applied > 10:
            print(f"  [+] ... and {applied - 10} more")

        print(f"\n[+] {applied}/{len(alignments)} alignment(s) applied")
        
        if applied > 0:
            print("\n[*] Recompilation...")
            try:
                idaapi.decompile(func_ea)
                print("[+] OK!")
                print("\n" + "="*60)
                print("F5 to refresh IDA or close and reopen")
                print("="*60)
            except Exception as e:
                print(f"[!] Error: {e}")
        
        return applied
    else:
        print(f"\n[DRY RUN] {len(alignments)} alignment(s) would be applied")
        return 0

def manual_fix_instruction(ea, target_stack_offset):
    """
    Manually fix a specific instruction
    Usage: manual_fix_instruction(0x4160A7, 0xC74)
    """
    esp_offset = find_esp_instruction_at_address(ea)
    if esp_offset is None:
        print(f"[!] No [esp+X] instruction found at 0x{ea:X}")
        return False
    
    new_sp = esp_offset - target_stack_offset
    current_sp = idc.get_spd(ea)
    
    print(f"[*] Instruction: {idc.GetDisasm(ea)}")
    print(f"[*] ESP offset: 0x{esp_offset:X} ({esp_offset})")
    print(f"[*] Current SP: {current_sp} -> offset {esp_offset - current_sp}")
    print(f"[*] Target: STACK[0x{target_stack_offset:X}] ({target_stack_offset})")
    print(f"[*] New SP: {new_sp}")
    
    try:
        idc.add_user_stkpnt(ea, new_sp)
        print(f"[+] SP delta applied!")

        func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
        idaapi.decompile(func_ea)
        print("[+] Recompiled - Close and reopen IDA or press F5")
        return True
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def show_instruction_info(ea=None):
    """
    Show all info about an instruction
    If ea=None, use the current address
    """
    if ea is None:
        ea = idc.here()
    
    func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    if func_ea == idc.BADADDR:
        print("[!] No function")
        return

    print(f"\n[*] Analyzing 0x{ea:X}")
    print(f"[*] Disasm: {idc.GetDisasm(ea)}")
    
    esp_offset = find_esp_instruction_at_address(ea)
    if esp_offset is None:
        print("[!] No [esp+X] instruction found")
        return
    
    current_sp = idc.get_spd(ea)
    result = esp_offset - current_sp
    
    print(f"\n[*] ESP offset: 0x{esp_offset:X} ({esp_offset})")
    print(f"[*] SP delta: {current_sp}")
    print(f"[*] Result: {result} (0x{result:X} is positive)")

    # Find corresponding STACK
    stack_offsets = extract_stack_offsets_from_pseudocode(func_ea)
    if stack_offsets:
        sorted_offsets = sorted(stack_offsets.keys())
        closest = min(sorted_offsets, key=lambda x: abs(x - result))
        print(f"\n[*] Closest STACK: 0x{closest:X} ({closest})")
        print(f"[*] Difference: {abs(result - closest)} bytes")
        
        if abs(result - closest) > 4:
            new_sp = esp_offset - closest
            print(f"\n[!] SUGGESTED CORRECTION:")
            print(f"    manual_fix_instruction(0x{ea:X}, 0x{closest:X})")
            print(f"    New SP: {new_sp}")

def fix_current_function(dry_run=True):
    """
    Correct the function with the new algorithm
    """
    ea = idc.here()
    func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    
    if func_ea == idc.BADADDR:
        print("[!] No function")
        return
    
    return force_align_stack_offsets(func_ea, dry_run)

def undo_all_sp_changes():
    """
    Remove every modification made by this script
    """
    print("[*] Removing all custom SP deltas...")
    count = 0
    
    for func_ea in idautils.Functions():
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        for head in idautils.Heads(func.start_ea, func.end_ea):
            try:
                idc.del_user_stkpnt(head)
                count += 1
            except:
                pass
    
    print(f"[+] {count} custom SP delta(s) removed")

if __name__ == "__main__":
    print("="*60)
    print("IDA SP Delta Fixer - FORCE ALIGNMENT v4")
    print("="*60)
    print("\nNew approach:")
    print("  - Force alignment between [esp+X] and STACK[Y]")
    print("  - No longer searches for errors, ENFORCES consistency")
    print("  - More tolerant and aggressive")
    print("\nMain commands:")
    print("  fix_current_function()           - Analyze (DRY RUN)")
    print("  fix_current_function(False)      - FIX")
    print("\nAdvanced commands:")
    print("  show_instruction_info()          - Show current instruction info")
    print("  show_instruction_info(0xADDR)    - Show specific instruction info")
    print("  manual_fix_instruction(ea, off)  - Manual correction")
    print("  undo_all_sp_changes()            - Undo all changes")
    print("="*60)
