import idaapi
import idc
import idautils
import re

def find_all_esp_references(func):
    """
    Trouve TOUTES les instructions qui référencent [esp+offset]
    """
    esp_instructions = []
    
    for head in idautils.Heads(func.start_ea, func.end_ea):
        disasm = idc.GetDisasm(head)
        
        # Chercher [esp+offset] ou [esp-offset]
        match = re.search(r'\[esp[\+\-]([0-9A-Fa-f]+)h?\]', disasm, re.IGNORECASE)
        if match:
            offset_str = match.group(1)
            offset = int(offset_str, 16)
            
            # Déterminer si c'est + ou -
            if '-' in match.group(0):
                offset = -offset
            
            mnem = idc.print_insn_mnem(head)
            esp_instructions.append((head, offset, mnem, disasm))
    
    return esp_instructions

def analyze_and_fix_all_esp_references(func_ea, dry_run=False):
    """
    Corrige TOUTES les références à [esp+offset], pas seulement LEA
    """
    print(f"\n{'[DRY RUN] ' if dry_run else ''}[*] Analyse COMPLÈTE de la fonction à 0x{func_ea:X}")
    
    func = idaapi.get_func(func_ea)
    if not func:
        print(f"[!] Pas de fonction trouvée")
        return 0
    
    frame_size = idc.get_func_attr(func_ea, idc.FUNCATTR_FRSIZE)
    print(f"[*] Taille frame: 0x{frame_size:X} ({frame_size} bytes)")
    
    # Obtenir tous les offsets STACK du pseudo-code
    stack_offsets = set()
    try:
        cfunc = idaapi.decompile(func_ea)
        text = str(cfunc)
        pattern = r'STACK\[0x([0-9A-Fa-f]+)\]'
        for match in re.finditer(pattern, text):
            stack_offsets.add(int(match.group(1), 16))
        print(f"[*] Offsets STACK trouvés: {sorted(stack_offsets)}")
    except Exception as e:
        print(f"[!] Erreur analyse pseudo-code: {e}")
        return 0
    
    if not stack_offsets:
        print("[!] Aucun offset STACK trouvé")
        return 0
    
    # Trouver TOUTES les instructions [esp+offset]
    esp_instructions = find_all_esp_references(func)
    if not esp_instructions:
        print("[*] Aucune référence [esp+offset] trouvée")
        return 0
    
    print(f"[*] {len(esp_instructions)} instructions avec [esp+offset] trouvées")
    
    # Grouper les corrections par adresse pour éviter les doublons
    fixes_by_address = {}
    errors_found = 0
    
    for ea, esp_offset, mnem, disasm in esp_instructions:
        current_sp = idc.get_spd(ea)
        current_stack_offset = esp_offset - current_sp
        
        # Vérifier si c'est une erreur
        is_error = current_stack_offset < 0 or current_stack_offset > frame_size * 3
        
        if is_error:
            errors_found += 1
            
            # Trouver le meilleur offset STACK correspondant
            best_target = None
            best_diff = float('inf')
            
            for stack_offset in stack_offsets:
                needed_sp = esp_offset - stack_offset
                diff = abs(needed_sp - current_sp)
                
                if abs(needed_sp) < frame_size * 2 and diff < best_diff:
                    best_diff = diff
                    best_target = (stack_offset, needed_sp)
            
            if best_target and ea not in fixes_by_address:
                target_offset, new_sp = best_target
                fixes_by_address[ea] = (new_sp, esp_offset, current_sp, current_stack_offset, target_offset, mnem, disasm)
    
    # Afficher les corrections nécessaires
    if errors_found > 0:
        print(f"\n[!] {errors_found} erreur(s) détectée(s)")
        print(f"[*] {len(fixes_by_address)} correction(s) unique(s) à appliquer:\n")
        
        for ea in sorted(fixes_by_address.keys()):
            new_sp, esp_off, curr_sp, curr_stack, target, mnem, disasm = fixes_by_address[ea]
            print(f"0x{ea:X}: {mnem:8s} [esp+0x{esp_off:X}]")
            print(f"  Current: SP={curr_sp:5d} -> STACK[{curr_stack:5d}] ❌")
            print(f"  New:     SP={new_sp:5d} -> STACK[0x{target:X}] ✓")
            print()
    
    # Appliquer les corrections
    fixes_applied = 0
    if not dry_run and fixes_by_address:
        print(f"[*] Application de {len(fixes_by_address)} correction(s)...\n")
        
        for ea, (new_sp, _, _, _, _, _, _) in fixes_by_address.items():
            try:
                idc.add_user_stkpnt(ea, new_sp)
                fixes_applied += 1
                print(f"  [+] 0x{ea:X}: SP delta -> {new_sp}")
            except Exception as e:
                print(f"  [!] 0x{ea:X}: Erreur: {e}")
        
        if fixes_applied > 0:
            print("\n[*] Recompilation du pseudo-code...")
            try:
                idaapi.decompile(func_ea)
                print("[+] Recompilation OK!")
                print("\n" + "="*60)
                print("IMPORTANT: Fermez et rouvrez la fenêtre Hex-Rays")
                print("pour voir les changements dans le pseudo-code!")
                print("="*60)
            except Exception as e:
                print(f"[!] Erreur recompilation: {e}")
    
    elif dry_run and fixes_by_address:
        print(f"\n[DRY RUN] {len(fixes_by_address)} correction(s) seraient appliquées")
    
    elif errors_found == 0:
        print("\n[+] Aucune erreur détectée - fonction déjà correcte!")
    
    return fixes_applied

def fix_current_function_complete(dry_run=True):
    """
    Correction COMPLÈTE (LEA, MOV, CMP, etc.)
    """
    ea = idc.here()
    func_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    
    if func_ea == idc.BADADDR:
        print("[!] Aucune fonction trouvée")
        return
    
    fixes = analyze_and_fix_all_esp_references(func_ea, dry_run)
    
    if not dry_run and fixes > 0:
        print(f"\n[+] {fixes} correction(s) appliquée(s) avec succès!")

def fix_all_functions_batch(dry_run=True):
    """
    Corrige toutes les fonctions du programme
    """
    print("="*60)
    print(f"{'[DRY RUN] ' if dry_run else ''}CORRECTION EN MASSE")
    print("="*60)
    
    total_functions = idc.get_func_qty()
    functions_with_errors = 0
    total_fixes = 0
    
    print(f"\n[*] Analyse de {total_functions} fonction(s)...\n")
    
    for i, func_ea in enumerate(idautils.Functions()):
        try:
            func = idaapi.get_func(func_ea)
            if not func:
                continue
            
            # Analyse rapide pour détecter les erreurs
            esp_refs = find_all_esp_references(func)
            if not esp_refs:
                continue
            
            frame_size = idc.get_func_attr(func_ea, idc.FUNCATTR_FRSIZE)
            errors = 0
            
            for ea, esp_offset, mnem, disasm in esp_refs:
                current_sp = idc.get_spd(ea)
                current_stack_offset = esp_offset - current_sp
                
                if current_stack_offset < 0 or current_stack_offset > frame_size * 3:
                    errors += 1
            
            if errors > 0:
                functions_with_errors += 1
                func_name = idc.get_func_name(func_ea)
                print(f"[{i+1}/{total_functions}] 0x{func_ea:X} {func_name}: {errors} erreur(s)")
                
                if not dry_run:
                    fixes = analyze_and_fix_all_esp_references(func_ea, dry_run=False)
                    total_fixes += fixes
                    
        except Exception as e:
            print(f"[!] Erreur 0x{func_ea:X}: {e}")
    
    print("\n" + "="*60)
    print(f"Fonctions analysées: {total_functions}")
    print(f"Fonctions avec erreurs: {functions_with_errors}")
    if not dry_run:
        print(f"Total corrections: {total_fixes}")
    print("="*60)

def undo_all_sp_changes():
    """
    Annule toutes les modifications SP
    """
    print("[*] Suppression de tous les points SP personnalisés...")
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
    
    print(f"[+] {count} point(s) SP supprimé(s)")
    print("[*] Redémarrez l'analyse IDA pour restaurer complètement")

if __name__ == "__main__":
    print("="*60)
    print("Script de correction COMPLÈTE des SP deltas")
    print("="*60)
    print("\nCe script corrige TOUTES les instructions [esp+offset]:")
    print("  - LEA, MOV, CMP, PUSH, ADD, SUB, etc.")
    print("  - Détecte les offsets négatifs (erreur IDA)")
    print("  - Propose la meilleure correction")
    print("\nCommandes:")
    print("  fix_current_function_complete()        - Analyser (DRY RUN)")
    print("  fix_current_function_complete(False)   - CORRIGER")
    print("  fix_all_functions_batch()              - Tout analyser")
    print("  fix_all_functions_batch(False)         - TOUT CORRIGER")
    print("  undo_all_sp_changes()                  - Annuler")
    print("="*60)
