# Simple IdaPython Script to detect function when IDA fail

import idaapi
import idc

def FindUnknownFunctions():
    print("Looking for unknown functions – 1st Way")
    seg = idaapi.get_segm_by_name(".text")
    start = seg.start_ea
    BAD = idaapi.BADADDR

    # 1st Way : Create a function when we find a hole
    ea = idaapi.find_not_func(start, idaapi.SEARCH_DOWN)
    while ea != BAD:
        idaapi.add_func(ea)
        ea = idaapi.find_not_func(ea + 1, idaapi.SEARCH_DOWN)

    print("Looking for unknown functions – 2nd Way")
    # 2nd Way : Define end of each function
    ea = idaapi.find_not_func(start, idaapi.SEARCH_DOWN)
    while ea != BAD:
        # cherche la prochaine donnée ou la fin de section
        end_ea = idaapi.find_data(ea, idaapi.SEARCH_DOWN)
        if end_ea == BAD or end_ea > seg.end_ea:
            end_ea = seg.end_ea
        idaapi.add_func(ea, end_ea)
        ea = idaapi.find_not_func(ea + 1, idaapi.SEARCH_DOWN)

    print("Done!")

FindUnknownFunctions()
