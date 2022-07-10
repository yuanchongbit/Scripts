import ida_nalt

nimps = ida_nalt.get_import_module_qty()

print("Found %d import(s)..." % nimps)

dic_imp = {}
for i in range(nimps):
    name = ida_nalt.get_import_module_name(i)
    if not name:
        print("Failed to get import module name for #%d" % i)
        name = "<unnamed>"

    print("Walking imports for module %s" % name)
    def imp_cb(ea, name, ordinal):
        if not name:
            print("%08x: ordinal #%d" % (ea, ordinal))
        else:
            print("%08x: %s (ordinal #%d)" % (ea, name, ordinal))
            dic_imp[ea] = name
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    ida_nalt.enum_import_names(i, imp_cb)
print(dic_imp)
print("All done...")
