from idaapi import *
from idautils import XrefsFrom
import ida_nalt


def fcg2dot(save_path, title):
	f = open(save_path, 'w')
	# dotfile digraph
	f.write(f"digraph \"{title}\" {{\n")
	f.write("\tgraph [\n\t];\n")
	f.write("\tnode [\n\t\tshape = \"box\"\n\t];\n")
	f.write("\tedge [\n\t];\n")

	# produce function dictionary, store map of function and node index
	node_index = 0
	dic = {}

	# enumerate intrinsic functions
	funcs = Functions()
	for func in funcs:
		fname = GetFunctionName(func)
		# func_size = calc_func_size(get_func(func))
		func_size = len(list(FuncItems(func)))
		dic[fname] = node_index
		f.write(f"\"{node_index}\" [ label = \"{fname}\", size = {func_size}, attr = \"intrinsic\"];\n")
		node_index += 1

	# enumerate extern functions
	nimps = ida_nalt.get_import_module_qty()
	dic_imp_addr = {} # store map of import function addr and name
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
	            dic_imp_addr[ea] = name
	        # True -> Continue enumeration
	        # False -> Stop enumeration
	        return True
	    ida_nalt.enum_import_names(i, imp_cb)

	for k, v in dic_imp_addr.items():
		dic[v] = node_index
		f.write(f"\"{node_index}\" [ label = \"{v}\", attr = \"extern\"];\n")
		node_index += 1

	# get call relation
	# NOTE: extern function won't be entry of edge
	funcs = Functions() # generator need acquire again
	for func in funcs:
		fname = get_func_name(func)

		f.write(f"// node {dic[fname]}\n")
		if not func is None:
			items = FuncItems(func)
			dic_fun = {} # record frequency
			
			# traverse all the instruction in this function
			for i in items:
				for xref in XrefsFrom(i, 0):
					if xref.type == fl_CN or xref.type == fl_CF:
						# fl_CN means flow call Near, fl_CF means flow Far
						# extern function
						if xref.to in dic_imp_addr:
							fdst = dic_imp_addr[xref.to]
						else:
							fdst = get_func_name(xref.to)
						
						if fdst in dic: # function name maybe None
							print(f"{fname} call {fdst} from {i}")
							if fdst not in dic_fun:
								dic_fun[fdst] = 1
							else:
								dic_fun[fdst] += 1


			for item in dic_fun:
				f.write(f"\"{dic[fname]}\" -> \"{dic[item]}\" [ frequency = {dic_fun[item]} ];\n")

	f.write("}\n")
	f.close()
	print('done!')

if __name__ == "__main__":
	title = "calc"
	save_path = f"{title}_frq.dot"
	fcg2dot(save_path, title)
