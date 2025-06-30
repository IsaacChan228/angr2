#!/usr/bin/env python3
"""
Use angr to analyze binary files and export call graphs and control flow graphs - Final Version
Supports multiple detection methods and detailed debugging output
"""

# use this code in terminal to run the script:
# python angr_analy_fast.py <binary_file>

import angr
import networkx as nx
import argparse
import sys
import os
import traceback
import time
import logging

# Set to True to disable all logging output
Disable_logging = True

# disable logging for angr modules
if Disable_logging:
    logging.getLogger('angr').propagate = False

def analyze_binary_and_export(binary_path, verbose=False):
    """
    Main control flow: analyze binary and export call graph and control flow graph
    """
    project, cfg, main_func = load_and_analyze_binary(binary_path, verbose)
    if not all([project, cfg, main_func]):
        return False
    
    # Export function list
    functionlist_ok = export_function_list(cfg, "functionlist.txt", verbose)

    # Export call graph
    callgraph_ok = export_call_graph(project, cfg, main_func, "callgraph.dot", binary_path, verbose)

    # Export control flow graph
    cfg_ok = export_cfg_graph(cfg, main_func, "cfg.dot", verbose)

    return functionlist_ok and callgraph_ok and cfg_ok


def load_and_analyze_binary(binary_path, verbose=False):
    """
    Load binary file and perform basic analysis
    
    Returns:
        tuple: (project, cfg, main_func) or (None, None, None) if failed
    """
    print(f"[+] Starting binary analysis: {binary_path}")
    
    if not os.path.exists(binary_path):
        print(f"[-] Error: File {binary_path} does not exist")
        return None, None, None
    
    try:
        # Load binary file
        print("[+] Loading binary file...")
        project = angr.Project(binary_path, auto_load_libs=False)
        
        print(f"[+] Architecture: {project.arch}")
        print(f"[+] Entry point: 0x{project.entry:x}")
        
        # Record analysis start time
        start_time = time.time()
        print(f"[+] Analysis start time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time))}")

        # Generate control flow graph
        print("[+] Analysis using CFGfast...")
        cfg = project.analyses.CFGFast(resolve_indirect_jumps=True)
        
        # print used time
        end_time = time.time()
        total_time = end_time - start_time
        print(f"[+] Time used: {total_time:.2f} seconds")

        # Find main function
        print("[+] Looking for main function...")
        main_func = None
        
        # Method 1: Through symbol table
        for symbol in project.loader.symbols:
            if symbol.name == 'main':
                main_func = cfg.functions.get(symbol.rebased_addr)
                print(f"[+] Found main via symbol table: 0x{symbol.rebased_addr:x}")
                break
        
        # Method 2: If not found, search in all functions
        if main_func is None:
            print("[+] Searching main in function list...")
            for addr, func in cfg.functions.items():
                if func.name and func.name == 'main':
                    main_func = func
                    break
        
        if main_func is None:
            print("[-] Error: Unable to find main function")
            return None, None, None
        
        print(f"[+] Found target function: {main_func.name} at 0x{main_func.addr:x}")
        
        return project, cfg, main_func
        
    except Exception as e:
        print(f"[-] Error occurred during analysis: {str(e)}")
        if verbose:
            traceback.print_exc()
        return None, None, None


def export_call_graph(project, cfg, main_func, output_path, binary_path, verbose=False):
    """
    Export call graph for main function
    
    Args:
        project: angr Project object
        cfg: Control flow graph
        main_func: main function object
        output_path: Output path
        binary_path: Binary file path
        verbose: Whether to show detailed information
    """
    print("[+] Generating call graph...")
    
    try:
        # Create call graph
        call_graph = nx.DiGraph()
        
        # Method 1: Use CFG to analyze function calls
        def analyze_function_calls_cfg(func):
            func_name = func.name if func.name else f"sub_{func.addr:x}"
            call_graph.add_node(func_name, addr=hex(func.addr))
            
            # Get function call targets
            callsites = []
            
            # Traverse all basic blocks of the function
            for block_addr in func.block_addrs:
                block = cfg.model.get_any_node(block_addr)
                if block:
                    # Check block successors
                    for succ in cfg.graph.successors(block):
                        # Check if it's a call edge
                        edge_data = cfg.graph.get_edge_data(block, succ)
                        if edge_data and edge_data.get('jumpkind') == 'Ijk_Call':
                            target_func = cfg.functions.get(succ.addr)
                            if target_func and target_func != func:
                                callsites.append(target_func)
            
            # Add call edges
            for target_func in callsites:
                target_name = target_func.name if target_func.name else f"sub_{target_func.addr:x}"
                call_graph.add_node(target_name, addr=hex(target_func.addr))
                call_graph.add_edge(func_name, target_name)
        
        # Method 2: Use instruction-level analysis
        def analyze_function_calls_instruction(func):
            func_name = func.name if func.name else f"sub_{func.addr:x}"
            
            # Traverse all basic blocks of the function
            for block_addr in func.block_addrs:
                try:
                    block = project.factory.block(block_addr)
                    
                    # Check each instruction
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':  # x86/x64 call instruction
                            # Try to resolve call target
                            if len(insn.operands) > 0:
                                op = insn.operands[0]
                                if op.type == 3:  # Immediate value (direct call)
                                    target_addr = op.value.imm
                                    target_func = cfg.functions.get(target_addr)
                                    if target_func and target_func != func:
                                        target_name = target_func.name if target_func.name else f"sub_{target_func.addr:x}"
                                        call_graph.add_node(target_name, addr=hex(target_func.addr))
                                        call_graph.add_edge(func_name, target_name)
                
                except Exception as e:
                    if verbose:
                        print(f"    Error analyzing block 0x{block_addr:x}: {e}")
                    continue
        
        # Recursively analyze called functions (starting from main function)
        visited = set()
        to_visit = [main_func]
        
        while to_visit:
            current_func = to_visit.pop(0)
            if current_func.addr in visited:
                continue
            visited.add(current_func.addr)
            
            analyze_function_calls_cfg(current_func)
            analyze_function_calls_instruction(current_func)
            
            # Add newly discovered functions to the visit list
            current_name = current_func.name if current_func.name else f"sub_{current_func.addr:x}"
            for target_name in call_graph.successors(current_name):
                # Find the corresponding function object
                for addr, func in cfg.functions.items():
                    func_name = func.name if func.name else f"sub_{func.addr:x}"
                    if func_name == target_name and func.addr not in visited:
                        to_visit.append(func)
                        break
        
        # If still no call relationships, at least include main function
        if call_graph.number_of_nodes() == 0:
            main_name = main_func.name if main_func.name else f"sub_{main_func.addr:x}"
            call_graph.add_node(main_name, addr=hex(main_func.addr))
        
        print(f"[+] Call graph contains {call_graph.number_of_nodes()} nodes and {call_graph.number_of_edges()} edges")
        
        # Export as DOT format
        print(f"[+] Exporting call graph to {output_path}...")
        
        dot_content = "digraph CallGraph {\n"
        dot_content += "    rankdir=TB;\n"
        dot_content += "    node [shape=box, style=filled, fillcolor=lightblue];\n"
        dot_content += "    edge [color=darkblue, arrowhead=vee];\n"
        dot_content += "    \n"
        dot_content += "    // Call graph title\n"
        dot_content += f'    label="Call Graph for {os.path.basename(binary_path)}";\n'
        dot_content += "    labelloc=t;\n"
        dot_content += "    \n"
        
        # Add nodes
        for node in call_graph.nodes(data=True):
            node_name, node_data = node
            addr = node_data.get('addr', '')
            dot_content += f'    "{node_name}" [label="{node_name}\\n{addr}"];\n'
        
        dot_content += "    \n"
        
        # Add edges
        for edge in call_graph.edges():
            dot_content += f'    "{edge[0]}" -> "{edge[1]}";\n'
        
        dot_content += "}\n"
        
        # Write to file
        with open(output_path, 'w') as f:
            f.write(dot_content)
        
        print(f"[+] Successfully exported call graph to {output_path}")
        
        # Show call graph statistics
        print(f"[+] Call graph statistics: {call_graph.number_of_nodes()} nodes, {call_graph.number_of_edges()} edges")
        
        if call_graph.number_of_edges() == 0:
            print(f"[!] No function call relationships detected (possibly due to compiler optimization or indirect calls)")
        
        return True
        
    except Exception as e:
        print(f"[-] Error occurred during analysis: {str(e)}")
        traceback.print_exc()
        return False

def export_cfg_graph(cfg, main_func, output_path, verbose=False):
    """
    Export control flow graph (CFG) for main function

    Args:
        cfg: angr generated control flow graph object
        main_func: main function object
        output_path: Output DOT file path
        verbose: Whether to show detailed information
    """
    print("[+] Generating control flow graph (CFG)...")
    try:
        # Only export main function's CFG
        func_cfg = nx.DiGraph()
        addr_to_label = {}

        for block_addr in main_func.block_addrs:
            node = cfg.model.get_any_node(block_addr)
            if node is None:
                continue
            label = f"0x{block_addr:x}"
            addr_to_label[block_addr] = label
            func_cfg.add_node(label)

        # Add edges
        for block_addr in main_func.block_addrs:
            node = cfg.model.get_any_node(block_addr)
            if node is None:
                continue
            for succ in cfg.graph.successors(node):
                if succ.addr in main_func.block_addrs:
                    src = addr_to_label[block_addr]
                    dst = addr_to_label[succ.addr]
                    func_cfg.add_edge(src, dst)

        # Export as DOT format
        dot_content = "digraph MainCFG {\n"
        dot_content += "    rankdir=TB;\n"
        dot_content += "    node [shape=box, style=filled, fillcolor=lightyellow];\n"
        dot_content += "    edge [color=darkgreen, arrowhead=vee];\n"
        dot_content += "    \n"
        dot_content += f'    label="CFG for {main_func.name}";\n'
        dot_content += "    labelloc=t;\n"
        dot_content += "    \n"

        for node in func_cfg.nodes():
            dot_content += f'    "{node}" [label="{node}"];\n'

        dot_content += "    \n"
        for src, dst in func_cfg.edges():
            dot_content += f'    "{src}" -> "{dst}";\n'

        dot_content += "}\n"

        with open(output_path, 'w') as f:
            f.write(dot_content)

        print(f"[+] Successfully exported control flow graph to {output_path}")
        print(f"[+] CFG statistics: {func_cfg.number_of_nodes()} nodes, {func_cfg.number_of_edges()} edges")

        return True

    except Exception as e:
        print(f"[-] Error exporting control flow graph: {str(e)}")
        traceback.print_exc()
        return False

def export_function_list(cfg, output_path, verbose=False):
    """
    Export list of all functions found in the binary file
    
    Args:
        cfg: angr generated control flow graph object
        output_path: Output file path
        verbose: Whether to show detailed information
    """
    print("[+] Generating function list...")
    
    try:
        functions = []
        
        # Collect all function information
        for addr, func in cfg.functions.items():
            func_name = func.name if func.name else f"sub_{func.addr:x}"
            
            # Safely get function size
            try:
                func_size = func.size if func.size is not None else 0
            except (TypeError, AttributeError):
                func_size = 0
            
            # Safely get block count
            try:
                block_count = len(func.block_addrs) if hasattr(func, 'block_addrs') and func.block_addrs else 0
            except (TypeError, AttributeError):
                block_count = 0
            
            func_info = {
                'name': func_name,
                'address': hex(func.addr),
                'size': func_size,
                'blocks': block_count
            }
            functions.append(func_info)
        
        # Sort by address
        functions.sort(key=lambda x: int(x['address'], 16))
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("# Function List\n")
            f.write("# Format: Function Name | Address | Size | Block Count\n")
            f.write("# " + "="*60 + "\n\n")
            
            for func_info in functions:
                f.write(f"{func_info['name']:<30} | {func_info['address']:<12} | {func_info['size']:<8} | {func_info['blocks']:<4}\n")
        
        print(f"[+] Successfully exported function list to {output_path}")
        print(f"[+] Total {len(functions)} functions found")
        
        return True
        
    except Exception as e:
        print(f"[-] Error exporting function list: {str(e)}")
        if verbose:
            traceback.print_exc()
        return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Analyze binary files using angr and export function list and call graph")
    parser.add_argument("binary", help="Path to the binary file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Show detailed debugging information")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("angr Binary Analysis Tool (CFGFast Version)")
    print("=" * 60)
    
    success = analyze_binary_and_export(args.binary, args.verbose)
    
    if success:
        print("\n[+] Analysis completed!")
        sys.exit(0)
    else:
        print("\n[-] Analysis failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
