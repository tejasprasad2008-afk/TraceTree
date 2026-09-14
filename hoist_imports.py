import os
import re

def hoist_imports(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        return
        
    top_imports = set()
    new_lines = []
    
    in_multiline_string = False
    for line in lines:
        stripped = line.strip()
        
        if stripped.startswith('"""') or stripped.startswith("'''"):
            if stripped.count('"""') % 2 != 0 or stripped.count("'''") % 2 != 0:
                in_multiline_string = not in_multiline_string
        
        if not in_multiline_string and line.startswith(' ') and (stripped.startswith('import ') or stripped.startswith('from ')):
            # This is an inline import
            top_imports.add(stripped)
            continue
            
        new_lines.append(line)
        
    if not top_imports:
        return
        
    # Find insertion point
    insert_idx = 0
    for i, line in enumerate(new_lines):
        if line.startswith('import ') or line.startswith('from '):
            insert_idx = i + 1
            
    # Insert top imports
    for imp in sorted(top_imports):
        new_lines.insert(insert_idx, imp + '\n')
        insert_idx += 1
        
    with open(filepath, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
        
    print(f"Hoisted {len(top_imports)} imports in {filepath}")

for root, _, files in os.walk('/Users/tejasprasad/TraceTree'):
    if any(exclude in root for exclude in ['node_modules', '.venv', 'venv', 'graphify-out']):
        continue
    for f in files:
        if f.endswith('.py'):
            hoist_imports(os.path.join(root, f))
