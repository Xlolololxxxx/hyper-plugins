import json
import re

filepath = 'local/hyper-target-panel/config/tools.json'

with open(filepath, 'r') as f:
    content = f.read()

# Fix the missing comma/bracket between nikto presets and nmap-quick
# Looking for: "presets": [ ... ] "id": "nmap-quick"
# We need to find where the presets array ends.
content = re.sub(r'(\s+\])(\s+"id": "nmap-quick")', r'\1,\n  {\2', content)

# But wait, the previous object (nikto) needs to be closed with `}`.
# The `]` closes the `presets` array. So we need `] } , {`.
content = re.sub(r'(\s+\])(\s+"id": "nmap-quick")', r'\1\n  },\n  {\2', content)

# Fix the mess after nuclei_from_httpx
# "parser": "nuclei"
# "command": "whatweb {target}",
# "category": "Web",
# "types": ["url", "domain"]
# },
# This fragment seems to be inside the nuclei_from_httpx object or merging with it.
# We want to close nuclei_from_httpx and remove the fragment.
# "parser": "nuclei" is the last valid field of nuclei_from_httpx.
# We should replace from `"parser": "nuclei"` to the next `},` (which closes the broken object)
# with `"parser": "nuclei" }`.
# And we drop the fragment.
# But wait, there is no `},` after the fragment?
# The fragment ends with `},`.
# So:
# "parser": "nuclei"
# "command": ...
# ...
# },

pattern = r'("parser": "nuclei")\s+"command": "whatweb \{target\}",\s+"category": "Web",\s+"types": \["url", "domain"\]\s+([},])'
content = re.sub(pattern, r'\1\n  }\2', content)

# Fix possible missing commas between objects if they were just concatenated
# content = re.sub(r'}\s+{', '},{', content) # risky if inside strings, but JSON strings usually don't contain newlines directly like that.

# Now let's try to parse it and do the merging logic
try:
    tools = json.loads(content)
except json.JSONDecodeError as e:
    print(f"JSON Error after regex fix: {e}")
    # Fallback: manual string manipulation or more regex
    # Let's save the current attempt to a file to debug if needed
    with open('local/hyper-target-panel/config/tools_fixed_attempt.json', 'w') as f:
        f.write(content)
    exit(1)

# Merging logic
merged_tools = []
seen_ids = set()

# Map of ID to index in merged_tools
id_map = {}

for tool in tools:
    tid = tool['id']
    if tid in seen_ids:
        # Merge types if existing
        existing_index = id_map[tid]
        existing_tool = merged_tools[existing_index]

        if 'types' in tool:
            if 'types' not in existing_tool:
                existing_tool['types'] = tool['types']
            else:
                existing_tool['types'] = list(set(existing_tool['types'] + tool['types']))

        # Don't add the duplicate
    else:
        seen_ids.add(tid)
        id_map[tid] = len(merged_tools)
        merged_tools.append(tool)

# Add types to whatweb if not present (since we deleted the fragment that had it)
# The fragment had types: ["url", "domain"]
for tool in merged_tools:
    if tool['id'] == 'whatweb':
        if 'types' not in tool:
             tool['types'] = ["url", "domain"]
    if tool['id'] == 'nikto':
         if 'types' not in tool:
             tool['types'] = ["url", "domain"]

# Write back
with open(filepath, 'w') as f:
    json.dump(merged_tools, f, indent=2)

print("Successfully fixed tools.json")
