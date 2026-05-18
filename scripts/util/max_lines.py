import json
import glob
import re

files = glob.glob('/Users/evanhelbig/.claude/projects/-Users-evanhelbig-projects-talos/*.jsonl')

max_lines = 0
best_content = None

for fname in files:
    with open(fname, 'r') as f:
        for line in f:
            try:
                obj = json.loads(line)
            except:
                continue
                
            if obj.get('type') == 'user' and 'message' in obj:
                content_list = obj['message'].get('content', [])
                if isinstance(content_list, str):
                    continue
                for item in content_list:
                    if isinstance(item, dict) and item.get('type') == 'tool_result' and 'content' in item:
                        content_str = item['content']
                        if not isinstance(content_str, str):
                            continue
                        if '1→#![allow(dead_code' in content_str or 'async fn main()' in content_str:
                            lines_count = len(content_str.split('\n'))
                            if lines_count > max_lines:
                                max_lines = lines_count
                                best_content = content_str

if best_content:
    print(f"Found max lines: {max_lines}")
    # Write to a file
    with open('best_main.txt', 'w') as f:
        f.write(best_content)
