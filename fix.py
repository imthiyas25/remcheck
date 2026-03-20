import re

with open('remcheck.py', 'r') as f:
    content = f.read()

# Fix 1: make --finding not required
content = content.replace(
    'parser.add_argument("--finding", required=True, metavar="FILE",',
    'parser.add_argument("--finding", metavar="FILE",'
)

# Fix 2: add guard after list_types block
content = content.replace(
    '    # Load finding\n    finding = load_finding(args.finding)',
    '    if not args.finding:\n        print("[ERROR] --finding FILE is required.")\n        parser.print_help()\n        sys.exit(EXIT_ERROR)\n\n    # Load finding\n    finding = load_finding(args.finding)'
)

with open('remcheck.py', 'w') as f:
    f.write(content)

print("Fixed!")
