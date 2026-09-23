print("SCRIPT STARTED")

from app.detectors import scan_line

print("IMPORT WORKED")

test_lines = [
    'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";',
    'password = "hunter2"',
    'name = "John Smith"',
]

print(f"NUMBER OF TEST LINES: {len(test_lines)}")

for line in test_lines:
    print(line[:50], "->", scan_line(line))

print("SCRIPT FINISHED")
