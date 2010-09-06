
# This is a temporary script to convert trusted_thread.cc.  It will be
# removed when the conversion is complete.

import re


def read_file(filename):
    fh = open(filename, "r")
    try:
        return fh.read()
    finally:
        fh.close()


def write_file(filename, data):
    fh = open(filename, "w")
    try:
        fh.write(data)
    finally:
        fh.close()


def extract_between(string, m1, m2):
    pre, rest = string.split(m1, 1)
    middle, post = rest.split(m2, 1)
    return middle


def uninline(asm):
    len1 = len(asm)
    asm = asm.replace("%%", "%")
    asm = asm.replace(r'\"', '"')
    removed = len1 - len(asm)
    assert removed >= 0
    return asm + " " * removed

asm_re = re.compile(r'"(.*?)\\n"')

def munge(line):
    match = asm_re.search(line)
    if match is not None:
        line = (line[:match.start()] + uninline(match.group(1)) +
                line[match.end():])
    # Change indentation from 6 spaces to 8, to fit with Emacs'
    # default indentation.
    line = "  " + line
    return line.rstrip()

def munge_lines(data):
    return (
        "// This has been automatically extracted from trusted_thread.cc.\n"
        "// It will be fixed up in the next commit.\n\n" +
        "".join(munge(line) + "\n" for line in data.split("\n")))


def main():
    data = read_file("trusted_thread.cc")
    for arch in ("x86_64", "i386"):
        asm = extract_between(data,
                              "\n//CUT_%s_START\n" % arch,
                              "\n//CUT_%s_END\n" % arch)
        write_file("trusted_thread_%s.S" % arch, munge_lines(asm))


if __name__ == "__main__":
    main()
