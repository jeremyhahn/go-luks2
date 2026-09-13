#!/usr/bin/env python3
"""Print the Dockerfile RUN chain that builds /entrypoint.sh, without the RUN.

Separate from dm-scope-guard-test.sh so that script can stay shell: a heredoc
inside a heredoc is how the first attempt at this broke.
"""
import re
import sys

lines = open(sys.argv[1]).read().split("\n")
start = next(
    i for i, line in enumerate(lines)
    if re.match(r"\s*RUN echo '#!/bin/bash' > /entrypoint\.sh", line)
)
end = start
while lines[end].rstrip().endswith("\\"):
    end += 1
chain = "\n".join(lines[start:end + 1])
print(re.sub(r"^\s*RUN ", "", chain, count=1))
