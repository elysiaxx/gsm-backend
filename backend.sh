#!/bin/bash

pythonenv=$1
dir="$(dirname -- $( readlink -f -- $0;);)";

"$pythonenv" -u "$dir"/manage.py -p 5002 &

echo $! > "$dir"/backend.pid