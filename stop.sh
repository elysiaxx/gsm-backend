#!/bin/bash

dir="$(dirname -- $( readlink -f -- $0;);)";
pid=""
while read line
do
  pid="$line"
done < "$dir"/backend.pid

kill -15 $pid