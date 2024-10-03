#!/bin/sh

i=0
while [ "$i" -lt $1 ]; do
    echo "start node $i..."
    go run  src/main/server/server.go $i&
    i=$(( i + 1 ))
done 
