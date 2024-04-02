#!/bin/bash

pow(){
    difficulty=$1
    if [ $difficulty -gt 60 ]; then
        echo 'too hard'
        exit 1
    fi
    chalprefix=$(hexdump -n 8 -e '2/4 "%08x" 1 "\n"' /dev/urandom)
    echo "sha256($chalprefix+???) == $(printf '0%.0s' $(seq 0 $(($difficulty - 1))))($difficulty)..."
    printf "> "
    read -t 600 answer
    res=$(printf "$chalprefix$answer"|sha256sum|awk '{print $1}'|cut -c1-15|tr [a-f] [A-F])
    rshift=$((60-$difficulty))
    res=$(echo "obase=10; ibase=16; $res" | bc)
    if [ $(($res>>$rshift)) -ne 0 ]; then
        echo 'POW failed'
        exit 1
    else
        echo 'POW passed'
        exit 0
    fi
}

pow $1
