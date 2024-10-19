#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <pcap_file>"
    exit 1
fi

PCAP_FILE=$1

valgrind --tool=callgrind --cache-sim=yes --branch-sim=yes --log-file=valgrind-callgrind.txt ./simba_decoder "$PCAP_FILE"
