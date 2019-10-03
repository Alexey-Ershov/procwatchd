#!/usr/bin/env bash

# clear
gcc -O2 -Wall main.c -o procwatchd && \
./procwatchd -c ./config1.txt -l log.txt -i 5 -w 3
