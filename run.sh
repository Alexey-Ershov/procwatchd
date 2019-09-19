#!/usr/bin/env bash

clear
gcc -O2 -Wall -Werror -Wno-pointer-sign -std=gnu11 main.c -o procwatchd && \
./procwatchd -c ./config.txt -l log.txt
