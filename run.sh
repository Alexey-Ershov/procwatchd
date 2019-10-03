#!/usr/bin/env bash

gcc -O2 -Wall main.c -o procwatchd && \
./procwatchd -c ./config.txt -l log.txt
