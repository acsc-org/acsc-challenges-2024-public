#!/bin/bash

(stdbuf -o0 ./pow.sh 24) && timeout 180 python3 -u ./launch.py
