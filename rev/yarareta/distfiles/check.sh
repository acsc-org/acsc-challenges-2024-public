#!/bin/sh

LD_PRELOAD=./libyara.so.10 ./yara -C ./yarareta ./PrintFlag

