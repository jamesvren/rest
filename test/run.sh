#!/bin/bash

if [ "$1" == "clear" ]; then
    python3 test.py -C
    exit 0
fi
python3 test.py -p 30 -t 4 -n -c cases::TestCases
#python3 test.py -p 30 -t 20 -n -c cases::TestCases

#for i in {1..10}; do
#  python3 test.py -p 30 -c cases::TestPort
#done
#for i in {1..10}; do
#  python3 test.py -p 30 -c cases::TestRouter
#done
