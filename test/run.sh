#!/bin/bash

python3 test.py -t 10000 -c cases::TestSecurityGroup,TestSubnet

#for i in {1..10}; do
#  python3 test.py -p 30 -c cases::TestPort
#done
#for i in {1..10}; do
#  python3 test.py -p 30 -c cases::TestRouter
#done
