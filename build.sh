#!/usr/bin/bash

rmmod net_link
make
insmod net_link.ko
./sender
make clean
