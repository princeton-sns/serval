#!/bin/bash

KERNEL_DIR=../../src/stack
MODULE=$KERNEL_DIR/serval.ko

if [ ! -f $MODULE ]; then
    echo "Module $MODULE does not exist."
    echo "Make sure you have compiled the Serval kernel module."
    exit -1
fi

VERMAGIC=`strings ../../src/stack/serval.ko | awk '/^vermagic=/ { split($1,a,"="); print a[2] }'`

echo "copying $MODULE to assets/serval-$VERMAGIC.ko"
cp $MODULE assets/serval-$VERMAGIC.ko

