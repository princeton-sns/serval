#!/bin/bash

KERNEL_DIR=../../src/stack/
MODULE=$KERNEL_DIR/serval.ko

if [ ! -f $MODULE ]; then
    echo "Module $MODULE does not exist."
    echo "Make sure you have compiled the Serval kernel module."
    exit -1
fi

UTS_RELEASE=`strings $MODULE | awk '/^UTS_RELEASE/ { print substr($2,2,length($2)-2) }'`

cp $MODULE assets/serval-$UTS_RELEASE.ko

