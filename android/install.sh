#!/bin/bash

SCRIPT_DIR=$PWD/`dirname $0`
PUSH_DIR=/sdcard
DATA_DIR=/data/local
ADB=adb
ADB_PARAMS=
ANDROID_DIR=$ANDROID_BUILD_TOP

if [ -z $TARGET_PRODUCT ]; then
        echo "There is no TARGET_PRODUCT environment variable set."
	echo "Please make sure that the Android build environment"
	echo "is configured by running \'source build/env-setup-sh\'."
	echo
	exit
fi

# Restart adb with root permissions
adb root

pushd $ANDROID_DIR

if [ ! -d $ANDROID_PRODUCT_OUT ]; then
    echo "Cannot find product directory $ANDROID_PRODUCT_OUT"
    exit
fi

popd
	
echo "Looking for Android devices..."

DEVICES=$(adb devices | awk '{ if (match($2,"device")) print $1}')
NUM_DEVICES=$(echo $DEVICES | awk '{print split($0,a, " ")}')

if [ $NUM_DEVICES -lt 1 ]; then
    echo "There are no Android devices connected to the computer."
    echo "Please connect at least one device before installation can proceed."
    echo
    exit
fi 

echo "$NUM_DEVICES Android devices found."
echo
echo "Assuming android source is found in $ANDROID_DIR"
echo "Check your device in case you need to allow permissions."
echo "Please make sure this is correct before proceeding."
echo
echo "Press any key to install SERVAL on these devices, or ctrl-c to abort"
# Wait for some user input
read

pushd $SCRIPT_DIR

LIB_PATH_PREFIX="system/lib"
LIB_FILES="libstack.so libserval.so libserval_javasock_jni.so"

BIN_HOST_PREFIX=
BIN_PATH_PREFIX="system/bin"
BIN_FILES="scafd udp_client udp_server"

# Binaries exectuting with root permissions
BIN_FILES_SU="serval"

APP_PATH_PREFIX="system/app"

pushd $ANDROID_DIR
pushd $ANDROID_PRODUCT_OUT

echo $PWD

function install_file()
{
    local src=$1
    local dir=$2
    local file=`basename $1`

    if [ -z "$3" ]; then
	local perm="755"
	else 
	local perm=$3
    fi

    $ADB -s $dev push $src $dir/$file
    #$ADB -s $dev push $src /sdcard/$file
    #$ADB -s $dev shell su -c "dd if=/sdcard/$file of=$dir/$file"
    #$ADB -s $dev shell rm -f /sdcard/$file
    $ADB -s $dev shell su -c "chmod $perm $dir/$file"
}

for dev in $DEVICES; do
    echo
    echo "Installing files onto device $dev"

    # Remount /system partition in rw mode
    $ADB -s $dev shell su -c "mount -o remount,rw -t yaffs2 /dev/block/mtdblock3 /system"

    # Enter directory holding unstripped binaries
    pushd symbols

    # Install libraries
    echo
    echo "Installing libraries"
    for file in $LIB_FILES; do
	echo "    $file"	
	install_file $LIB_PATH_PREFIX/$file /$LIB_PATH_PREFIX 644
    done
    
    # Install binaries
    echo
    echo "Installing binaries with root permissions"
    for file in $BIN_FILES_SU; do
	echo "    $file"	
	install_file $BIN_PATH_PREFIX/$file /$BIN_PATH_PREFIX 4775
    done

    echo
    echo "Installing binaries"
    for file in $BIN_FILES; do
	echo "    $file"	
	install_file $BIN_PATH_PREFIX/$file /$BIN_PATH_PREFIX 755
    done

    # Back to product dir
    popd
   
    # Cleanup data folder if any
    #$ADB -s $dev shell rm /data/local/tmp/serval-*.sock

    # Reset filesystem to read-only
    $ADB -s $dev shell su -c "mount -o remount,ro -t yaffs2 /dev/block/mtdblock3 /system"
done

popd
popd
popd

echo
echo "done."
