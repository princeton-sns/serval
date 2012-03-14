#!/bin/bash

SCRIPT_DIR=$PWD/`dirname $0`
PUSH_DIR=/sdcard
DATA_DIR=/data/local
ADB=`which adb`
ADB_PARAMS=
ANDROID_DIR=$SCRIPT_DIR/../
ARCH=armeabi-v7a

if [ -z $ADB ]; then
    echo "adb tool not found. Please install the Android SDK and include adb in your PATH."
    exit;
fi

# Restart adb with root permissions
adb root

#pushd $ANDROID_DIR

#if [ ! -d $ANDROID_PRODUCT_OUT ]; then
#    echo "Cannot find product directory $ANDROID_PRODUCT_OUT"
#    exit
#fi

#popd
	
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

SERVAL_PREFIX="/data/local/serval"

LIB_HOST_PATH="Serval/libs/$ARCH"
LIB_PATH="system/lib"
LIB_FILES="libservalctrl.so libservalctrl_jni.so libservalnet_jni.so"

BIN_HOST_PATH="Serval/libs/$ARCH"
#BIN_PATH="system/bin"
BIN_PATH=$SERVAL_PREFIX
BIN_FILES="servd serv"

# Binaries executing with root permissions
BIN_FILES_SU="serval"

APP_PATH="system/app"

#MODULE_PATH="/system/lib/modules"
MODULE_PATH=$SERVAL_PREFIX
MODULE_HOST_PATH="src/stack"
MODULE_FILES="serval.ko"

pushd "$ANDROID_DIR"

echo $PWD

function install_file()
{
    local src=$1
    local dir=$2
    local file=`basename $1`

    if [ ! -f $src ]; then
	echo "file $src not found, skipping"
	return
    fi
    if [ -z "$3" ]; then
	local perm="755"
	else 
	local perm=$3
    fi

    #$ADB -s $dev push $src $dir/$file
    $ADB -s $dev push $src /sdcard/$file
    $ADB -s $dev shell su -c "dd if=/sdcard/$file of=$dir/$file"
    $ADB -s $dev shell rm /sdcard/$file
    $ADB -s $dev shell su -c "chmod $perm $dir/$file"
}

for dev in $DEVICES; do
    echo
    echo "Installing files onto device $dev"

    # Remount /system partition in rw mode
    $ADB -s $dev shell su -c "mount -o remount,rw -t yaffs2 /dev/block/mtdblock3 /system"
    $ADB -s $dev shell su -c "mount -o remount,rw -t yaffs2 /dev/block/mtdblock5 /data"

    $ADB shell su -c "mkdir $SERVAL_PREFIX"

    pushd $LIB_HOST_PATH
    # Install libraries
    echo
    echo "Installing libraries"
    for file in $LIB_FILES; do
	echo "    $file"	
	install_file $file /$LIB_PATH 644
    done
    
    popd
    pushd $BIN_HOST_PATH

    echo
    echo "Installing binaries"
    for file in $BIN_FILES; do
	echo "    $file"	
	install_file $file /$BIN_PATH 755
    done

    popd
    pushd $MODULE_HOST_PATH

    echo
    echo "Installing module"
    for file in $MODULE_FILES; do
	echo "    $file"	
	install_file $file /$MODULE_PATH 644
    done

    popd

    # Cleanup data folder if any
    #$ADB -s $dev shell rm /data/local/tmp/serval-*.sock

    # Reset filesystem to read-only
    $ADB -s $dev shell su -c "mount -o remount,ro -t yaffs2 /dev/block/mtdblock3 /system"
    $ADB -s $dev shell su -c "mount -o remount,ro -t yaffs2 /dev/block/mtdblock5 /data"
done

popd

echo
echo "done."
