#!/bin/sh
if [ -z "$1" ]; then
    echo "Extract the signature section of an ELF file"
    echo "$0 filename [outputfile]"
    echo "The signature will be in outputfile"
    echo "Default outputfile is filename.sig"
    exit 1
fi

if [ ! -f $1 ]; then
    echo "$1 does not exist!" 
    exit 1
fi

if [ -z "$2" ]; then
    outfile=$1.sig
else
    outfile=$2
fi

echo "Extracting the signature section from: $1"
echo "The signature will be in $outfile"

# Find the offset of the signature. readelf produce offset in hex
hex_offset=`readelf -S $1 | grep signature | awk '{print $5}'`

if [ -z "$hex_offset" ]; then
    echo "No signature in file $1"
    exit 1
fi

# convert hex offset in dec offset, and copy with dd
temp=`echo "$hex_offset" | tr '[a-f]' '[A-F]'`
dec_offset=`echo "ibase=16; $temp" | bc`
dd if=$1 of=$outfile bs=1 skip=$dec_offset count=512
