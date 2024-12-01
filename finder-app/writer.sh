#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Wrong number of arguments"
	exit 1
fi

mkdir -p `dirname $1`
echo $2 > $1
