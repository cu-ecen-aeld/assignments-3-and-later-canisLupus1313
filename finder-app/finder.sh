#!/bin/bash

if [ $# -ne 2 ]; then
	echo "Wrong number of arguments"
	exit 1
fi

if [ ! -d $1 ]; then
	echo "Directory $1 not found"
	exit 1
fi

X=`grep -rl $2 $1 | wc -l`
Y=`grep -r $2 $1 | wc -l`
echo "The number of files are $X and the number of matching lines are $Y"
