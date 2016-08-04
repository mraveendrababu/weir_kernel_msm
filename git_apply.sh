#!/bin/bash
option=$1
file=$2
patch=multilsm.patch

git apply --$option --include="$file" $patch
