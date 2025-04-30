#!/usr/bin/env bash
set -e

STATUS=$(git status --porcelain)
if [[ -z $STATUS ]]
then
	echo "tree is clean"
else
	echo "tree is dirty"
	echo ""
	echo "$STATUS"
	echo ""
	echo "---------------------- Diff below ----------------------"
	echo ""
	git --no-pager diff
	exit 1
fi
