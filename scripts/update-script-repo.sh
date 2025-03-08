#!/bin/bash

SCRIPTDIR=`dirname $(readlink -f ${BASH_SOURCE[0]})`

REPOS=`ls -d $SCRIPTDIR/*/`

echo -e "\e[32mScanning dir to update git repos ...\e[39m"

for repo in $REPOS; do
	cd "$repo"
	echo -e "\n\e[93mMoved to: $repo\n\e[39m"

	if [ -d .git ]; then
            echo -e "\e[34mGit found! Cheking out\e[39m"
   	    git checkout
        else
	   echo -e "\e[44mNo git repo found, skipping...\e[49m"
	fi

	cd "$SCRIPTDIR";
done

echo -e "\n\e[32mDone updating, bye!\e[39m"

