#!/bin/bash

# testing helpers
RED='\e[0;31m'
GREEN='\e[0;32m'
NOC='\e[0m'

function alerting()
{
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        echo -e "[${GREEN}PASS${NOC}]: Raw socket finished with \
exit code $exit_code"
    else
        echo -e "[${RED}FAIL${NOC}]: Raw socket crashed with exit \
code $exit_code, aborting the rest tests"
        exit $exit_code
    fi
}

# testing data
URLS=('http://david.choffnes.com/classes/cs4700sp14/2MB.log'
      'http://david.choffnes.com/classes/cs4700sp14/10MB.log'
      'http://david.choffnes.com/classes/cs4700sp14/50MB.log')
SEARCH_PATH=`pwd | xargs dirname`
TARGET=`find $SEARCH_PATH -name rawhttpget`
DOWNLOAD_PATH=/tmp
FILENAME=index.html

# ensure the target executable `rawhttpget` has been made
if [ "$TARGET" == "" ]; then
    echo -e "${RED}Please run 'make' first before running this \
script standalone or just run 'make test'${NOC}"
    exit 1
fi

# kick off the integration test
for url in ${URLS[@]};
do
    echo "Sanity test with URL: $url"
    filename=`echo $url | awk -F/ '{print $NF}'`
    FILENAME=`[ "$filename" = "" ] && echo $FILENAME || echo $filename`
    $TARGET $url -d $DOWNLOAD_PATH -vv
    alerting
    wget_out=$DOWNLOAD_PATH/$FILENAME.wget
    wget -O $wget_out $url
    # verify the diff
    diff $DOWNLOAD_PATH/$FILENAME $wget_out > /dev/null
    rcdiff=$?
    # verify md5sum
    md5sum $DOWNLOAD_PATH/$FILENAME | sed -r "s@([0-9a-z]{32})(\s+)([^\s]+)@\1\2$wget_out@g" | md5sum -c --quiet
    rcmd5sum=$?
    if [ $rcdiff -eq 0 ] && [ $rcmd5sum -eq 0 ]; then
        echo -e "[${GREEN}PASS${NOC}]: The file ($DOWNLOAD_PATH/$FILENAME) downloaded by $TARGET is exactly the same with that ($wget_out) downloaded by wget"
    else
        echo -e "[${RED}FAIL${NOC}]: The file ($DOWNLOAD_PATH/$FILENAME) downloaded by $TARGET is not the same with that ($wget_out) downloaded by wget"
    fi
done
