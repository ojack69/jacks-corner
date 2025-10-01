#!/bin/bash

check_params(){
    if [ -z "$1" ]
    then
        echo -e "\e[31m[x] Missing required attribute: $2\e[39m"
        return 1
    fi
    return 0
}

if [ $# -eq 0 ]
then
    echo "Usage: ./bloodhound_uploader.sh <BLOODHOUND_SERVER> <BLOODHOUND_USERNAME> <PASSWORD> <TARGET_ZIP_FILE>"
    exit 1
fi

check_params "$1" "BLOODHOUND_SERVER"
check_params "$2" "BLOODHOUND_USERNAME"
check_params "$3" "PASSWORD"
check_params "$4" "TARGET_ZIP_FILE"

if [ $? -eq 1 ]
then
    exit 1
fi

BLOODHOUND_SERVER=$1
BLOODHOUND_USERNAME=$2
PASSWORD=$3
TARGET_ZIP_FILE=$(readlink -f $4)

echo -e "\e[32m[!] Uploading collected data $TARGET_ZIP_FILE to $BLOODHOUND_SERVER...\e[39m"

login_response=$(curl -s -X 'POST' "$BLOODHOUND_SERVER/api/v2/login" -H 'accept: application/json' -H 'Prefer: 0' -H 'Content-Type: application/json' -d "{\"username\": \"$BLOODHOUND_USERNAME\", \"secret\":\"$PASSWORD\", \"login_method\": \"secret\"}")

jwt_token=$(echo $login_response | jq -r .data.session_token)
if [[ "$jwt_token" == "null" ]]
then
    echo -e "\e[31m[x] Login failed!\e[39m"
    exit 2
fi
echo -e "\e[32m[!] Logged in...\e[39m"

echo -e "\e[32m[!] Creating job...\e[39m"

job_creation_response=$(curl -s -X POST "$BLOODHOUND_SERVER/api/v2/file-upload/start" -H "Authorization: Bearer $jwt_token" -H 'accept: application/json' -H 'Prefer: 0' -H 'Content-Type: application/json' -d '')
job_id=$(echo $job_creation_response | jq -r .data.id)

if [[ "$job_id" == "null" ]]
then
    echo "[x] Failed to create job!"
    exit 3
fi

echo -e "\e[32m[!] Unzipping collected data archive...\e[39m"
tmp_dir=$(mktemp -d)
cp "$TARGET_ZIP_FILE" "$tmp_dir"
cd "$tmp_dir"
unzip "$tmp_dir/$(basename $TARGET_ZIP_FILE)" 1>/dev/null
rm "$tmp_dir/"*".zip"
cd "-" 1> /dev/null

echo -e "\e[32m[!] Uploading ingested files to job $job_id\e[39m\n"
for f in $(ls $tmp_dir)
do
    echo -e "\e[93m[>] Uploading $f\e[39m"
    upload_response=$(curl -s -X POST "$BLOODHOUND_SERVER/api/v2/file-upload/$job_id" -H "Authorization: Bearer $jwt_token" -H 'accept: application/json' -H 'Prefer: 0' -H 'Content-Type: application/json' -d @"$tmp_dir/$f")
done

complete_upload_response=$(curl -s -X POST "$BLOODHOUND_SERVER/api/v2/file-upload/$job_id/end" -H "Authorization: Bearer $jwt_token" -H 'accept: application/json' -H 'Prefer: 0' -H 'Content-Type: application/json' -d '') 

rm -rf "$tmp_dir"
echo -e "\n\e[32m[!] All done!\e[39m"

