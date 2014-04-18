#!/usr/bin/env bash
#
# Cloud fuzzing example config file 

# BASE_AMI needs to be Windows AMI 
BASE_AMI="ami-6666666"		 
KEYPAIR="KeypairNameHere"
SECURITY_GROUP="SecurityGroupName"
USER_DATA_FILE="userdata.txt"
# Must reference a remotely accessible ps file 
# so instance can reach it during boot. 
USER_DATA_URL="https://name.tld/file.ps1"
# local path to winrm command.
PATH_TO_WINRM=""
AMI_PASSWORD="reallyYouWroteThisInBash?"
# Name of AMI result image. 
RESULT_AMI_NAME=""
BASE_MOUNTPOINT="$HOME/fuzzmounts/base"

export EC2_URL="https://ec2.us-west-2.amazonaws.com"
