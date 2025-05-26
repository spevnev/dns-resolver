#!/bin/bash

RESET="\e[0m"
RED="\e[1;31m"
GREEN="\e[1;32m"

named_dir=./build/named
named_conf_path=./tests/named.conf
named_pid_path=$named_dir/named.pid
zone_base_path=./tests/test.zone.base
zone_file_path=$named_dir/test.zone
zone_name=test.com
cases_src_dir=./tests/cases
cases_out_dir=./build/tests/cases

set -e -o pipefail

# Check executables
executables=(named named-checkzone)
for executable in "${executables[@]}"; do
    if [ ! -x "$(command -v $executable)" ]; then
        echo "[ERROR] $executable is not installed"
        exit 1
    fi
done

# Create zone file
mkdir -p $named_dir
cp $zone_base_path $zone_file_path
zone_entries=$(grep -r "///" $cases_src_dir | sed -re 's/(\S+):\s*\/{3} (.+)/\2 ; \1/')
echo -e "\n$zone_entries" >> $zone_file_path

# Check zone file, and print output on error
set +e
output=$(named-checkzone -k fail $zone_name $zone_file_path)
if [ $? -ne 0 ]; then
    echo "$output"
    exit 1
fi
set -e

# Start named
named -c $named_conf_path

# Terminate named before exiting
trap "kill -- \$(cat $named_pid_path)" SIGINT SIGTERM EXIT

# Run tests
set +e
passed=0
failed=0
for test in $(find $cases_out_dir -type f -executable); do
    # Remove common path
    test_name=$(echo $test | cut -c $((${#cases_out_dir}+2))-)

    $test
    if [ $? -eq 0 ]; then
        echo -e $GREEN"[PASSED] $test_name"$RESET
        ((passed += 1))
    else
        echo -e $RED"[FAILED] $test_name"$RESET
        ((failed += 1))
    fi
done
echo ""
echo "Total:"
echo "    Passed: $passed"
echo "    Failed: $failed"

if [ $failed -ne 0 ]; then
    exit 1
fi
