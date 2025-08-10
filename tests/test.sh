#!/bin/bash

RESET="\e[0m"
RED="\e[1;31m"
GREEN="\e[1;32m"

named_dir=./build/named
named_pid_path=$named_dir/named.pid
keys_path=./tests/bind/keys
named_config_path=./tests/bind/named.conf
base_zone_path=./tests/bind/base.db
zone_names=(unsigned.com signed.com)

bind_cases_src_dir=./tests/cases/bind
cases_out_dir=./build/tests/cases

# Check executables
executables=(named named-checkzone awk sed)
for executable in "${executables[@]}"; do
    if [ ! -x "$(command -v $executable)" ]; then
        echo "[ERROR] $executable is not installed"
        exit 1
    fi
done

# Setup named directory
mkdir -p $named_dir
cp -r $keys_path $named_dir

# Create a zone file for every zone name
# The entries are defined in test cases as comments that start with ///
zone_entries=$(grep -r "///" $bind_cases_src_dir | sed -re 's/(\S+):\s*\/{3} (.+)/\2 ; \1/')
for zone_name in "${zone_names[@]}"; do
    zone_path=$named_dir/$zone_name.db
    echo -e "$(cat $base_zone_path)\n$zone_entries" > $zone_path

    output=$(named-checkzone -i local -k fail $zone_name $zone_path)
    if [ $? -ne 0 ]; then
        echo "[ERROR] $output"
        exit 1
    fi
done

# Start named
named -c $named_config_path
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to start named"
    exit 1
fi

# Terminate named before exiting
trap "kill -- \$(cat $named_pid_path)" SIGINT SIGTERM EXIT

# Run tests
passed=0
failed=0
for test in $(find $cases_out_dir -type f -executable); do
    # Remove common path
    test_name=$(echo $test | awk -F/ '{print $NF}')

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
