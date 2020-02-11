#!/bin/bash

function run_mutation_folder()
{
    cd /home/fivosts/Repos/aleth/workspace/mutec
    for filename in ./aleth/$1/*; do

    #   ## Move file
        noprefix=${filename##*/}
        nosuffix=${noprefix%".mutec"*}
        cp $filename ../../$1/$nosuffix

    #   # Compile ethereum
        cd /home/fivosts/Repos/aleth/build
        cmake --build .

    #   # Execute for 2254
        cd /home/fivosts/Repos/aleth/build/test/
        for ((i=1; i <= 2254; i++)); do
            # ./testeth -t DifficultyTests/difficultyByzantium$i >> /home/fivosts/Repos/aleth/workspace/mutec/results/$1/$noprefix.txt
            TESTOUT=$( { ./testeth -t DifficultyTests/difficultyByzantium$i >> /home/fivosts/Repos/aleth/workspace/mutec/results/$1/$noprefix.txt; } 2>&1 )
            echo $TESTOUT >> /home/fivosts/Repos/aleth/workspace/mutec/results/$1/$noprefix.txt
            echo "" >> /home/fivosts/Repos/aleth/workspace/mutec/results/$1/$noprefix.txt

        done

    #   # Rollback version
        cd /home/fivosts/Repos/aleth/$1
        git checkout ./*
        cd /home/fivosts/Repos/aleth/workspace/mutec

    done
}

function run_successful_mutants()
{
    cd /home/fivosts/Repos/aleth/workspace/mutec/results/
    mutants=$(grep -lnr "HAVE FAILED")

    for f in $mutants; do

        pass_keys=()

        ## Checked
        string="++ ./testeth -t DifficultyTests/difficultyByzantium"
        while IFS= read -r line
        do
            if [[ $line == $string* ]]; then
              temp=${line#$string}
              number=${temp%%" "*}
              # echo $number
              if [[ $line == *"No errors"* ]]; then
                pass_keys+=(1)
              else
                pass_keys+=(0)
              fi
            fi
        done < $f

        nosuffix=${f%".mutec"*}

        path=${f%".txt"*}
        full_path=${path##*/}

        ## Checked
        cd /home/fivosts/Repos/aleth/workspace/mutec/aleth/
        cp $path /home/fivosts/Repos/aleth/$nosuffix
        
        cd /home/fivosts/Repos/aleth/build
        # cmake --build . --target testeth

        cd /home/fivosts/trace_classification/aleth/traces/
        echo $full_path
        mkdir $full_path

        ### Checked
        cd $full_path
        mkdir pass
        mkdir fail

        ### Checked
        cd pass
        mkdir traces
        mkdir reduced_traces
        mkdir encoded_traces

        ### Checked
        cd ../fail
        mkdir traces
        mkdir reduced_traces
        mkdir encoded_traces

        cd /home/fivosts/Repos/aleth/build/test/

        for ((i=1; i <= 2254; i++)); do
            j=$((i-1))
            echo $i
            echo $j
            if [[ "${pass_keys[$j]}" == "1" ]]; then
                ./testeth -t DifficultyTests/difficultyByzantium$i > /home/fivosts/trace_classification/aleth/traces/$full_path/pass/traces/trace$i.log
            elif [[ "${pass_keys[$j]}" == "0" ]]; then
                ./testeth -t DifficultyTests/difficultyByzantium$i > /home/fivosts/trace_classification/aleth/traces/$full_path/fail/traces/trace$i.log
            else
                echo "PROBLEM"
                echo $j
                echo $i
                echo "${pass_keys[@]}"
                exit
            fi
        done

        cd /home/fivosts/Repos/aleth
        git checkout $nosuffix
        cd /home/fivosts/Repos/aleth/workspace/mutec/results/
    done

}

set -ex 
# run_mutation_folder "libdevcore"
# run_mutation_folder "libdevcrypto"
# run_mutation_folder "libethashseal"
# run_mutation_folder "libethcore"
# run_mutation_folder "libethereum"
# run_mutation_folder "libevm"
run_successful_mutants