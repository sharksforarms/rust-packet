set -xe

FUZZERS=$(TERM="" cargo fuzz list)
## build fuzzers
echo $FUZZERS | xargs -i cargo fuzz run {} -- -runs=0

wget -q -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/download/v2.4.29/fuzzit_Linux_x86_64
chmod a+x fuzzit


for FUZZER in $(echo $FUZZERS)
do
    if [ $1 == "fuzzing" ]; then
        ./fuzzit create job fuzzitdev/$FUZZER ./fuzz/target/x86_64-unknown-linux-gnu/debug/$FUZZER
    else
        ./fuzzit create job --type local-regression fuzzitdev/$FUZZER ./fuzz/target/x86_64-unknown-linux-gnu/debug/$FUZZER
    fi
done
