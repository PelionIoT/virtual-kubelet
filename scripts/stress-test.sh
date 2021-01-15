#!/bin/bash

set -e

if [ -z "$4" ]
then
    echo "Usage: stress-test.sh <KaaS URL> <API Gateway> <Access Key> <Number> [prefix]"

    exit 1
fi
# KaaS URL, API Gateway, Access Key, Number
kaas_url=$1
export API_HOST=$2
export ACCESS_KEY=$3
number=$4

prefix=${5:-virtual-kubelet}

kubeconfigs_dir=/tmp/kubeconfigs
provider_config=/tmp/mock.json

mkdir -p $kubeconfigs_dir
echo "{}" > $provider_config
./generate-kubeconfigs.sh $kaas_url $prefix $number $kubeconfigs_dir
virtual-kubelet stress --provider mock --provider-config $provider_config --kubeconfigs $kubeconfigs_dir
