#!/bin/bash

set -e

if [ -z "$3" ]
then
    echo "Usage: stress-test.sh <SERVER_URI> <ACCOUNT_ID> <NUMBER>"

    exit 1
fi

kubeconfigs_dir=/tmp/kubeconfigs
provider_config=/tmp/mock.json

mkdir -p $kubeconfigs_dir
echo "{}" > $provider_config
./generate-kubeconfigs.sh $1 $2 $3 $kubeconfigs_dir
virtual-kubelet stress --provider mock --provider-config $provider_config --kubeconfigs $kubeconfigs_dir