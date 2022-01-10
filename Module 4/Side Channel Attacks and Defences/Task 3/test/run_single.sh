#!/bin/bash

source /etc/environment
timeout 5s /home/sgx/pin-3.11-97998-g7ecce2dac-gcc-linux-master/source/tools/SGXTrace/run_tracer.sh $1 $2
