#!/bin/bash
result=$( grep "SOMap pickleit to ./cadetread/ubuntu/soMap.pickle" logs/monitors/resim.log )
if [[ -z "result" ]]; then
    echo "cadet test failed prepInjectWatch"
    exit 1
fi
echo "passed prep inject"
