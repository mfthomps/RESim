#!/bin/bash
echo "RESIM_DIR is $RESIM_DIR"
sudo cp $RESIM_DIR/simics/setup/lmgrdFix /usr/bin/
gotit=$(grep lmgrdFix /etc/rc.local)
if [[ -z "$gotit" ]]; then
    echo '/usr/bin/lmgrdFix' | sudo tee -a /etc/rc.local
    sudo /usr/bin/lmgrdFix
fi

