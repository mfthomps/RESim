README for populating CSETs for use by the monitor.


There are three repo locations:
    /mnt/vmLib/bigstuff/cfe-challenges:  debian packages from jenkins builds
    /mnt/vmLib/bigstuff/cgc-challenges:  expanded packages.
    /mnt/vmLib/cgcForensicsRepo/CB-share/... binaries, polls and pov files renamed for use by the monitor

CSET debian packages are retrieved from cgc-dev using fetchSets.py,
which gathers a list of CFE-style CSETs by looking at a local svn repo. So,
first svn up on that repo.

Then run ./sortLatestSets.py to remove old dups.

The .deb packages are expanded using "expandSets.py", which should be run on the NFS host,
e.g., bladet1.  Redirect output to expand.txt, then run mkNewCBList.py to get a list of
just the CBs that changed.

Once the CSETs are expanded, use ./getCFE_CSET_IDs_actual.py to create a list of CSETs,
which is written to allCFE-CSETS.txt.  This file is put into /usr/share/cgc-monitor by the
demoRepo package.

Then ./dobuild.sh and collectPackages.  And run updatePackages; fullCB on the NFS host.


FOR the test harness:
use pushCSETs-cgc-cfe.sh and pushCSETs-gw.sh to push the csets to gateways/controllers,
then on the gateway, in the working directory, run 
updateCSETs
mkTar...
or syncPoller...


In the load-tests svn, run:
getCFE_CSET_IDs_actual.py

then cd ../; ./load-test-distrib.sh
then expand that tar into the dev directory of each controller/gateway
