# pz-signer.deb

DEB packaging of PZ Signer from ePUAP.

This build contains fixes for Java 9+ compatibility.

Run:
```
mkdir -p /tmp/pzsigner-deb
cd /tmp/pzsigner-deb
git clone https://git.jacekk.net/r/projects/pzsigner-deb
cd pzsigner-deb
debuild -us -uc
sudo dpkg -i ../pzsigner_*_amd64.deb
```
