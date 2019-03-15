# mitmproxy-adblock

The goal of this repo is to add ad-blocking to
[mitmproxy](https://github.com/mitmproxy/mitmproxy/).

To setup clone the latest version of mitmproxy and copy the files from this
repo into the mitmproxy directory.  Setup the virtual environment using dev.sh
and then run using `mitmdump -s ./blockrequest.py`.

Update the blocklist (Easylist and EasyPrivacy) by downloading the latest
versions as .txt files in the blocklists folder.
