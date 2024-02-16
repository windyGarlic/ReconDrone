echo  "Requires go" 
sleep 0.2
echo "This must be run with sudo"
sleep 0.5 
#pip install -r requirements.txt
cp reconDrone.sh reconDrone
chmod +x reconDrone
cp reconDrone /usr/bin/

pip install -U duckduckgo_search

if ! which httpx > /dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
fi
if ! which dnsx > /dev/null; then
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
fi
if ! which subfinder > /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi
if ! which amass > /dev/null; then
    go install -v github.com/owasp-amass/amass/v4/...@master
fi
if ! which chaos > /dev/null; then
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
fi
if ! which wafw00f > /dev/null; then
    git clone https://github.com/EnableSecurity/wafw00f.git
    cd wafw00f/
    python3 setup.py install
fi
if ! which nuclei > /dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
fi
if ! which hakip2host > /dev/null; then
    go install github.com/hakluke/hakip2host@latest
fi
