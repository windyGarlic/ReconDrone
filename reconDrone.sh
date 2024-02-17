#! /bin/bash

# httpx, dnsx, subfinder, amass, chaos, wafw00f, nuclei, rush, hakip2host, ddgs
dotDotDot(){
echo -n "."
sleep 0.5
echo -n "."
sleep 0.5
echo "."
sleep 0.5
}

banner(){
echo "
╦═╗╔═╗╔═╗╔═╗╔╗╔  ╔╦╗╦═╗╔═╗╔╗╔╔═╗
╠╦╝║╣ ║  ║ ║║║║   ║║╠╦╝║ ║║║║║╣ 
╩╚═╚═╝╚═╝╚═╝╝╚╝  ═╩╝╩╚═╚═╝╝╚╝╚═╝  
                            
                            - windyGarlic
                "
}

if [ "$1" = "-h" ]; then
    banner
	echo "Provide a domain as an argument and flags if required.
USAGE:
    TOOLS -
        -d string   Target domain to scan.
        -w          Enable WafW00f to gather waf info for all subdomains.
        -n          Nuclei scan using all templates across all subdomains.
        -m          Amass  enum to find extra subdomains.  (Does not support json currently), (slow)
        -a          Find extra subdomains by seaching company's entire ASN ip range (can be slow) 
        -f          Full scan. Runs all tools.
    OUTPUT (Default will be text files) -
        --json      Include output as json. 
        --sql       Upload to SQL database. (must be configured)

E.g: reconDrone -d example.com -n -a --json 
	"
	exit 0
fi

# Parse options
TEMP=$(getopt -o d:nwaf --long domain:,nuclei,wafwoof,amass,fullscan,json,sql,sheets -- "$@")

if [ $? -ne 0 ]; then
    echo "Error in command line arguments."
    exit 1
fi
if [ ! $1 ]; then
    echo "[-] No argument provided" 
    exit 1
fi
eval set -- "$TEMP"

# Default values
NUCLEI=0
WAFWOOF=0
AMASS=0
FULLSCAN=0
JSON=0
SQL=0
ASN=0


while true; do
    case "$1" in
        -d|--domain) domain="$2"; shift 2;;
        -n|--nuclei) NUCLEI=1; shift;;
        -w|--wafwoof) WAFWOOF=1; shift;;
        -m|--amass) AMASS=1; shift;;
        -a|--asn) ASN=1; shift;;
        -f|--fullscan) FULLSCAN=1; shift;;
        --json) JSON=1; shift;;
        --) shift; break;;
        *) echo "Internal error!"; exit 1;;
    esac
done

banner
echo -n "[*] Recon Drone deployed"
dotDotDot
echo "[+] Target aquired: $domain"


if [ ! -e "../../bugbounty.txt" ]; then
    curl -s https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/chaos-bugbounty-list.json > bugbounty.txt
else
    echo "[-]"
fi

url="https://$domain"
url2="https://www.$domain"
chaosKey='OXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXg'


if [[ ! -e results ]]; then mkdir results; fi
cd results
if [[ -s $domain ]]; then mv $domain $RANDOM.$domain;fi

mkdir $domain
cd $domain
echo $domain > domain.txt
echo $url > url.txt

dig $domain | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' > temp.txt 
sed -n '2p' temp.txt > ip.txt 
rm temp.txt


while read ip;
do
     whois -r $ip >> whois.txt 
     whois -h whois.cymru.com $ip >> whois.txt 
done<ip.txt

echo -n "[+] IP found: "
cat ip.txt

IPforScan=$(cat ip.txt)
curl -s https://api.iplocation.net/?ip=$IPforScan | jq .isp > cloudHosting.txt &
curl -s -L $url | grep 'href' | grep "linkedin" > linkedin.txt &
curl -s -sILk $url/security.txt > temp &
curl -s -sILk $url/.well-known/security.txt >> temp &
curl -s -sILk $url > header.txt &
curl -s -L $url | grep -m 1 -o -P '(?<=<title>).*(?=</title?)' > title.txt &


if [[ $JSON -eq '1' ]]; then
    /home/windygarlic/go/bin/subfinder -silent -d $domain -oJ >> temp.txt 
else
    /home/windygarlic/go/bin/subfinder -silent -d $domain >> temp.txt 
fi


if [[ $JSON -eq '1' ]]; then
    /home/windygarlic/go/bin/chaos -silent -key $chaosKey -d $domain -json >> temp.txt   
else
    /home/windygarlic/go/bin/chaos -silent -key $chaosKey -d $domain >> temp.txt   
fi


if [[ $AMASS == "1" ]]; then
    amass enum -silent -d $domain >> temp.txt
fi


if [[ $ASN == "1" ]]; then
	ip_to_int() {
    	local ip="$1"
    	IFS=. read -r i1 i2 i3 i4 <<< "$ip"
    	echo "$(( (i1<<24) + (i2<<16) + (i3<<8) + i4 ))"
	}

	int_to_ip() {
	    local int="$1"
	    echo "$(( (int>>24)&255 )).$(( (int>>16)&255 )).$(( (int>>8)&255 )).$(( int&255 ))"
	}

	# Gets ASN data base 
	if [ ! -e "../../ip2asn-v4.tsv" ]; then
	    wget https://iptoasn.com/data/ip2asn-v4.tsv.gz 2> /dev/null
	    gunzip ip2asn-v4.tsv.gz 2> /dev/null
        mv ip2asn-v4.tsv ../../
	fi

	COMPANY=$(echo $DOMAIN | awk -F "." '{print$1}')
    ddgs text -k "$domain asn ip" -m 5 -o csv
    ASN=$(cat *.csv | grep -o 'AS[0-9]\+' | head -n1 | awk -F "S" '{print $2}')
    
    
    if [ ! -z "$ASN" ]; then

	    cat ../../ip2asn-v4.tsv | grep -i "$ASN" | grep -i "$COMPANY" | awk -F " " '{print $1" "$2}' > ipRange
    
        # Checks for asn in data and returns ip-range. Will prompt user to enter company name if no ranges found. 
	    if [ -s ipRange ] ; then
	    		while read line; do
	            	start_ip=$(echo $line | awk -F " " '{print $1}')
	            	end_ip=$(echo $line | awk -F " " '{print $2}')
	            	start_int=$(ip_to_int "$start_ip")
	            	end_int=$(ip_to_int "$end_ip")

	    		    for ((int = start_int; int <= end_int; int++)); do
	    		        current_ip=$(int_to_ip "$int")
	    		        echo "$current_ip" >> ipList
	    	    	done
	    	done < ipRange
	    fi
	    # Scans IP range for extra domainns
	    cat ipList | hakip2host | sort -u >> tmp
	    cat tmp | awk -F " " '{print$3}' | sort -u | grep -v "*" >> temp.txt
        rm *.csv
	    rm tmp 
    fi
fi


sort temp.txt | uniq > subs.txt
rm temp.txt


if [[ $JSON -eq '1' ]]; then
    cat subs.txt | /home/windygarlic/go/bin/dnsx -silent -cdn -j > dnsx.cdn 
else
    cat subs.txt | /home/windygarlic/go/bin/dnsx -silent -cdn > dnsx.cdn 
fi

cat dnsx.cdn | wc -l > numberOfAssets
cat subs.txt | httpx -silent >> httpx.txt
cat httpx.txt | wc -l > numberOfWebApps
cat httpx.txt |  grep -o '\//.*' | cut -c 3- > subs2.txt
assNum=$(cat httpx.txt | wc -l)
echo "[+] Subdomains found: $assNum"


while read subdomains; do
    echo -n $subdomains >> hosting.txt
    dig +short $subdomains > tmp
	IP=$(tail -n 1 tmp) 
    curl -s https://api.iplocation.net/?ip=$IP | jq .isp >> hosting.txt 
    rm tmp
done<subs2.txt


if [[ $WAFWOOF == "1" ]]; then
    if [[ $JSON == "1" ]]; then
        wafw00f -i httpx.txt --format=json 2> /dev/null | grep site | grep '[+]' > waf.txt
    else
        wafw00f -i httpx.txt 2> /dev/null | grep site | grep '[+]' > waf.txt
    fi

    wc -l waf.txt | sed 's/ .*//' > wafNumber.txt
    echo -n 'Total=' >> waf.providers
    cat wafNumber.txt >> waf.providers
    if grep -q 'Cloudflare' waf.txt; then
        echo -n 'Cloudflare=' >> waf.providers
        grep -c 'Cloudflare' waf.txt >> waf.providers
    fi
    if grep -q 'Akamai' waf.txt; then
        echo -n 'Akamai=' >> waf.providers
        grep -c 'Akamai' waf.txt >> waf.providers
    fi
    if grep -q 'Amazon' waf.txt; then
        echo -n 'Amazon=' >> waf.providers
        grep -c 'Amazon' waf.txt >> waf.providers
    fi
    if grep -q 'Citrix' waf.txt; then
        echo -n 'Citrix=' >> waf.providers
        grep -c 'Citrix' waf.txt >> waf.providers
    fi
    if grep -q 'Imperva' waf.txt; then
        echo -n 'Imperva=' >> waf.providers
        grep -c 'Imperva' waf.txt >> waf.providers
    fi
    if grep -q 'Microsoft' waf.txt; then
        echo -n 'Microsoft=' >> waf.providers
        grep -c 'Microsoft' waf.txt >> waf.providers
    fi
    if grep -q 'F5' waf.txt; then
        echo -n 'F5=' >> waf.providers
        grep -c 'F5' waf.txt >> waf.providers
    fi
    if grep -q 'IBM' waf.txt; then
        echo -n 'IBM=' >> waf.providers
        grep -c 'IBM' waf.txt >> waf.providers
    fi
fi

if [[ $NUCLEI == "1" ]]; then 

    if [[ $JSON == "1" ]]; then 
        /home/windygarlic/go/bin/nuclei -l httpx.txt -j -o nucleiScan.txt
    else
        /home/windygarlic/go/bin/nuclei -l httpx.txt -o nucleiScan.txt
    fi
    grep info nucleiScan.txt > info.txt
    grep low nucleiScan.txt > low.txt
    grep medium nucleiScan.txt > medium.txt
    grep high nucleciScan.txt > high.txt
    grep unknown nucleiScan.txt > unknown.txt
    grep critical nucleiScan.txt > crit.txt

    cat info.txt | wc -l  > numberOfInfos
    cat med.txt  | wc -l > numberOfMeds
    cat high.txt | wc -l  > numberOfHighs
    cat low.txt  | wc -l > numberOfLows
    cat unknown.txt | wc -l > numberOfUnknowns
    cat crit.txt | wc -l  > numberOfCrits
fi 

#nmap -sC -sV -iL ip.txt -oN initial_nmap.txt

mkdir isp
cd isp
cat ../hosting.txt | grep -i "akamai" > akamai
cat ../hosting.txt | grep -i "amazon" > amazon
cat ../hosting.txt | grep -i "cloudflare" > cloudflare
cat ../hosting.txt | grep -i "Microsoft" > microsoft
cat ../hosting.txt | grep -i "salesforce" > salesforce
cat ../hosting.txt | grep -i "Incapsula" > incapsula
cat ../hosting.txt | grep -i "Telstra" > Telstra
cat ../hosting.txt | grep -i "Google" > Google
cat ../hosting.txt | grep -i "Fastly" > Fastly
cat ../hosting.txt | grep -i "Rackspace" > Rackspace	
wc -l * > ../realCDN
cd ..

while read sub; do curl -s -D- $sub | grep -i "strict-transport-security:" | sort -u >> hsts.txt; done < httpx.txt
while read sub; do curl -s -D- $sub | grep -i "content-security-policy:" | sort -u >> csp.txt; done < httpx.txt

totalhttp=$(cat httpx.txt | sort -u | wc -l)
totalhsts=$(cat hsts.txt | wc -l)
totalcsp=$(cat csp.txt | wc -l)
csppercent=$(( $totalcsp*100/$totalhttp )) || echo '[-]'
hstspercent=$(( $totalhsts*100/$totalhttp )) || echo '[-]'
echo $hstspercent | sort -u > hstspercent
echo $csppercent | sort -u > cspPercent
cat header.txt | grep 'x-xss' >  policy.txt 
cat header.txt | grep 'x-frame' >> policy.txt
cat temp | grep "200 OK" > security.txt 
rm temp

echo -n "[+] Generating report"
dotDotDot

echo "--------" >> report
echo "Report - " >> report
echo "--------" >> report
echo "" >> report
echo -n "Domain: " >> report
cat domain.txt >> report 2> /dev/null
echo -n "URL: " >> report
cat url.txt >> report 2> /dev/null
echo -n "Hosting: " >> report 
cat cloudHosting >> report  2> /dev/null|| echo "NA" >> report 2> /dev/null
echo -n "LinkedIn: " >> report
cat linkedin.txt >> report 2> /dev/null || echo "NA" >> report 2> /dev/null
echo "" >> report
echo -n "Number of apps with WAF: " >> report 
cat wafNumber.txt >> report  2> /dev/null || echo "NA" >> report
echo -n "Number of assets: " >> report
cat numberOfAssets  >> report || echo "NA" >> report
echo -n "Number of web apps: " >> report
cat numberOfWebApps >> report  2> /dev/null|| echo "NA" >> report
echo -n "Percent of apps with CSP: " >> report
cat cspPercent >> report  2> /dev/null|| echo "NA" >> report
echo -n "Percent of apps with HSTS: " >> report
cat hstsPercent >> report  2> /dev/null|| echo "NA" >> report
echo "" >> report
cat policy.txt >> report 2> /dev/null
echo "" >> report
echo "Vulnerabilities" >> report
echo -n "Critical: " >> report
cat  numberOfCrits >> report  2> /dev/null|| echo "NA" >> report 2> /dev/null
echo -n "High: " >> report
cat numberOfHighs >> report  2> /dev/null|| echo "NA" >> report 2> /dev/null
echo -n "Medium: " >> report
cat numberOfMeds >> report  2> /dev/null|| echo "NA" >> report 2> /dev/null
echo -n "Low: " >> report
cat numberOfLows >> report  2> /dev/null|| echo "NA" >> report 2> /dev/null
echo -n "Unknown: " >> report
cat numberOfUnknowns >> report 2> /dev/null || echo "NA" >> report 2> /dev/null

mkdir vulns 2> /dev/null
mv crit.txt vulns 2> /dev/null
mv high.txt vulns 2> /dev/null
mv medium.txt vulns 2> /dev/null
mv low.txt vulns 2> /dev/null
mv info.txt vulns 2> /dev/null
mv unknown.txt vulns 2> /dev/null
mv nucleiScan.txt vuln 2> /dev/null

mkdir subdomains 2> /dev/null
mv httpx.txt subdomains 2> /dev/null
mv dnsx.cdn subdomains  2> /dev/null
mv waf.txt subdomains 2> /dev/null

mkdir info 2> /dev/null
mv whois.txt info 2> /dev/null
mv ip.txt info  2> /dev/null
mv header.txt info  2> /dev/null
mv report info  2> /dev/null
mv security.txt info 2> /dev/null
mv realCDN info/CDNInfo 2> /dev/null

rm domain.txt  2> /dev/null
rm url.txt  2> /dev/null
rm cloudHosting.txt 2> /dev/null
rm hosting.txt 2> /dev/null
rm csp.txt 2> /dev/null
rm hsts.txt 2> /dev/null
rm linkedin.txt  2> /dev/null
rm cspPercent  2> /dev/null
rm hstspercent  2> /dev/null
rm policy.txt  2> /dev/null
rm wafNumber.txt  2> /dev/null
rm numberOfAssets  2> /dev/null
rm numberOfWebApps  2> /dev/null
rm numberOfCrits  2> /dev/null
rm numberOfHighs  2> /dev/null
rm numberOfMeds  2> /dev/null
rm numberOfLows  2> /dev/null
rm numberOfUnknowns 2> /dev/null
rm numberOfInfos  2> /dev/null
rm subs2.txt  2> /dev/null
rm title.txt  2> /dev/null
rm subs.txt  2> /dev/null
rm waf.providers  2> /dev/null
rm subs2.txt    2> /dev/null
rm title.txt  2> /dev/null
rm subs.txt  2> /dev/null
rm waf.providers  2> /dev/null
rm -r isp/ 2> /dev/null

echo -n "[+] Cleaning in progress"
dotDotDot
cd ../../ 
echo "[*] Recon mission complete."
