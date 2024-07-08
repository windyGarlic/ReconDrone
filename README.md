

![296635735-43d28796-2855-44bb-99e8-2139d286c08d](https://github.com/windyGarlic/ReconDrone/assets/111098407/252093c3-1bed-4ecf-aedd-b07773b1d1ea)

<h1>Recon Drone</h1>

This is a tool that perform an audit of a companys public facing web assets. It will generate subdomains and gather data such as the technologies each asset 
is using such as (WAF, CDN, ect.). It can also perform vulnerability scanning on all public facing web applications.

<h2>usage</h2>

```
USAGE:
    TOOLS -
        -d string   Target domain to scan.
        -w          Enable WafW00f to gather waf info for all subdomains.
        -n          Nuclei scan using all templates across all subdomains.
        -m          Amass  enum to find extra subdomains.  (Does not support json currently)
        -a          Find extra subdomains by seaching company's entire ASN ip range (can be slow) 
        -f          Full scan. Runs all tools.
    OUTPUT -
        --json      Include output as json. 
E.g:
reconDrone -n -a -d example.com --json
