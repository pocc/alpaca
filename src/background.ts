/* Background script. */
const browser = chrome;
let PUBLIC_SUFFIX_LIST = Object();
let CF_IPv4_LIST: string[] = []
let CF_IPv6_LIST: string[] = []
let AWS_LIST: {[ipaddr: string]: string} = {}
let ACTIVE_URL = '';
let DNS_CACHE: {[iso8601_date: string]: {[hostname: string]: string[]}} = {}  // Saving the DNS CACHE, per day
const getDate = () => new Date().toISOString().substr(0,10)

const DEBUG = false;

const RESERVED_IPV4 = {
    "0.0.0.0/8": "Current network",
    "10.0.0.0/8": "Private network    Used for local communications within a private network.",
    "100.64.0.0/10": "Private network    Shared address space for communications between a service provider and its subscribers when using a carrier-grade NAT.",
    "127.0.0.0/8": "Host    Used for loopback addresses to the local host.",
    "169.254.0.0/16": "Subnet    Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified, such as would have normally been retrieved from a DHCP server.",
    "172.16.0.0/12": "Private network    Used for local communications within a private network.",
    "192.0.0.0/24": "Private network    IETF Protocol Assignments.",
    "192.0.2.0/24": "Documentation    Assigned as TEST-NET-1, documentation and examples.",
    "192.88.99.0/24": "Internet    Reserved. Formerly used for IPv6 to IPv4 relay (included IPv6 address block 2002::/16).",
    "192.168.0.0/16": "Private network    Used for local communications within a private network.",
    "198.18.0.0/15": "Private network    Used for benchmark testing of inter-network communications between two separate subnets.",
    "198.51.100.0/24": "Documentation    Assigned as TEST-NET-2, documentation and examples.",
    "203.0.113.0/24": "Documentation    Assigned as TEST-NET-3, documentation and examples.",
    "224.0.0.0/4": "Internet    In use for IP multicast.[11] (Former Class D network.)",
    "233.252.0.0/24":"Documentation    Assigned as MCAST-TEST-NET, documentation and examples.",
    "240.0.0.0/4": "Internet    Reserved for future use.[13] (Former Class E network.)",
    "255.255.255.255/32": "Subnet    Reserved for the `limited broadcast` destination address."
}

const RESERVED_IPV6 = {
    
}


// For a tab, record the last url matching the regex and the timestamp of when it was visited
const EXTN_URL = chrome.runtime.getURL('')
const formatLog = (requestID: string, msg: string, data: any) => {
    console.log(`Alpaca|${new Date().getTime()}|${requestID}|${msg}: `, data)
}


browser.runtime.onInstalled.addListener(async () => {
    PUBLIC_SUFFIX_LIST = await setPublicSuffixList(); // Only check PSL on install
    const respv4 = await fetch('https://www.cloudflare.com/ips-v4')
    CF_IPv4_LIST = (await respv4.text()).split('\n')
    const respv6 = await fetch('https://www.cloudflare.com/ips-v6')
    CF_IPv6_LIST = (await respv6.text()).split('\n')
    formatLog('0', `Loaded PSL with this many entries`, PUBLIC_SUFFIX_LIST.length);
    formatLog('0', 'Alpaca Chrome extension has been installed at', EXTN_URL);
    const aws_resp = await fetch('https://ip-ranges.amazonaws.com/ip-ranges.json')
    const aws_text = await aws_resp.text()
    const aws_json = JSON.parse(aws_text)
    for (const i of aws_json.prefixes) {
        AWS_LIST[i.ip_prefix] = i.region
    };
    for (const i of aws_json.ipv6_prefixes) {
        AWS_LIST[i.ipv6_prefix] = i.region
    }
    /*
    Use CSS from https://sharkcoder.com/visual/shapes to make text more distinct

    2px px border
        orange | cloudflare
        red | fastly
        teal | cloudfront

    1px dark green border
        green | example.com, fe80::, ::, 169.254.x.x, private ip addresses

    grey border 2px: cloud; white border 2px: company
        blue1 | azure, similar color for microsoft
        blue2 | gcp, google
        blue3 | aws, amazon
        blue4 | facebook
        blue5 | apple
    /*

    /*
    const gcp_resp = await fetch('https://www.gstatic.com/ipranges/cloud.json')
    const gcp_text = await gcp_resp.text()
    const gcp_json = JSON.parse(gcp_text)
    for (const i of gcp_json.prefixes) {
        GCP_LIST[i.ip_prefix] = i.region
    };
    for (const i of gcp_json.ipv6_prefixes) {
        GCP_LIST[i.ipv6_prefix] = i.region
    }
    const azure_resp = await fetch('https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519')
    */

    formatLog('0', 'Alpaca Chrome extension loaded with this number of AWS entries', Object.keys(AWS_LIST).length);
});

// Don't need tab of update because we need to query tabs for url anyway
chrome.tabs.onActivated.addListener((_activeInfo)=> {
    console.log("Alpaca| Tab activated", _activeInfo);
    chrome.tabs.query({active: true}, (tabs) => {
        ACTIVE_URL = tabs[0].url || tabs[0].pendingUrl || ACTIVE_URL;  // If url isn't available, page is still loading
    });
});

chrome.tabs.onUpdated.addListener((_tabID, _changeInfo, tab) => {
    if (_changeInfo.status === 'complete') {
        if (DEBUG)
            console.log("Tab update completed", _tabID, _changeInfo, tab);
        sendMessage(_tabID, _changeInfo.url || tab.url || '');
    }
    ACTIVE_URL = tab.url || ACTIVE_URL;
});

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
        parseArgs(request, sender).then(sendResponse)
        return true;
    }
);


function sendMessage(tab_id: number, url: string) {
    if (DEBUG)
        console.log("Attempting to send to active tabs and got these vars", tab_id, url)
    if (tab_id && url.startsWith('http')) {
        if (DEBUG)
            console.log("Alpaca| Sending message to tab", tab_id, "at", url)
        chrome.tabs.sendMessage(tab_id, {event: "tab_updated", url: url}, function(response) {
            console.log("Alpaca| Sent message and received response", response)
        });
    }
}

async function setPublicSuffixList() {
    const PUBLIC_SUFFIX_URL = 'https://publicsuffix.org/list/public_suffix_list.dat'
    const resp = await fetch(PUBLIC_SUFFIX_URL)
    let resptext = await resp.text()
    resptext = resptext.split('// ===END ICANN DOMAINS===')[0]  // Use only public domains
    const public_suffixes = [...resptext.matchAll(/\n([^\n\/].*)/g)].map((i) => i[1])
    return public_suffixes
}

// Remove subdomains, protocol, searches, and hashes from domain, 'https://blog.github.com?search=true' => 'github.com'
/*function getBaseDomain(url: string): string {
    const hostname = (new URL(url)).hostname
    const parts = hostname.split('.')
    let rightside = parts.pop() as string;
    let publicSuffix;
    // Be as greedy as possible when it comes to possible effective TLDs.
    for (const part of parts.reverse()) {
        publicSuffix = rightside
        rightside = `${part}.${rightside}`
        if (!PUBLIC_SUFFIX_LIST.includes(rightside)) { // If the parsed domain from the right is no longer in PSL
            const re = new RegExp(`(.*)\.${publicSuffix}$`, 'g');
            let registeredDomain = (re.exec(hostname) as string[])[1]; 
            // remove subdomains
            if (registeredDomain.includes('.')) registeredDomain = registeredDomain.split('.').reverse()[0]
                return  registeredDomain + '.' + publicSuffix
        }
    }
    return ''
}*/

export interface Question {
    name: string;
    type: number;
}

export interface Answer {
    name: string; // hostname
    type: number;
    TTL: number;
    data: string; // IP address
}

export interface DNSQuery {
    Status: number;
    TC: boolean;
    RD: boolean;
    RA: boolean;
    AD: boolean;
    CD: boolean;
    Question: Question[];
    Answer: Answer[];
}

function is_domain_valid(domain: string) {
    let is_valid_domain = false
    for (const tld of PUBLIC_SUFFIX_LIST) {
        if (domain === tld) {
            return false
        }
        if (domain.endsWith('.' + tld) && domain.length > tld.length + 1) {
            is_valid_domain = true
        }
    }
    return is_valid_domain;
}

async function DNSLookup(domain: string): Promise<string[] | []> {
    const A_TYPE = 1
    const AAAA_TYPE = 28
    const todaysDate = getDate()
    if (!is_domain_valid(domain))
        return ["invalid_domain"]

    DNS_CACHE[todaysDate] = DNS_CACHE[todaysDate] || {}
    if (DNS_CACHE[todaysDate][domain]) {
        if (DEBUG)
            console.log("Hit cache for", domain)
        return DNS_CACHE[todaysDate][domain]
    } else {
        if (DEBUG)
            console.log("missed", DNS_CACHE)
    }
 
    try {
        const required_headers = {headers: {'accept': 'application/dns-json'}}
        const respA = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, required_headers);
        const respTextA = await respA.text();
        if (DEBUG)
            console.log("Alpaca| Sending IPv4 DNS query for", domain, "Got", respTextA)
        const respJSONA: DNSQuery = JSON.parse(respTextA);
        let answers: Answer[];
        if (respJSONA.Status === 0 && respJSONA.Answer) {
            answers = respJSONA.Answer.filter((rr) => rr.type === A_TYPE)
        } else {
            // if IPv4 fails, try IPv6
            const respAAAA = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=AAAA`, required_headers);
            const respTextAAAA = await respAAAA.text();
            if (DEBUG)
                console.log("Alpaca| Sending IPv6 DNS query for", domain, "Got", respTextAAAA)
            const respJSONAAAA: DNSQuery = JSON.parse(respTextAAAA);
            if (!respJSONAAAA.Answer) {
                return [] // We've exhausted both IPv4 and IPv6 record requests
            }
            answers = respJSONAAAA.Answer.filter((rr) => rr.type === AAAA_TYPE)
        }
        let ip_addrs = []
        for (const rr of answers) {
            ip_addrs.push(rr.data)
        }
        console.log("Alpaca| Found IP ADDRs", ip_addrs, "for domains", domain, ". Adding to cache")
        DNS_CACHE[todaysDate][domain] = ip_addrs
        return ip_addrs
    } catch {
        return []
    }
}

async function parseArgs(request: any, sender: any) {
    if (DEBUG)
        console.log(sender.tab ?
            "Alpaca| Got request from content script: " + sender.tab.url + JSON.stringify(request):
            "Got request from the extension");
    if (request.requestName === "CF_IPV4_LIST") {
        return {data: CF_IPv4_LIST};
    } else if (request.requestName === "CF_IPV6_LIST") {
        return {data: CF_IPv6_LIST};
    } else if (request.requestName === "DNS_LOOKUP") {
        let domain = request.domain
        if (domain.includes('://')) { // Get rid of scheme
            domain = domain.split('://')[1]
        }
        const ip_addrs: string[] = await DNSLookup(domain)
        return {data: ip_addrs, error: ip_addrs && ip_addrs[0] === "invalid_domain"};
    }
    return {data: "UNKNOWN REQUEST NAME"};
}