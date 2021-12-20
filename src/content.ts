import { dns_response } from '../index';
// Alpaca Content Script
const browser = chrome
const DEBUG = false
let DNS_CACHE: {[url: string]: string[]} = {}  // Having a DNS_CACHE on an ephemeral page sholud be fine
let LAST_URL = ""
const NO_ERR = ""

console.log("Alpaca|", "🎬"," Content script loaded on", document.location.href)
window.addEventListener('load', contentScriptMain);

let CF_IPV4_LIST: string[] = []
let CF_IPV6_LIST: string[] = []
let PUBLIC_SUFFIX_LIST: string[] = []
chrome.runtime.sendMessage({requestName: "CF_IPV4_LIST"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received from background script, asked for IPv4", response.data)
    CF_IPV4_LIST = response.data
});
chrome.runtime.sendMessage({requestName: "CF_IPV6_LIST"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received from background script, asked for IPv6", response.data)
    CF_IPV6_LIST = response.data
});
chrome.runtime.sendMessage({requestName: "PUBLIC_SUFFIX_LIST"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received from background script, asked for IPv6", response.data)
    PUBLIC_SUFFIX_LIST = response.data
});


chrome.runtime.onMessage.addListener(
    function(request, _, sendResponse) {
        if (DEBUG)
            console.log("Alpaca|", "💬", "Received message from background script", request)
        if (!request.url && !request.event) {
            console.log("Alpaca|", "💬", "Problem parsing request. Expecting url, event:", request)
        }
        // If there's a new URL that hasn't been highlighted
        if (LAST_URL !== request.url) {
            highlight(ADDR_REGEX)
            sendResponse('Highlighting ' + request.url);
        } else {
            sendResponse("Not highlighting")
        }
        return true;
    }
);

// Taken from https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
const IPV4ADDR_RE  = /((?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\/?\d{0,2})/g
const IPV6ADDR_RE = new RegExp('((?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\\/?\\d{0,2})', 'g')
// https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
// test against https://github.com/bensooter/URLchecker/blob/master/top-1000-websites.txt
// 
const DOMAIN_RE =  /((?:https?:\/\/)?(?:[a-zA-Z\d][A-Za-z\d\.-]*\.)+[a-zA-Z]{2,})/g

const ADDR_REGEX = new RegExp(IPV4ADDR_RE.source + '|' + IPV6ADDR_RE.source + '|' + DOMAIN_RE.source, 'g')

async function contentScriptMain() {
    console.time('alpaca');
    const url = document.location.href
    console.log("Alpaca|", "🖊️", "Highlighting", url)
    LAST_URL = url
    await highlight(ADDR_REGEX)
    console.timeEnd('alpaca');
}

/************
 * IP logic *
 ************/
type IPversion = 4 | 6
type IPAddrGroups = {
    ipGroupList: Uint32Array;
    ipType: IPversion;
} | null
const normalize_ipv6 = (ipv6: string) => {
    const MAX_IPV6_HEXTETS = 8;
    // Expand out :: to :0000: as many times as needed
    // There can be at most one ::
    if (ipv6.includes('::')) {
        const [ipv6Pre, ipv6Post] = ipv6.split('::');
        const ipv6_pre_hextets = ipv6Pre.split(':').filter(e => e).length;
        const ipv6_post_hextets = ipv6Post.split(':').filter(e => e).length;
        const omitted_zero_hextets = MAX_IPV6_HEXTETS - ipv6_pre_hextets - ipv6_post_hextets;
        let ary_zeroes = Array(omitted_zero_hextets).fill('0000').join(':')
        if (ipv6_pre_hextets !== 0)  // If not addr like ::1
            ary_zeroes = ":" + ary_zeroes
        if (ipv6_post_hextets !== 0)  // If not addr like fe80::
            ary_zeroes = ary_zeroes + ":"
        ipv6 = ipv6.replace('::',  ary_zeroes);
    }
    // Pad left 0s to every group
    const groups = ipv6.split(':')
    groups.map((g) => {g.padStart(4, '0')})
    ipv6 = groups.join(':')
    ipv6 = ipv6.replace('.', ':') // IPv4 address space
    return ipv6
}

// Parse an IP address into number groups, and match the mask to all groups
function parseIP(ipAddr2Parse: string[], radix: number, bitsPerGroup: number, maskSize: number, bitsPerAddress: number): Uint32Array {
    let ipGroupList = ipAddr2Parse.map((g) => parseInt(g, radix))
    let ipGroupIntList = new Uint32Array(ipGroupList)
    let ipNumAry = new Uint32Array(bitsPerAddress / 8)
    for (let i=0; i< ipGroupIntList.length; i++) {
        const ipGroupInt = ipGroupIntList[i];
        if (maskSize >= bitsPerGroup) 
            ipNumAry[i] = ipGroupInt;
        else if (maskSize > 0)
            ipNumAry[i] = ipGroupInt & -Math.pow(2, bitsPerGroup - maskSize);
        else 
            return ipNumAry;
        maskSize -= bitsPerGroup;
    }    
    return ipNumAry;
}

function getIPNumObj(ipAddr: string, maskSizeStr: string, IPver: IPversion): IPAddrGroups {
    // Not using existing IPv4 And IPv6 regexes because they don't have capture groups for the IP addr groups
    const maskSize = parseInt(maskSizeStr, 10)
    if (IPver === 4) {
        let ipv4 = ipAddr.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
        if (ipv4) {
            ipv4 = ipv4.splice(1,);
            return {ipGroupList: parseIP(ipv4, 10, 8, maskSize, 32), ipType: 4}
        }
    } else if (IPver === 6) {
        let ipv6 = ipAddr.match(new RegExp('^' + '([0-9a-f]+):'.repeat(7) + '([0-9a-f]+)$'));
        if (ipv6) {
            ipv6 = ipv6.splice(1,);
            return {ipGroupList: parseIP(ipv6, 16, 16, maskSize, 128), ipType: 6}
        }
    }
    return null
}

// Takes in a str looking like 1.2.3.4 or 1.2.3.4/28 and a str looking like 1.2.3.4/28
// This code is about ~2x faster for IPv6 than isInSubnet in https://github.com/beaugunderson/ip-address
/* Tests: 
    IsIpInSupernet("2001:db8::ff00:42:8329", "2001:db8:0:0:0:ff00:0:0/95") => true
    IsIpInSupernet("2001:db8::ff0f:42:8329", "2001:db8:0:0:0:ff00:0:0/95") => false
    IsIpInSupernet("2001:db8::ff00:42:8329/73", "2001:db8:0:0:0:ff00:0:0/95") => false
    IsIpInSupernet("192.168.4.0/25", "192.168.0.0/17") => true
    IsIpInSupernet("192.169.0.0/25", "192.168.0.0/17") => false
 */
function IsIpInSupernet(subnetIPStr: string, supernetIPStr: string): boolean {
    // Takes an IPv4 or IPv6 address or subnet and verifies whether it is in an IPv4 or IPv6 supernet.
    // If the subnet and supernet differ in IP type, this will return false.
    let [supernetIPAddr, supernetMaskStr] = supernetIPStr.split('/');
    let [subnetIPAddr, subnetMaskStr] = subnetIPStr.split('/');
    let IPversion: IPversion;
    if (subnetIPStr.includes('.') && supernetIPAddr.includes('.')) {
        IPversion = 4;
    } else if (subnetIPStr.includes(':') && supernetIPAddr.includes(':')) {
        subnetIPAddr = normalize_ipv6(subnetIPAddr);
        supernetIPAddr = normalize_ipv6(supernetIPAddr);
        IPversion = 6;
    } else {
        return false;
    }

    // If an IP address is provided without a subnet, assume it's a singleton /32 or /128
    const subnetAddrMask = parseInt(subnetMaskStr) || IPversion === 4 && 32 || IPversion === 6 && 128
    const superNetMaskBigger = parseInt(supernetMaskStr) <= subnetAddrMask
    const subnetIP = getIPNumObj(subnetIPAddr, supernetMaskStr, IPversion);
    const supernetIP = getIPNumObj(supernetIPAddr, supernetMaskStr, IPversion);
    if (!subnetIP || !supernetIP)
        return false;
    const subnetIPTypesMatch = subnetIP.ipType === supernetIP.ipType
    for (let i=0; i < supernetIP.ipGroupList.length; i++) // Verify that every IP group is the same
        if (subnetIP.ipGroupList[i] !== supernetIP.ipGroupList[i])
            return false
    return superNetMaskBigger && subnetIPTypesMatch;
}

/*******************
 * Highlight logic *
 *******************/

// https://developer.mozilla.org/en-US/docs/Web/API/Document/createTreeWalker
// https://stackoverflow.com/questions/31275446/how-to-wrap-part-of-a-text-in-a-node-with-javascript
async function highlight(regex: RegExp) {
    const acceptFn = (node: HTMLElement) => {
        if (node.textContent && node.textContent.match(regex)) {
            return NodeFilter.FILTER_ACCEPT;
        }
        return NodeFilter.FILTER_SKIP;
    }
    const treeWalker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_TEXT,
        { acceptNode: acceptFn},
    );
    let nodes = [];
    let text = '';
    let currentNode = treeWalker.nextNode();
        
    while (currentNode) {
        nodes.push({
            textNode: currentNode,
            start: text.length
        });
        text += currentNode.nodeValue
        currentNode = treeWalker.nextNode() as Node;
    }
    
    if (!nodes.length)
        return;

    let match;
    let spanNodes = [];
    while (match = regex.exec(text)) {
        const matchLength = match[0].length;
        
        // Prevent empty matches causing infinite loops        
        if (!matchLength)
        {
            regex.lastIndex++;
            continue;
        }
        
        for (var i = 0; i < nodes.length; ++i) {
            let node = nodes[i];
            const nodeLength = (node.textNode.nodeValue as string).length;
            
            // skip any links in svg, script, style tags
            const parentNode = node.textNode.parentNode;
            if (parentNode) {
                if (["svg", "script", "style"].includes(parentNode.nodeName.toLowerCase()))
                    continue;
            }
            // Skip nodes before the match
            if (node.start + nodeLength <= match.index)
                continue;
        
            // Break after the match
            if (node.start >= match.index + matchLength)
                break;
            
            // Split the start node if required
            if (node.start < match.index) {
                nodes.splice(i + 1, 0, {
                    textNode: (node.textNode as Text).splitText(match.index - node.start),
                    start: match.index
                });
                continue;
            }
            
            // Split the end node if required
            if (node.start + nodeLength > match.index + matchLength) {
                nodes.splice(i + 1, 0, {
                    textNode: (node.textNode as Text).splitText(match.index + matchLength - node.start),
                    start: match.index + matchLength
                });
            }

            const addr = node.textNode.textContent as string;

            // Only mark domains that match the PSL
            if (addr.match(DOMAIN_RE)) {
                if (!is_domain_valid(addr)) {
                    continue;
                }
            }
            
            // Highlight the current node
            // Highlight IPv4 and IPv6 immediately because no fetches are required
            const spanNode = document.createElement("span");
            spanNode.className = "alpaca_addr";
            mark_addr(spanNode, [addr], '');
            (node.textNode.parentNode as HTMLElement).replaceChild(spanNode, node.textNode);
            spanNode.appendChild(node.textNode);
            spanNodes.push(spanNode)
        }
    }
    // Domains should be checked async after IPs because they require fetch
    // Should fire async as fast as it can go
    // Hopefully no race conditions as nodes are separate
    for (let node of spanNodes) {
        if (node.textContent) {
            modify_page(node, node.textContent);
        }
    }
}

async function modify_page(spanNode: HTMLSpanElement, addr: string) {
    const domain_match = addr.match(DOMAIN_RE);
    if (domain_match) {
        const domain = domain_match[0];
        if (Object.keys(DNS_CACHE).includes(domain)) {  // DNS_CACHE isn't guaranteed to be used because everything is async
            console.log(`Alpaca| Got ${domain} from content script cache`)
            modify_addrs(spanNode, DNS_CACHE[domain], domain, null)
        } else {
            const response: dns_response = await new Promise((resolve) => {
                browser.runtime.sendMessage({requestName: "DNS_LOOKUP", domain: domain}, (response) => {
                    resolve(response)
                });
            });
            if (!response.error) {
                const ip_addrs = response.data
                DNS_CACHE[domain] = ip_addrs
                console.log(`Alpaca| Got ${domain} from background script cache`)
                modify_addrs(spanNode, ip_addrs, domain, response)
            } else {
                modify_addrs(spanNode, [], '', response)
            }
        }
    } 
}

function modify_addrs(spanNode: HTMLSpanElement, ip_addrs: string[], domain: string, response: dns_response | null) {
    if (response && (response.dns_code !== 0 || response.error.length > 0)) { // If no IP address was returned
        spanNode.classList.add('alpaca_nxdomain');
        spanNode.title = `DNS RCODE ${response.dns_code}\n${response.error}`;
        console.log(`Alpaca| ❌ ${domain} NXDOMAIN hostname not found`);
        return;
    }
    // Should work for both IPv4/6 addrs
    mark_addr(spanNode, ip_addrs, domain)
}

// Mark an IPv4 or IPv6 address
function mark_addr(spanNode: HTMLSpanElement, ip_addrs: string[], domain: string) {
    domain = domain || 'Domain unknown';
    let is_cf = false;
    let CF_IP_LIST;
    const first_ip_addr = ip_addrs[0]
    if (first_ip_addr.match(IPV4ADDR_RE)) {
        CF_IP_LIST = CF_IPV4_LIST
    }
    else if (first_ip_addr.match(IPV6ADDR_RE)) {
        CF_IP_LIST = CF_IPV6_LIST
    } else {
        return;
    }
    let cf_msg = `🟠 ${domain} proxied over Cloudflare\n`
    for (const ip_subnet of CF_IP_LIST) {
        for (const ip_addr of ip_addrs) {
            if (IsIpInSupernet(ip_addr, ip_subnet)) {
                cf_msg += `\n${ip_addr} in Cloudflare ${ip_subnet}`
                is_cf = true;
            }
        }
    }
    if (is_cf) {
        console.log(`Alpaca| 🟠 ${domain} [${ip_addrs}] in Cloudflare IP ranges`)
        spanNode.title = cf_msg
        spanNode.classList.add('alpaca_cloudflare')
    } else {
        console.log(`Alpaca| 🟣 ${domain} [${ip_addrs}] not in Cloudflare IP ranges`)
        spanNode.title = `🟣 ${domain} is not proxied over Cloudflare\n\n${ip_addrs.join('\n')}`
        spanNode.classList.add('alpaca_non_cloudflare')
    }
}

function is_domain_valid(domain: string) {
    let is_valid_domain = false
    for (const tld of PUBLIC_SUFFIX_LIST) {
        if (domain === tld) {
            return false
        }
        // Domain has to be `.tld` plus at least one domain character
        if (domain.endsWith('.' + tld) && domain.length > tld.length + 1) {
            is_valid_domain = true
        }
    }
    return is_valid_domain;
}
