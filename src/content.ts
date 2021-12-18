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

chrome.runtime.onMessage.addListener(
    function(request, _, sendResponse) {
        if (DEBUG)
            console.log("Alpaca|", "💬", "Received message from background script", request)
        if (!request.url && !request.event) {
            console.log("Alpaca|", "💬", "Problem parsing request. Expecting url, event:", request)
        }
        // If there's a new URL that hasn't been highlighted
        if (LAST_URL !== request.url) {
            highlight_ips()
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
// https://stackoverflow.com/a/5717133
// test against https://github.com/bensooter/URLchecker/blob/master/top-1000-websites.txt
const DOMAIN_RE = /(?:^|\s)((?:https?:\/\/)?(?:[a-zA-Z\d][A-Za-z\d\.-]*\.)+[a-zA-Z]{2,})/g  // domain name

const ADDR_REGEX = new RegExp(IPV4ADDR_RE.source + '|' + IPV6ADDR_RE.source + '|' + DOMAIN_RE.source, 'g')

async function contentScriptMain() {
    await highlight_ips()
}

// Takes in a str looking like 1.2.3.4 or 1.2.3.4/28 and a str looking like 1.2.3.4/28
function IsIpv4InCidr(subsetIPStr: string, CidrNotationStr: string) {
    function IPNumber(ipAddr: string, maskSizeStr: string): number {
        let ip = ipAddr.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
        if (ip) {
            const ipNum = (+ip[1]<<24) + (+ip[2]<<16) + (+ip[3]<<8) + (+ip[4]);
            const maskSize = parseInt(maskSizeStr, 10)
            const mask = -1<<(32-maskSize)
            return ipNum & mask
        }
        return 0
    }
    const [cidrIPStr, cidrMaskStr] = CidrNotationStr.split('/');
    let [IPAddrStr, IPAddrMaskStr] = subsetIPStr.split('/');
    IPAddrMaskStr = IPAddrMaskStr || cidrMaskStr // If only an IP address is provided, assume the cidr net's mask
    return IPNumber(IPAddrStr, IPAddrMaskStr) === IPNumber(cidrIPStr, cidrMaskStr) && cidrMaskStr <= IPAddrMaskStr
}

function IsIpv6InCidr(subsetIPStr: string, CidrNotationStr: string) {
    // Very bad 
    return subsetIPStr.substr(0,8) === CidrNotationStr.substr(0,8)
}

async function highlight_ips() {
    // Hardcoding these so I don't have to use a background script to get them
    // I stole this function from here: http://is.gd/mwZp7E (cloud-to-butt extension)
    const url = document.location.href
    console.log("Alpaca|", "🖊️", "Rehighlighting", url)
    LAST_URL = url
    // For text documents. Asked on SO about this: https://stackoverflow.com/questions/70358848
    if (document.contentType === 'text/html') {
        const acceptFn = (node: HTMLElement) => {
            if (node.nodeType === Node.TEXT_NODE && node.textContent && node.textContent.match(ADDR_REGEX)) {
                return NodeFilter.FILTER_ACCEPT;
            }
            return NodeFilter.FILTER_SKIP;
        }
        const treeWalker = document.createTreeWalker(
            document.body,
            NodeFilter.SHOW_TEXT,
            { acceptNode: acceptFn},
        );
        let nodeList = [];
        let currentNode = treeWalker.currentNode;
        while(currentNode) {
            nodeList.push(currentNode);
            currentNode = treeWalker.nextNode() as Node;
        }
        nodeList.splice(0,1) // body is first element
        for (let node of nodeList) {
            if (!node.textContent) continue; // No point in replacing empty content
            if (node.textContent.includes('alpaca_addr')) {
                console.error("This should never happen (TM). Erroring to avoid recursion")
            }
            let parentNode = node.parentElement as HTMLElement;
            const isHidden = window.getComputedStyle(parentNode).display === 'none';
            const p_tagname = parentNode.tagName.toLowerCase();
            let maybeAddr = node.nodeValue || '';
            if(!p_tagname.includes("script") && p_tagname != 'svg' && p_tagname != 'textarea' && !isHidden) {
                modify_page(maybeAddr, parentNode)
            }
        }
    
    } else if (document.contentType === 'text/plain' || document.contentType === 'application/json') {
        // If it's a text document
        const parentNode = document.body.children[0] as HTMLElement
        await modify_page(document.body.textContent as string, parentNode)    
    }
}

// https://developer.mozilla.org/en-US/docs/Web/API/Document/createTreeWalker


async function modify_page(maybeAddr: string, parentNode: HTMLElement) {
    const addr_matches = [... maybeAddr.matchAll(ADDR_REGEX)]
    let addrs_in_page: string[] = []
    for (const addr_match of addr_matches) {
        // Matches IPV4ADDR_RE || IPV6ADDR_RE || DOMAIN_RE
        const addr_match_str = addr_match[1] || addr_match[2] || addr_match[3]
        if (!addrs_in_page.includes(addr_match_str)) {
            addrs_in_page.push(addr_match_str)
        }
    }
    for (const addr_match_str of addrs_in_page) {
        const domain_matches = [... addr_match_str.matchAll(DOMAIN_RE)]
        if (domain_matches.length > 0) {
            const domain = domain_matches[0][1];
            if (Object.keys(DNS_CACHE).includes(domain)) {  // DNS_CACHE isn't guaranteed to be used because everything is async
                modify_addrs(DNS_CACHE[domain], domain, parentNode, NO_ERR)
            } else {
                const response: {data: string[], error: string} = await new Promise((resolve) => {
                    browser.runtime.sendMessage({requestName: "DNS_LOOKUP", domain: domain}, (response) => {
                        resolve(response)
                    });
                });
                if (!response.error) {
                    const ip_addrs = response.data
                    DNS_CACHE[domain] = ip_addrs
                    modify_addrs(ip_addrs, domain, parentNode, '')
                }
            }
        } else {
            modify_addrs([maybeAddr], '', parentNode, NO_ERR)
        }
    }
}

function modify_addrs(ip_addrs: string[], domain: string, parentNode: HTMLElement, errMsg: string) {
    if (errMsg.length > 0 || ip_addrs.length === 0) { // If no IP address was returned
        const domainRe = new RegExp('(?:^|\\s)(' + domain + ')', 'g')
        const nxdomainSpan = `<span class="alpaca_nxdomain alpaca_addr" id="alpaca_${domain}" title="NXDOMAIN:${domain} not found">${domain}</span>`
        parentNode.innerHTML = parentNode.innerHTML.replace(domainRe, nxdomainSpan)
        console.log("Alpaca|", "❌", domain || '?', ip_addrs, "NXDOMAIN hostname not found")
        return;
    }
    const v4_match = ip_addrs[0].match(IPV4ADDR_RE) || [];
    const v6_match = ip_addrs[0].match(IPV6ADDR_RE) || [];
    let addr_replaced = false;
    let match = ''
    if (domain) {
        match = domain
    } else if (v4_match.length > 0) {
        match = v4_match[0]
    } else if (v6_match.length > 0) {
        match = v6_match[0]
    }
    let matchRe = new RegExp(match, 'g')
    for (const v4_addr of v4_match) {
        let last_addr_replaced = highlight_IP(parentNode, v4_addr, ip_addrs, CF_IPV4_LIST, matchRe, match, IsIpv4InCidr);
        addr_replaced = last_addr_replaced || addr_replaced
        if (!last_addr_replaced) {
            replaceNonCF(parentNode, v4_addr, ip_addrs, domain, matchRe, match)
        }
    }
    for (const v6_addr of v6_match) {
        let last_addr_replaced = highlight_IP(parentNode, v6_addr, ip_addrs, CF_IPV6_LIST, matchRe, match, IsIpv6InCidr);
        addr_replaced = last_addr_replaced || addr_replaced
        if (!last_addr_replaced) {
            replaceNonCF(parentNode, v6_addr, ip_addrs, domain, matchRe, match)
        }
    }
    const domain_str = domain || (v4_match && v4_match[0]) || (v6_match && v6_match[0]) || '?'
    if (addr_replaced)
        console.log("Alpaca|", "🟠", domain_str, ip_addrs, "in Cloudflare")
}

function highlight_IP(parentNode: HTMLElement, ip_addr: string, ip_addrs: string[], CF_IPlist: string[], matchRe: RegExp, match: string, ipSubnetFunc: any): boolean {
    for (const ip_subnet of CF_IPlist) {
        if (ipSubnetFunc(ip_addr, ip_subnet)) {
            const spanData = `id="alpaca_${ip_addr}" title="${ip_addr} in CF ${ip_subnet}.\nAll: ${ip_addrs}">${match}`;
            const spanStr = `<span class="alpaca_cloudflare alpaca_addr"${spanData}</span>`
            parentNode.innerHTML = parentNode.innerHTML.replace(matchRe,  spanStr);
            return true;
        }
    }
    return false;
}

function replaceNonCF(parentNode: HTMLElement, domain_str: string, ip_addrs: string[], domain: string, matchRe: RegExp, match: string) {
    // domain / IP address gets a white-grey background, so we know this extension is working
    console.log("Alpaca|", "🟣", domain_str, ip_addrs, "not in Cloudflare")
    parentNode.innerHTML = parentNode.innerHTML.replace(matchRe, `<span class="alpaca_non_cloudflare alpaca_addr" id="alpaca_${domain}" title="${ip_addrs}\nNot proxied over Cloudflare">${match}</span>`);
}
