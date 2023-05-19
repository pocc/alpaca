import { dns_response } from '../index';
// Alpaca Content Script
const browser = chrome
const DEBUG = true
let DNS_CACHE: {[url: string]: string[]} = {}  // Having a DNS_CACHE on an ephemeral page sholud be fine
let LAST_URL = ""

console.log("Alpaca|", "🎬"," Content script loaded on", document.location.href)
window.addEventListener('load', contentScriptMain);

let CF_IPV4_LIST: string[] = []
let CF_IPV6_LIST: string[] = []
let PUBLIC_SUFFIX_LIST: string[] = []
// This could cause significant network traffic, so it should be user configurable
let GET_STATUS_CODES_FOR_ALL_URLS = false
chrome.runtime.sendMessage({requestName: "CF_IPV4_LIST"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received from service_worker script, asked for IPv4", response.data)
    CF_IPV4_LIST = response.data
});
chrome.runtime.sendMessage({requestName: "CF_IPV6_LIST"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received from service_worker script, asked for IPv6", response.data)
    CF_IPV6_LIST = response.data
});
chrome.runtime.sendMessage({requestName: "PUBLIC_SUFFIX_LIST"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received from service_worker script, asked for Public Suffix List", response.data)
    PUBLIC_SUFFIX_LIST = response.data
});


chrome.runtime.onMessage.addListener(
    function(request, _, sendResponse) {
        if (DEBUG)
            console.log("Alpaca|", "💬", "Received message from service_worker script", request)
        if (!request.url && !request.event) {
            console.log("Alpaca|", "💬", "Problem parsing request. Expecting url, event:", request)
        }
        const last_url = new URL(LAST_URL)
        const req_url = new URL(request.url)
        // If there's a new URL that hasn't been highlighted
        if (last_url.origin !== req_url.origin || last_url.pathname !== req_url.pathname) {
            LAST_URL = request.url
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

/* Generated with this clientside javascript on https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
 * let tbody = document.querySelector('#table-uri-schemes-1 > tbody')
 * let regex = '/(?:' + [...tbody.rows].map(i=>i.cells[0].textContent).join('|') + ')?/'
 */
const SCHEME_RE = /(?:(?:aaa|aaas|about|acap|acct|acd|acr|adiumxtra|adt|afp|afs|aim|amss|android|appdata|apt|ar|ark|attachment|aw|barion|bb|beshare|bitcoin|bitcoincash|blob|bolo|browserext|cabal|calculator|callto|cap|cast|casts|chrome|chrome-extension|cid|coap|coap+tcp|coap+ws|coaps|coaps+tcp|coaps+ws|com-eventbrite-attendee|content|content-type|crid|cstr|cvs|dab|dat|data|dav|dhttp|diaspora|dict|did|dis|dlna-playcontainer|dlna-playsingle|dns|dntp|doi|dpp|drm|drop|dtmi|dtn|dvb|dvx|dweb|ed2k|eid|elsi|embedded|ens|ethereum|example|facetime|fax|feed|feedready|fido|file|filesystem|finger|first-run-pen-experience|fish|fm|ftp|fuchsia-pkg|geo|gg|git|gitoid|gizmoproject|go|gopher|graph|grd|gtalk|h323|ham|hcap|hcp|http|https|hxxp|hxxps|hydrazone|hyper|iax|icap|icon|im|imap|info|iotdisco|ipfs|ipn|ipns|ipp|ipps|irc|irc6|ircs|iris|iris.beep|iris.lwz|iris.xpc|iris.xpcs|isostore|itms|jabber|jar|jms|keyparc|lastfm|lbry|ldap|ldaps|leaptofrogans|lorawan|lpa|lvlt|magnet|mailserver|mailto|maps|market|matrix|message|microsoft.windows.camera|microsoft.windows.camera.multipicker|microsoft.windows.camera.picker|mid|mms|modem|mongodb|moz|ms-access|ms-appinstaller|ms-browser-extension|ms-calculator|ms-drive-to|ms-enrollment|ms-excel|ms-eyecontrolspeech|ms-gamebarservices|ms-gamingoverlay|ms-getoffice|ms-help|ms-infopath|ms-inputapp|ms-lockscreencomponent-config|ms-media-stream-id|ms-meetnow|ms-mixedrealitycapture|ms-mobileplans|ms-newsandinterests|ms-officeapp|ms-people|ms-project|ms-powerpoint|ms-publisher|ms-remotedesktop-launch|ms-restoretabcompanion|ms-screenclip|ms-screensketch|ms-search|ms-search-repair|ms-secondary-screen-controller|ms-secondary-screen-setup|ms-settings|ms-settings-airplanemode|ms-settings-bluetooth|ms-settings-camera|ms-settings-cellular|ms-settings-cloudstorage|ms-settings-connectabledevices|ms-settings-displays-topology|ms-settings-emailandaccounts|ms-settings-language|ms-settings-location|ms-settings-lock|ms-settings-nfctransactions|ms-settings-notifications|ms-settings-power|ms-settings-privacy|ms-settings-proximity|ms-settings-screenrotation|ms-settings-wifi|ms-settings-workplace|ms-spd|ms-stickers|ms-sttoverlay|ms-transit-to|ms-useractivityset|ms-virtualtouchpad|ms-visio|ms-walk-to|ms-whiteboard|ms-whiteboard-cmd|ms-word|msnim|msrp|msrps|mss|mt|mtqp|mumble|mupdate|mvn|news|nfs|ni|nih|nntp|notes|num|ocf|oid|onenote|onenote-cmd|opaquelocktoken|openpgp4fpr|otpauth|p1|pack|palm|paparazzi|payment|payto|pkcs11|platform|pop|pres|prospero|proxy|pwid|psyc|pttp|qb|query|quic-transport|redis|rediss|reload|res|resource|rmi|rsync|rtmfp|rtmp|rtsp|rtsps|rtspu|sarif|secondlife|secret-token|service|session|sftp|sgn|shc|shttp (OBSOLETE)|sieve|simpleledger|simplex|sip|sips|skype|smb|smp|sms|smtp|snews|snmp|soap.beep|soap.beeps|soldat|spiffe|spotify|ssb|ssh|starknet|steam|stun|stuns|submit|svn|swh|swid|swidpath|tag|taler|teamspeak|tel|teliaeid|telnet|tftp|things|thismessage|tip|tn3270|tool|turn|turns|tv|udp|unreal|upt|urn|ut2004|uuid-in-package|v-event|vemmi|ventrilo|ves|videotex|vnc|view-source|vscode|vscode-insiders|vsls|w3|wais|web3|wcr|webcal|web+ap|wifi|wpid|ws|wss|wtai|wyciwyg|xcon|xcon-userid|xfire|xmlrpc.beep|xmlrpc.beeps|xmpp|xri|ymsgr|z39.50|z39.50r|z39.50s):\/\/)?/
// faster
// const SCHEME_RE = /(?:[0-9a-z.-]+)?/ 
const HOST_RE =  /(?:[a-zA-Z0-9][A-Za-z0-9\.-]*\.)+[a-zA-Z]{2,}\.?/
const PORT_RE = /(?::\d{1,5})?/
// Not including valid characters () because [link text](link url) is common and makes this trickier 
const URL_PATH_RE = /\/[a-zA-Z0-9._~!$&#?%*+,;=:@\/-]*/
const DOMAIN_RE = new RegExp(SCHEME_RE.source + HOST_RE.source + PORT_RE.source + '(?:' + URL_PATH_RE.source + ')?', 'g')
const DOMAIN_WITH_PATH_RE = new RegExp(SCHEME_RE.source + HOST_RE.source + PORT_RE.source + URL_PATH_RE.source, 'g')

const ADDR_REGEX = new RegExp(IPV4ADDR_RE.source + '|' + IPV6ADDR_RE.source + '|' + DOMAIN_RE.source, 'g')

async function contentScriptMain() {
    console.time('alpaca');
    const url = document.location.href
    console.log("Alpaca|", "🖊️", "Highlighting", url)
    LAST_URL = url
    if (document.contentType.startsWith('text/json') || document.contentType === 'application/json') {
        await highlight_text(ADDR_REGEX) // this algo is faster on text
    } else { // sholud be contentType === 'text/html'
        await highlight(ADDR_REGEX)
    }
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
            let ipv4Ary = ipv4.splice(1,);
            return {ipGroupList: parseIP(ipv4Ary, 10, 8, maskSize, 32), ipType: 4}
        }
    } else if (IPver === 6) {
        let ipv6 = ipAddr.match(new RegExp('^' + '([0-9a-f]+):'.repeat(7) + '([0-9a-f]+)$'));
        if (ipv6) {
            let ipv6Ary = ipv6.splice(1,);
            return {ipGroupList: parseIP(ipv6Ary, 16, 16, maskSize, 128), ipType: 6}
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
async function highlight(regex: RegExp) {
    const acceptFn = (node: HTMLElement) => {
        // Taken from JQuery via https://stackoverflow.com/a/26915468
        const isHidden = node.style && node.style.display === 'none' || !node.ownerDocument.contains(node)
        if (node.textContent && node.textContent.match(regex) && !isHidden) {
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
    let currentNode = treeWalker.nextNode();
        
    while (currentNode) {
        nodes.push(currentNode);
        currentNode = treeWalker.nextNode() as Node;
    }
    
    let spanNodes: HTMLSpanElement[] = [];
    if (!nodes.length)
        return;

    for (var i = 0; i < nodes.length; ++i) {
        let node = nodes[i];
        let text = node.textContent
        if (!text)
            continue;

        // skip any links in svg, script, style tags
        const parentNode = node.parentNode;
        if (parentNode) {
            if (["svg", "script", "style", "noscript"].includes(parentNode.nodeName.toLowerCase()))
                continue;
            // Don't recurse on self
            if ((parentNode as HTMLElement).classList.value.includes('alpaca_addr')) {
                continue;
            }
        }
        if ((node.textContent as string).includes('alpaca_addr')) {
            continue;
        }

        let matches = [... text.matchAll(ADDR_REGEX)]
        let offset = 0;
        for (let match of matches) {
            let index = (match.index || 0) - offset;
            // Only mark domains that match the PSL
            let host_match = match[0].match(HOST_RE)
            if (host_match) {
                if (!is_domain_valid(host_match[0])) {
                    continue;
                }
            }
            // Executive decision that IPv6 addresses less than 6 characters like :: and ::1 aren't interesting 
            if (match[0].match(IPV6ADDR_RE) && match[0].length < 6) {
                continue;
            }
            let range = document.createRange();
            range.setStart(node, index);
            range.setEnd(node, index + match[0].length);
            
            let spanNode = document.createElement("span");
            spanNode.className = "alpaca_addr";
            spanNode.appendChild(range.extractContents());
            range.insertNode(spanNode);
            if (!spanNode.nextSibling)
                continue;
            node = spanNode.nextSibling;
            offset += index + match[0].length;
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

// https://stackoverflow.com/questions/31275446/how-to-wrap-part-of-a-text-in-a-node-with-javascript
// This algorithm is better at highlighting large blocks of text
// Unexpected reasons a link is broken up into multiple nodes (and why this is necessary):
//   * Other software has highlighted the domain and path, but not schema.
//   * When searching, the system may bold the keyword in the middle of a URL.
async function highlight_text(regex: RegExp) {
    const acceptFn = (node: HTMLElement) => {
        // Taken from JQuery via https://stackoverflow.com/a/26915468
        const isHidden = node.style.display.toLowerCase() === 'none' || !node.ownerDocument.contains(node)
        if (node.textContent && node.textContent.match(regex) && !isHidden) {
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
            let host_addr = addr.match(HOST_RE) 
            if (host_addr) {
                if (!is_domain_valid(host_addr[0])) {
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

// This function exists so that you can see the response code of the URL
// It's possible to return more, but let's start with status code
async function fetch_url(url: string) {
    const response: {status_code: number, error: string} = await new Promise((resolve) => {
        browser.runtime.sendMessage({requestName: "URL_FETCH", url: url}, (response) => {
            resolve(response)
        });
    });
    return response.status_code;
}

async function modify_page(spanNode: HTMLSpanElement, addr: string) {
    const domain_match = addr.match(HOST_RE);
    if (domain_match) {
        const domain = domain_match[0];
        if (Object.keys(DNS_CACHE).includes(domain)) {  // DNS_CACHE isn't guaranteed to be used because everything is async
            console.log(`Alpaca| Got ${domain} from content script cache`)
            await modify_addrs(spanNode, DNS_CACHE[domain], domain, null)
        } else {
            const response: dns_response = await new Promise((resolve) => {
                browser.runtime.sendMessage({requestName: "DNS_LOOKUP", domain: domain}, (response) => {
                    resolve(response)
                });
            });
            if (response?.data && !response?.error) {
                const ip_addrs = response.data
                DNS_CACHE[domain] = ip_addrs
                console.log(`Alpaca| Got ${domain} from service_worker script cache`)
                await modify_addrs(spanNode, ip_addrs, domain, response)
            } else {
                await modify_addrs(spanNode, [], addr, response)
            }
            // Don't check HTTP status code if there was a DNS error
            if (response.dns_code !== 0 && GET_STATUS_CODES_FOR_ALL_URLS && addr.match(DOMAIN_WITH_PATH_RE)) {
                const status_code = await fetch_url(addr)
                const statusCode = '[' + status_code.toString() + '] '
                spanNode.insertAdjacentText('afterbegin', statusCode)
            }
        }
    } else {
        await modify_addrs(spanNode, [addr], '', null)
    }
}

async function modify_addrs(spanNode: HTMLSpanElement, ip_addrs: string[], domain: string, response: dns_response | null) {
    if (response && (response.dns_code !== 0 || response.error.length > 0)) { // If no IP address was returned
        spanNode.classList.add('alpaca_nxdomain');
        spanNode.title = `DNS RCODE ${response.dns_code}\n${response.error}`;
        console.log(`Alpaca| ❌ ${domain} NXDOMAIN hostname not found`);
        return;
    }
    // Should work for both IPv4/6 addrs
    await mark_addr(spanNode, ip_addrs, domain)
}

// Mark an IPv4 or IPv6 address
async function mark_addr(spanNode: HTMLSpanElement, ip_addrs: string[], domain: string) {
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
    let cf_msg = `🟠 proxied over Cloudflare\n${domain}\n `
    for (const ip_subnet of CF_IP_LIST) {
        for (const ip_addr of ip_addrs) {
            if (IsIpInSupernet(ip_addr, ip_subnet)) {
                cf_msg += `\n${ip_addr} in Cloudflare ${ip_subnet}`
                is_cf = true;
            }
        }
    }
    /*
    let ipData = [];
    for (let ip of ip_addrs) {
        let resp = await fetch(`https://rdap.arin.net/registry/ip/${ip}`);
        let ipDatum = await resp.json();
        ipData.push(ipDatum);
    }*/
    if (is_cf) {
        console.log(`Alpaca| 🟠 ${domain} [${ip_addrs}] in Cloudflare IP ranges`)
        spanNode.title = cf_msg
        spanNode.classList.add('alpaca_cloudflare')
    } else {
        console.log(`Alpaca| 🟣 ${domain} [${ip_addrs}] not in Cloudflare IP ranges`)
        spanNode.title = `🟣 not proxied over Cloudflare\n${domain}\n\n${ip_addrs.join('\n')}`
        spanNode.classList.add('alpaca_non_cloudflare')
    }
}

function is_domain_valid(domain: string) {
    if (domain.endsWith('.')) { // root doesn't need to be in domain
        domain = domain.slice(0, -1)
    }
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
