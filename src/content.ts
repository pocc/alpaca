import { dns_response, cymru_asn } from '../index';
// Alpaca Content Script
const browser = chrome
const DEBUG = true
let IPS: any = {};
let DNS_CACHE: {[url: string]: string[]} = {}  // Having a DNS_CACHE on an ephemeral page sholud be fine
let LAST_URL = ""
let ADDR_CACHE: any = {}; // general data for every address

console.log("Alpaca|", "🎬"," Content script loaded on", document.location.href)
window.addEventListener('load', contentScriptMain);
let PUBLIC_SUFFIX_LIST: string[] = []
// This could cause significant network traffic, so it should be user configurable
let GET_STATUS_CODES_FOR_ALL_URLS = false
browser.runtime.sendMessage({requestName: "IPS"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received IPS from service_worker script, asked for IPS", response.data)
    IPS = response.data
});
browser.runtime.sendMessage({requestName: "PUBLIC_SUFFIX_LIST"}, function(response) {
    if (DEBUG)
        console.log("Alpaca|", "💬", "Received from service_worker script, asked for Public Suffix List", response.data)
    PUBLIC_SUFFIX_LIST = response.data
});

// https://www.w3schools.com/howto/howto_css_modals.asp
document.body.insertAdjacentHTML('beforeend', 
`<div id="myModal" class="alpaca_modal">
    <div class="alpaca_modal-content">
        <div class="alpaca_modal-header">
            <span class="alpaca_close">&times;</span>
        <h2 id=alpaca_modal_title></h2>
    </div>
    <div class="alpaca_modal-body">
    </div>
</div>`);

browser.runtime.onMessage.addListener(
    function(request, _, sendResponse) {
        if (DEBUG)
            console.log("Alpaca|", "💬", "Received message from service_worker script", request)
        if (request.context = 'contextMenu') {
            contextMenuRedirect(request.selectionText);
        } else {
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
        }
        return true;
    }
);

// Taken from https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
const IPV4ADDR_RE  = /(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\/?\d{0,2}/g
const IPV6ADDR_RE = /[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,6}::?[0-9a-fA-F]{0,4}(?:\/?\d{1,3})?/g
const IP_RE = new RegExp(IPV4ADDR_RE.source + '|' + IPV6ADDR_RE.source, 'g')
// https://stackoverflow.com/questions/10306690/what-is-a-regular-expression-which-will-match-a-valid-domain-name-without-a-subd
// test against https://github.com/bensooter/URLchecker/blob/master/top-1000-websites.txt

/* Generated with this clientside javascript on https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
 * let tbody = document.querySelector('#table-uri-schemes-1 > tbody')
 * let regex = '/(?:' + [...tbody.rows].map(i=>i.cells[0].textContent).join('|') + ')?/'
 */
const SCHEME_RE = /(?:(?:aaa|aaas|about|acap|acct|acd|acr|adiumxtra|adt|afp|afs|aim|amss|android|appdata|apt|ar|ark|attachment|aw|barion|bb|beshare|bitcoin|bitcoincash|blob|bolo|browserext|cabal|calculator|callto|cap|cast|casts|chrome|chrome-extension|cid|coap|coap+tcp|coap+ws|coaps|coaps+tcp|coaps+ws|com-eventbrite-attendee|content|content-type|crid|cstr|cvs|dab|dat|data|dav|dhttp|diaspora|dict|did|dis|dlna-playcontainer|dlna-playsingle|dns|dntp|doi|dpp|drm|drop|dtmi|dtn|dvb|dvx|dweb|ed2k|eid|elsi|embedded|ens|ethereum|example|facetime|fax|feed|feedready|fido|file|filesystem|finger|first-run-pen-experience|fish|fm|ftp|fuchsia-pkg|geo|gg|git|gitoid|gizmoproject|go|gopher|graph|grd|gtalk|h323|ham|hcap|hcp|http|https|hxxp|hxxps|hydrazone|hyper|iax|icap|icon|im|imap|info|iotdisco|ipfs|ipn|ipns|ipp|ipps|irc|irc6|ircs|iris|iris.beep|iris.lwz|iris.xpc|iris.xpcs|isostore|itms|jabber|jar|jms|keyparc|lastfm|lbry|ldap|ldaps|leaptofrogans|lorawan|lpa|lvlt|magnet|mailserver|mailto|maps|market|matrix|message|microsoft.windows.camera|microsoft.windows.camera.multipicker|microsoft.windows.camera.picker|mid|mms|modem|mongodb|moz|ms-access|ms-appinstaller|ms-browser-extension|ms-calculator|ms-drive-to|ms-enrollment|ms-excel|ms-eyecontrolspeech|ms-gamebarservices|ms-gamingoverlay|ms-getoffice|ms-help|ms-infopath|ms-inputapp|ms-lockscreencomponent-config|ms-media-stream-id|ms-meetnow|ms-mixedrealitycapture|ms-mobileplans|ms-newsandinterests|ms-officeapp|ms-people|ms-project|ms-powerpoint|ms-publisher|ms-remotedesktop-launch|ms-restoretabcompanion|ms-screenclip|ms-screensketch|ms-search|ms-search-repair|ms-secondary-screen-controller|ms-secondary-screen-setup|ms-settings|ms-settings-airplanemode|ms-settings-bluetooth|ms-settings-camera|ms-settings-cellular|ms-settings-cloudstorage|ms-settings-connectabledevices|ms-settings-displays-topology|ms-settings-emailandaccounts|ms-settings-language|ms-settings-location|ms-settings-lock|ms-settings-nfctransactions|ms-settings-notifications|ms-settings-power|ms-settings-privacy|ms-settings-proximity|ms-settings-screenrotation|ms-settings-wifi|ms-settings-workplace|ms-spd|ms-stickers|ms-sttoverlay|ms-transit-to|ms-useractivityset|ms-virtualtouchpad|ms-visio|ms-walk-to|ms-whiteboard|ms-whiteboard-cmd|ms-word|msnim|msrp|msrps|mss|mt|mtqp|mumble|mupdate|mvn|news|nfs|ni|nih|nntp|notes|num|ocf|oid|onenote|onenote-cmd|opaquelocktoken|openpgp4fpr|otpauth|p1|pack|palm|paparazzi|payment|payto|pkcs11|platform|pop|pres|prospero|proxy|pwid|psyc|pttp|qb|query|quic-transport|redis|rediss|reload|res|resource|rmi|rsync|rtmfp|rtmp|rtsp|rtsps|rtspu|sarif|secondlife|secret-token|service|session|sftp|sgn|shc|shttp (OBSOLETE)|sieve|simpleledger|simplex|sip|sips|skype|smb|smp|sms|smtp|snews|snmp|soap.beep|soap.beeps|soldat|spiffe|spotify|ssb|ssh|starknet|steam|stun|stuns|submit|svn|swh|swid|swidpath|tag|taler|teamspeak|tel|teliaeid|telnet|tftp|things|thismessage|tip|tn3270|tool|turn|turns|tv|udp|unreal|upt|urn|ut2004|uuid-in-package|v-event|vemmi|ventrilo|ves|videotex|vnc|view-source|vscode|vscode-insiders|vsls|w3|wais|web3|wcr|webcal|web+ap|wifi|wpid|ws|wss|wtai|wyciwyg|xcon|xcon-userid|xfire|xmlrpc.beep|xmlrpc.beeps|xmpp|xri|ymsgr|z39.50|z39.50r|z39.50s):\/\/)?/
// faster
// const SCHEME_RE = /(?:[0-9a-z.-]+)?/ 
const HOST_RE =  /(?:[a-zA-Z0-9][A-Za-z0-9-]*\.)+[a-zA-Z]{2,}\.?/
const PORT_RE = /(?::\d{1,5})?/
// Not including valid characters () because [link text](link url) is common and makes this trickier 
const URL_PATH_RE = /\/[a-zA-Z0-9._~!$&#?%*+,;=:@\/-]*/
const DOMAIN_RE = new RegExp(SCHEME_RE.source + HOST_RE.source + PORT_RE.source + '(?:' + URL_PATH_RE.source + ')?', 'g')
const DOMAIN_WITH_PATH_RE = new RegExp(SCHEME_RE.source + HOST_RE.source + PORT_RE.source + URL_PATH_RE.source, 'g')

const ADDR_REGEX = new RegExp(IP_RE.source + '|' + DOMAIN_RE.source, 'g')


function contextMenuRedirect(selectionText: string) {
    let addr = selectionText || 'no text selected';
    addr = addr.trim();
    let ipMatch = addr.match(IP_RE)
    if (ipMatch) {
        let ip = ipMatch[0];
        window.open(`https://bgp.he.net/ip/${ip}#_ipinfo`, '_blank');
        return;
    }
    let hostMatch = addr.match(HOST_RE)
    if (hostMatch) {
        let host = hostMatch[0];
        window.open(`https://bgp.he.net/dns/${host}`, '_blank');
        return;
    }
    // If it's > 20 chars, add ... to signify that it's longer
    let addrWithEllipses = addr.slice(0,20) + (addr.length>20 ? '...' : '')
    alert(`Alpaca: Selected text "${addrWithEllipses}" does not match the hostname or IP regexes.`)
}

/*
// Attempt to reapply highlighting after page load.

let observer = new MutationObserver(async mutations => {
    for(let mutation of mutations) {
        let nodes = mutation.addedNodes as any;
        if (nodes.length > 0) {
            // mirror filtering logic in treeWalker
            nodes = [...nodes].filter((node:any)=>{
                const isHidden = node.style && node.style.display === 'none' || !node.ownerDocument.contains(node)
                return node.textContent && node.textContent.match(ADDR_REGEX) && !isHidden
            })
            highlight(nodes).then((spanNodes:any) => modifyNodes(spanNodes));
        }
     }
 });
 observer.observe(document, { childList: true, subtree: true });
 */

async function contentScriptMain() {
    console.time('alpaca');
    const url = document.location.href
    console.log("Alpaca|", "🖊️", "Highlighting", url)
    LAST_URL = url
    let highlighter;
    if (document.contentType.startsWith('text/json') || document.contentType === 'application/json') {
        highlighter = highlight_text(ADDR_REGEX) // this algo is faster on text
    } else { // sholud be contentType === 'text/html'
        let candidateNodes = await walkNodes(ADDR_REGEX);
        highlighter = highlight(candidateNodes)
    }
    highlighter.then((spanNodes:any) => modifyNodes(spanNodes));
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

// basic validator to avoid slow regexes
function isValidIPv4(ip: string): boolean {
    let octets: Array<string> = ip.split('.');
    if (octets.length !== 4) return false
    for (let i=0; i < octets.length; ++i) {
        let octet = octets[i];
        if (octet.length > 3) return false;
        if (octet.length === 3) {
            if (octet.charCodeAt(0) < 49 || octet.charCodeAt(0) > 50) return false;
            octet = octet.slice(1,)
        }
        if (octet.charCodeAt(0) < 48 || octet.charCodeAt(0) > 57 || octet.charCodeAt(1) < 48 || octet.charCodeAt(1) > 57) return false;
    }
    return true;
}

// basic validator to avoid slow regexes
function isValidIPv6(ip: string): boolean {
    for (let i=0; i<ip.length; ++i) {
        // If outside of chars '0123456789:' => not IPv6
        if (ip.charCodeAt(i) < 48 || ip.charCodeAt(i) > 58) return false;
    }
    return true;
}

function getIPNumObj(ipAddr: string, maskSizeStr: string, IPver: IPversion): IPAddrGroups {
    // Not using existing IPv4 And IPv6 regexes because they don't have capture groups for the IP addr groups
    const maskSize = parseInt(maskSizeStr, 10)
    if (IPver === 4) {
        if (isValidIPv4(ipAddr)) {
            let ipv4Ary = ipAddr.split('.');
            return {ipGroupList: parseIP(ipv4Ary, 10, 8, maskSize, 32), ipType: 4}
        }
    } else if (IPver === 6) {
        if (isValidIPv6(ipAddr)) {
            let ipv6Ary = ipAddr.split(':');
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
async function walkNodes(regex: RegExp) {
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
    return nodes;
}

async function highlight(nodes: any) {
    let avoidNodeNames = ["svg", "script", "style", "noscript", "pre", "code"];

    let spanNodes: HTMLSpanElement[] = [];
    if (!nodes.length)
        return;

    for (var i = 0; i < nodes.length; ++i) {
        let node = nodes[i];
        let text: any = node.textContent
        if (!text)
            continue;
        // skip any links in svg, script, style tags
        if (avoidNodeNames.includes(node.nodeName.toLowerCase()))
            continue;
        if ((node as HTMLElement)?.classList?.value?.includes('alpaca_addr')) {
            continue;
        }
        // Don't recurse on self
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
            let matchStr = match[0]
            // Executive decision that IPv6 addresses less than 6 characters like :: and ::1 aren't interesting
            if (matchStr.match(IPV6ADDR_RE) && matchStr.length < 6) {
                continue;
            }
            let range = document.createRange();
            range.setStart(node, index);
            range.setEnd(node, index + matchStr.length);

            let spanNode = document.createElement("button");
            spanNode.className = "alpaca_addr";
            spanNode.id = `alpaca_${host_match}_${i}-${matches.indexOf(match)}`; // Add number to the end to make it unique
            spanNode.appendChild(range.extractContents());
            range.insertNode(spanNode);
            if (!spanNode.nextSibling)
                continue;
            node = spanNode.nextSibling;
            offset += index + matchStr.length;
            spanNodes.push(spanNode)

            // Create modal to contain data when a node is clicked on.
            // https://www.w3schools.com/howto/howto_css_modals.asp
            let modal = document.getElementById("myModal") as HTMLElement;
            let span = document.getElementsByClassName("alpaca_close")[0] as HTMLSpanElement;
            // When the user clicks on the button, open the modal
            spanNode.onclick = function() {
                let title = document.getElementById('alpaca_modal_title') as HTMLHeadingElement;
                title.textContent = spanNode.textContent;
                let modalBody = document.getElementsByClassName('alpaca_modal-body')[0];
                let domain = (spanNode as any).textContent.toLowerCase();
                let data = ADDR_CACHE[domain];
                if (!data) return; // wait 2s until data has populated
                let table = document.createElement('table');
                let thead = table.createTHead();
                let theadRow = thead.insertRow();
                let row = table.insertRow();
                Object.keys(data).forEach(key=>{
                    let cell = theadRow.insertCell();
                    let text = document.createTextNode(key); 
                    cell.appendChild(text)
                });
                Object.values(data).forEach((value:any)=>{
                    let cell = row.insertCell();
                    let text = document.createTextNode(value);
                    cell.appendChild(text);
                });
                modalBody.textContent = '';
                modalBody.prepend(table);
                modal.style.display = "block";
            }
            // When the user clicks on <span> (x), close the modal
            span.onclick = function() {
                modal.style.display = "none";
            }
            // When the user clicks anywhere outside of the modal, close it
            window.onclick = function(event:Event) {
                if (event.target == modal) {
                    modal.style.display = "none";
                }
            }
        }
    }
    return spanNodes;
}

function modifyNodes(spanNodes: HTMLSpanElement[]) {
    // Domains should be checked async after IPs because they require fetch
    // Should fire async as fast as it can go
    // Hopefully no race conditions as nodes are separate

    // Run 10 at a time in promises to prevent locking browser for pages with massive #'s of domains
    const chunkSize = 100;
    spanNodes = [...spanNodes];
    for (let i = 0; i < spanNodes.length; i += chunkSize) {
        const chunkNodes = spanNodes.slice(i, i + chunkSize);
        let promises = []
        for (let node of chunkNodes) {
            if (node.textContent) {
                promises.push(modify_page(node, node.textContent));
            }     
        }
        Promise.all(promises);
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
    return spanNodes;
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
            modify_addrs(spanNode, DNS_CACHE[domain], domain, null)
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
                modify_addrs(spanNode, ip_addrs, domain, response)
            } else {
                modify_addrs(spanNode, [], addr, response)
            }
            // Don't check HTTP status code if there was a DNS error
            if (response.dns_code !== 0 && GET_STATUS_CODES_FOR_ALL_URLS && addr.match(DOMAIN_WITH_PATH_RE)) {
                const status_code = await fetch_url(addr)
                const statusCode = '[' + status_code.toString() + '] '
                spanNode.insertAdjacentText('afterbegin', statusCode)
            }
        }
    } else {
        modify_addrs(spanNode, [addr], '', null)
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
    domain = domain.toLowerCase() || 'Domain unknown';

    function get_ips() {
        let cf_ips = ipsInSubnet(ip_addrs, IPS.CF);
        if (Object.keys(cf_ips).length > 0) return ['cloudflare', cf_ips];
        let aws_ips = ipsInSubnet(ip_addrs, IPS.AWS_LIST);
        if (Object.keys(aws_ips).length > 0) return ['amazon', aws_ips];
        let akamai_ips = ipsInSubnet(ip_addrs, IPS.AKAMAI);
        if (Object.keys(akamai_ips).length > 0) return ['akamai', akamai_ips];
        let google_ips = ipsInSubnet(ip_addrs, IPS.GOOGLE);
        if (Object.keys(google_ips).length > 0) return ['google', google_ips];
        let microsoft_ips = ipsInSubnet(ip_addrs, IPS.MICROSOFT);
        if (Object.keys(microsoft_ips).length > 0) return ['microsoft', microsoft_ips];
        return ['other_cdn', ip_addrs]
    }

    let [source, ip_list] = get_ips()
    let company_emojis: any = {
        cloudflare: "🟠",
        amazon: "🟢",
        akamai: "🟡",
        google: "🟣",
        microsoft: "🟤",
        other_cdn: "🔵"
    }
    let ip_list_str = source === 'other_cdn' ? ip_addrs.join('\n') : Object.entries(ip_list).map(i=>`${source.padEnd(10, ' ')}| ` + i.join(` ∈ `)).join('\n');
    let message =  `${company_emojis[source]} ${domain}\n\n${ip_list_str}`
    console.log('Alpaca|' + message)
    spanNode.title = message
    spanNode.classList.add(`alpaca_${source}`)
    // Should be async and not tie up execution
    addAsnInfo(spanNode, ip_addrs, domain);
}

function ipsInSubnet(ip_addrs: string[], supernet: string[]) {
    let result: any = {};
    for (const ip_subnet of supernet) {
        for (const ip_addr of ip_addrs) {
            if (IsIpInSupernet(ip_addr, ip_subnet)) {
                result[ip_addr] = ip_subnet;
            }
        }
    }
    return result;
}

async function addAsnInfo(spanNode: HTMLSpanElement, ip_addrs: string[], domain: string) {
    new Promise((resolve) => {
        browser.runtime.sendMessage({requestName: "ASN_LOOKUP", ip: ip_addrs[0]}, (response) => {
            if (response.error) {
                console.log("Aborting request for", domain, "due to", response.error)
                return;
            }
            resolve(response.data)
        });
    }).then((asnData: any) => {
        ADDR_CACHE[domain] = {
            ...ADDR_CACHE[domain],
            ...asnData
        }
        delete asnData.ip;
        let asnDataStr = Object.entries(asnData).map(i=>i.join(': ')).join('\n');
        spanNode.title += '\n\n' + asnDataStr;
    })
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
