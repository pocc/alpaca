/* Service Worker script. */
import { cymru_asn } from "index"; 

class DNSError extends Error {
    constructor(msg: string) {
        super(msg);
        this.name = this.constructor.name; 
    }
}
const browser = chrome;
let PUBLIC_SUFFIX_LIST = Object();
let IPS: any = {
    CF: [],
    AWS_LIST: [],
    AWS_LIST_DESC: {}, // like 2a01:578:0:7000::/56 : "eu-west-1"
    AKAMAI: [],
    GOOGLE: [],
    MICROSOFT: []
}
let ACTIVE_URL = '';
let DNS_CACHE: {[iso8601_date: string]: {[hostname: string]: string[]}} = {}  // Saving the DNS CACHE, per day
let ASN_CACHE = [];
const getDate = () => new Date().toISOString().slice(0,10)

const DEBUG = true;

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

let contextMenuItem = {
    "id": "alpaca",
    "title": "Lookup address in bgp.he.net",
    "contexts": ["selection"]
};

// Global try / catch because it's easy
try {
    chrome.contextMenus.remove('alpaca', function() {
        chrome.contextMenus.create(contextMenuItem);
        // Created with https://stackoverflow.com/questions/14452777/is-that-possible-calling-content-script-method-by-context-menu-item-in-chrome-ex
        // Send clickData to content script
        chrome.contextMenus.onClicked.addListener(function(clickData, tab) {
            let tabId = (tab as chrome.tabs.Tab)?.id as number;
            chrome.tabs.sendMessage(tabId, {
                "context": 'contextMenu',
                "selectionText": clickData.selectionText
            });
        });
    });


    // For a tab, record the last url matching the regex and the timestamp of when it was visited
    const EXTN_URL = chrome.runtime.getURL('')
    const formatLog = (requestID: string, msg: string, data: any) => {
        console.log(`Alpaca|${new Date().getTime()}|${requestID}|${msg}: `, data)
    }


    browser.runtime.onInstalled.addListener(async () => {
        PUBLIC_SUFFIX_LIST = await setPublicSuffixList(); // Only check PSL on install
        formatLog('0', `Loaded PSL with this many entries`, PUBLIC_SUFFIX_LIST.length);
        formatLog('0', 'Alpaca Chrome extension has been installed at', EXTN_URL);

        let respCFv4Fetch = fetch('https://www.cloudflare.com/ips-v4');
        let respCFv6Fetch = fetch('https://www.cloudflare.com/ips-v6');
        let awsFetch = fetch('https://ip-ranges.amazonaws.com/ip-ranges.json');
        let akamaiFetch = fetch('https://techdocs.akamai.com/origin-ip-acl/docs/update-your-origin-server?json=on');
        let googleFetch = fetch('https://www.gstatic.com/ipranges/goog.json');
        let microsoftFetch = fetch('');
        let [respCFv4, respCFv6, aws_resp, akamai_resp, google_resp] = await Promise.all(
            [
                respCFv4Fetch, 
                respCFv6Fetch, 
                awsFetch, 
                akamaiFetch,
                googleFetch,
                microsoftFetch
            ]
        );

        const aws_text = await aws_resp.text();
        const aws_json = JSON.parse(aws_text);
        let AWS_LIST_DESC:any = {};
        for (const i of aws_json.prefixes) {
            AWS_LIST_DESC[i.ip_prefix] = i.region;
        };
        for (const i of aws_json.ipv6_prefixes) {
            AWS_LIST_DESC[i.ipv6_prefix] = i.region;
        }
        let akamai_text = await akamai_resp.text();
        let akamai_IPs_partial = [...akamai_text.matchAll(/```\\n(.+?)```/ig)].map(i=>i[1]).join('')
        IPS.AKAMAI = akamai_IPs_partial.replaceAll(' ', '').split('\\n').filter(i=>i)

        let CF_IPV4 = (await respCFv4.text()).split('\n');
        let CF_IPV6 = (await respCFv6.text()).split('\n');
        IPS.CF = CF_IPV4.concat(CF_IPV6);
        IPS.AWS_LIST = Object.keys(AWS_LIST_DESC);
        let google_json = await google_resp.json()
        for (let i=0; i<google_json.prefixes.length; ++i) {
            IPS.GOOGLE.push(Object.values(google_json.prefixes[i])[0])
        }
        // Taken from Microsoft's AS https://bgp.he.net/AS8075#_prefixes
        IPS.MICROSOFT = ["101.203.88.76","101.203.89.63","102.133.0.0/16","102.133.0.0/17","102.133.128.0/17","102.37.0.0/16","102.37.0.0/17","102.37.128.0/17","103.131.148.0/24","103.131.149.0/24","103.136.102.34","103.136.102.35","103.136.103.28","103.136.103.29","103.140.210.8","103.140.210.9","103.155.245.0/24","103.16.102.139","103.16.102.23","103.162.254.50","103.162.254.95","103.164.237.0/24","103.189.128.0/24","103.203.158.101","103.203.158.102","103.218.244.106","103.218.244.108","103.218.247.114","103.218.247.115","103.228.174.5","103.228.174.6","103.231.152.101","103.231.152.102","103.246.232.110","103.246.232.116","103.249.62.0/24","103.249.63.0/24","103.26.68.7","103.26.69.104","103.26.70.18","103.26.70.20","103.26.71.165","103.26.71.35","103.27.168.5","103.27.168.6","103.27.170.220","103.27.170.5","103.30.172.29","103.30.172.62","103.41.12.23","103.41.12.50","103.58.119.0/24","103.77.108.128","103.77.108.26","103.77.110.10","103.77.110.14","103.8.80.0/24","104.146.128.0/17","104.208.0.0/13","104.40.0.0/13","104.47.19.0/24","108.140.0.0/14","111.221.16.0/21","111.221.24.0/22","111.221.29.0/24","111.221.30.0/23","111.221.64.0/18","113.197.64.0/24","113.197.65.0/24","113.197.66.0/24","113.197.67.0/24","119.11.184.84","119.11.184.85","123.255.90.222","123.255.91.120","128.94.0.0/16","129.35.19.0/24","13.104.0.0/14","13.107.14.0/24","13.64.0.0/11","131.253.1.0/24","131.253.12.0/22","131.253.128.0/17","131.253.24.0/21","131.253.32.0/20","131.253.5.0/24","131.253.6.0/24","131.253.61.0/24","131.253.62.0/23","131.253.8.0/24","132.164.0.0/16","132.245.0.0/16","134.170.0.0/16","135.130.0.0/16","135.149.0.0/16","135.56.0.0/24","137.116.0.0/16","137.117.0.0/16","137.135.0.0/16","138.105.0.0/16","138.128.250.0/24","138.128.251.0/24","138.239.0.0/16","138.91.0.0/16","142.0.188.0/24","142.147.54.0/24","142.147.61.0/24","142.215.8.23","142.215.8.24","145.46.160.0/24","145.46.161.0/24","147.145.0.0/16","147.243.0.0/16","148.7.0.0/16","149.112.11.10","149.112.11.20","149.112.13.43","149.112.13.44","149.112.27.12","149.112.27.13","150.171.0.0/16","150.171.0.0/24","150.171.254.0/24","151.206.0.0/16","155.62.0.0/16","157.31.0.0/16","157.55.0.0/16","157.56.0.0/16","157.95.0.0/16","158.158.0.0/16","158.23.0.0/16","159.128.0.0/16","161.69.104.0/24","167.105.0.0/16","167.162.0.0/16","167.186.0.0/16","167.92.211.0/24","167.92.212.0/24","168.61.0.0/16","168.62.0.0/15","169.138.0.0/16","170.114.39.0/24","170.114.47.0/24","170.114.56.0/24","170.114.57.0/24","170.165.0.0/16","170.88.82.0/24","170.88.83.0/24","170.88.84.0/24","170.88.85.0/24","172.128.0.0/11","172.160.0.0/11","172.200.0.0/13","172.208.0.0/13","176.116.123.0/24","176.126.38.18","176.126.38.28","178.18.225.38","178.255.242.0/24","183.177.61.5","183.177.61.64","185.0.20.214","185.0.20.215","185.1.101.31","185.1.102.101","185.1.104.139","185.1.104.57","185.1.106.46","185.1.107.34","185.1.109.26","185.1.112.134","185.1.112.37","185.1.116.33","185.1.119.23","185.1.119.24","185.1.122.15","185.1.126.248","185.1.126.253","185.1.131.6","185.1.143.24","185.1.15.14","185.1.159.20","185.1.170.123","185.1.170.161","185.1.170.170","185.1.170.94","185.1.172.5","185.1.172.9","185.1.208.100","185.1.208.133","185.1.208.167","185.1.208.172","185.1.210.105","185.1.210.133","185.1.226.124","185.1.226.150","185.1.30.58","185.1.48.11","185.1.48.19","185.1.55.95","185.1.55.96","185.1.63.177","185.1.63.178","185.1.65.227","185.1.65.228","185.1.8.22","185.1.8.32","185.1.86.27","185.1.87.110","185.1.87.120","185.1.94.41","185.117.183.0/24","185.117.230.0/24","185.135.57.0/24","185.154.80.0/24","185.154.81.0/24","185.154.82.0/24","185.154.83.0/24","185.195.244.0/24","185.195.245.0/24","185.209.208.0/24","185.209.209.0/24","185.211.208.0/24","185.232.60.162","185.232.60.165","185.242.139.0/24","185.52.203.0/24","185.6.36.28","185.76.37.0/24","185.79.175.184","187.16.218.139","187.16.218.144","191.232.0.0/13","192.100.104.0/21","192.100.112.0/21","192.100.120.0/21","192.100.128.0/22","192.121.80.117","192.121.80.59","192.145.251.47","192.145.251.48","192.197.157.0/24","192.203.154.162","192.38.7.76","192.38.7.86","192.40.79.0/24","192.48.225.0/24","192.65.185.49","192.84.160.0/24","192.84.161.0/24","193.110.224.62","193.110.226.62","193.136.250.60","193.136.251.6","193.149.1.29","193.149.64.0/19","193.169.198.74","193.169.198.85","193.178.185.104","193.178.185.84","193.188.137.21","193.188.137.51","193.201.28.116","193.201.28.129","193.203.0.164","193.203.0.165","193.221.113.0/24","193.239.117.16","193.239.118.163","193.239.118.172","193.239.118.173","193.242.98.149","193.242.98.152","193.25.180.248","193.25.180.249","194.110.197.0/24","194.116.96.88","194.146.118.17","194.146.118.18","194.180.131.0/24","194.41.19.0/24","194.41.21.0/24","194.41.22.0/24","194.42.48.50","194.44.235.0/24","194.50.21.0/24","194.53.172.34","194.59.190.10","194.59.190.8","194.68.123.181","194.88.240.77","194.9.117.84","195.105.26.0/24","195.114.140.0/24","195.149.232.105","195.149.232.50","195.182.218.146","195.182.218.167","195.245.240.181","195.42.145.236","195.42.145.28","195.66.224.112","195.66.224.140","195.66.236.140","195.66.244.116","195.66.244.82","195.8.43.0/24","196.11.234.40","196.11.234.41","196.223.1.47","196.223.1.48","196.223.14.156","196.223.14.173","196.223.21.101","196.223.21.102","196.223.22.156","196.223.22.173","196.46.25.140","196.46.25.141","196.60.58.34","196.60.58.35","196.60.70.147","196.60.70.47","196.60.8.133","196.60.9.133","196.60.96.156","196.60.96.173","198.179.18.16","198.179.18.95","198.180.95.0/24","198.180.97.0/24","198.185.5.0/24","198.200.130.0/24","198.206.164.0/24","198.22.19.0/24","198.22.205.0/24","198.32.118.18","198.32.118.91","198.32.132.117","198.32.132.18","198.32.134.3","198.32.134.5","198.32.141.141","198.32.146.199","198.32.160.199","198.32.176.145","198.32.176.45","198.32.182.105","198.32.182.205","198.32.195.124","198.32.195.125","198.32.212.157","198.32.212.95","198.32.242.188","198.32.242.189","198.32.96.35","198.32.96.36","198.47.13.0/24","198.49.8.0/24","198.51.0.0/24","198.52.0.0/24","198.8.73.0/24","199.0.184.0/24","199.0.185.0/24","199.103.122.0/24","199.103.90.0/23","199.189.36.0/24","199.189.37.0/24","199.242.32.0/20","199.242.48.0/21","199.30.16.0/20","199.60.28.0/24","199.65.243.0/24","199.65.247.0/24","199.65.251.0/24","199.65.28.0/24","2.58.103.0/24","20.0.0.0/11","20.135.0.0/16","20.136.0.0/17","20.143.0.0/16","20.150.0.0/15","20.152.0.0/16","20.153.0.0/16","20.157.0.0/16","20.160.0.0/12","20.184.0.0/13","20.192.0.0/10","20.196.0.0/18","20.203.0.0/17","20.33.0.0/16","20.36.0.0/14","20.37.64.0/19","20.40.0.0/13","20.45.128.0/20","20.45.64.0/20","20.45.80.0/24","20.46.144.0/20","20.46.192.0/19","20.46.32.0/19","20.46.32.0/24","20.48.0.0/12","20.64.0.0/10","20.74.128.0/17","200.0.17.217","200.0.17.218","200.192.108.42","200.192.108.85","2001:12f8:0:11::42","2001:12f8:0:11::85","2001:12f8:0:2::72","2001:12f8:0:2::73","2001:12f8::21","2001:13c7:6001::21","2001:1a40:10::","2001:43f8:11f0::1","2001:43f8:1f0::15","2001:43f8:1f0::17","2001:43f8:1f1::15","2001:43f8:1f1::17","2001:43f8:390::2","2001:43f8:390::30","2001:43f8:60:1::10","2001:43f8:6d0::13","2001:43f8:6d0::9","2001:43f8:6d1::14","2001:43f8:6d1::47","2001:43f8:9d0::1","2001:478:132::11","2001:478:132::18","2001:478:96::35","2001:478:96::36","2001:504:0:10::80","2001:504:0:1::80","2001:504:0:2::80","2001:504:0:3::80","2001:504:0:4::80","2001:504:0:5::80","2001:504:0:6::80","2001:504:0:7::80","2001:504:0:a::80","2001:504:102::1","2001:504:105::43","2001:504:105::44","2001:504:10::80","2001:504:116::1","2001:504:12::80","2001:504:13:4::35","2001:504:13:4::36","2001:504:13::21","2001:504:16::1","2001:504:16::68","2001:504:17:10::14","2001:504:17:114::32","2001:504:17:115::23","2001:504:17:115::85","2001:504:1::","2001:504:1a::34","2001:504:1a::35","2001:504:24:1::1","2001:504:27::1","2001:504:2d::18","2001:504:31::1","2001:504:36::1","2001:504:38:1:0:a500:8075:1","2001:504:39::41","2001:504:39::42","2001:504:3d:1:0:a500:8075:1","2001:504:40:108::1","2001:504:40:12::1","2001:504:41:110::57","2001:504:41:110::58","2001:504:47::1","2001:504:58::43","2001:504:58::44","2001:504:61::1","2001:504:a::","2001:504:b:10::7","2001:504:d::80","2001:504:f::12","2001:504:f::80","2001:67c:29f0::80","2001:7f8:10::","2001:7f8:10::80","2001:7f8:10a::1","2001:7f8:12:1:0:1:0:8075","2001:7f8:12:1::80","2001:7f8:12:6:0:1:0:8075","2001:7f8:12:6::80","2001:7f8:13::","2001:7f8:14::6","2001:7f8:17::1","2001:7f8:18:12::77","2001:7f8:18::28","2001:7f8:19:1::1","2001:7f8:1::","2001:7f8:1c:24a:f25c::49","2001:7f8:1f::80","2001:7f8:23:ffff::88","2001:7f8:24::","2001:7f8:24::98","2001:7f8:26::","2001:7f8:27::80","2001:7f8:28::25","2001:7f8:28::45","2001:7f8:2a:0:2:1:0:8075","2001:7f8:2a:0:2:2:0:8075","2001:7f8:2c:1000:0:1f8b:0:1","2001:7f8:2c:1000:0:1f8b:0:2","2001:7f8:30:0:2:1:0:8075","2001:7f8:30:0:2:2:0:8075","2001:7f8:35::80","2001:7f8:3d::1","2001:7f8:3e:0:a500:0:8075:1","2001:7f8:3e:0:a500:0:8075:2","2001:7f8:3f::1","2001:7f8:42::","2001:7f8:43::80","2001:7f8:44::1","2001:7f8:4:1::1","2001:7f8:4:2::1","2001:7f8:4::1","2001:7f8:54:5::14","2001:7f8:54:5::97","2001:7f8:54::1","2001:7f8:54::5","2001:7f8:58::1","2001:7f8:60::10","2001:7f8:60::13","2001:7f8:63::","2001:7f8:64:225::80","2001:7f8:6c::43","2001:7f8:6e::18","2001:7f8:6e::28","2001:7f8:73::1","2001:7f8:7:a::80","2001:7f8:7:b::80","2001:7f8:7a::80","2001:7f8:7f::21","2001:7f8:83::80","2001:7f8:8:20:0:1f8b:0:1","2001:7f8:8:20:0:1f8b:0:3","2001:7f8:8:5:0:1f8b:0:1","2001:7f8:8::1","2001:7f8:9e::1","2001:7f8:9f::6","2001:7f8::1","2001:7f8:a:1::6","2001:7f8:a:2::6","2001:7f8:af::80","2001:7f8:b6::1","2001:7f8:b:100:1d1:a5d0:8075:112","2001:7f8:b:100:1d1:a5d0:8075:212","2001:7f8:bc::80","2001:7f8:bd::80","2001:7f8:be::80","2001:7f8:c0::80","2001:7f8:c1::80","2001:7f8:c3::80","2001:7f8:c7::80","2001:7f8:c:8235:194:42:48:50","2001:7f8:cd::","2001:7f8:d1::1","2001:7f8:d5::1","2001:7f8:d:203::18","2001:7f8:d:fc::18","2001:7f8:d:ff::18","2001:7f8:de::80","2001:7f8:ed::20","2001:7f8:f5::1","2001:7f8:f:1::70","2001:7f8:f::70","2001:7fa:0:1::","2001:7fa:11:1:0:2f2c:0:1","2001:7fa:11:1:0:2f2c:0:2","2001:7fa:11:2:0:2f2c:0:1","2001:7fa:11:2:0:2f2c:0:2","2001:7fa:11:4:0:2f2c:0:1","2001:7fa:11:4:0:2f2c:0:2","2001:7fa:11:6:0:1f8b:0:1","2001:7fa:11:6:0:1f8b:0:2","2001:7fa:11::2","2001:7fa:3:ca07::","2001:7fa:4:c0cb::9","2001:7fa:7:1::80","2001:7fa:7:2::80","2001:7fa:8::13","2001:7fa:8::14","2001:c38:8000::80","2001:de8:10::","2001:de8:10::54","2001:de8:12:100::13","2001:de8:12:100::23","2001:de8:1:2::11","2001:de8:1::10","2001:de8:4::80","2001:de8:5:1::80","2001:de8:5::80","2001:de8:6:1::80","2001:de8:6::1","2001:de8:6::80","2001:de8:7:1::80","2001:de8:7::80","2001:de8:8:6::80","2001:de8:8::80","2001:de8:c:2::80","2001:de8:c::80","2001:de8:d::80","2001:dea:0:10::16","2001:dea:0:10::7","2001:dea:0:20::12","2001:dea:0:20::14","2001:dea:0:30::","2001:dea:0:30::23","2001:dea:0:40::26","2001:dea:0:40::72","2001:dea:0:50::","2001:ded::17","2001:ded::32","2001:df0:680:3::22","2001:df0:680:3::23","2001:df0:680:4::1","2001:df0:680:5::36","2001:df0:680:5::37","2001:df0:680:6::18","2001:df0:680:6::19","2001:df0:7::/48","2001:df0:d7::/48","2001:df0:d8::/48","2001:df0:d9::/48","2001:df0:f080:cdc:cdc:cdc:cdc:13","2001:df0:f080:cdc:cdc:cdc:cdc:14","2001:df2:1900:1::13","2001:df2:1900:1::38","2001:df2:1900:2::12","2001:df2:1900:2::26","2001:df2:1900:3::12","2001:df2:1900:3::13","2001:df2:1900:4::10","2001:df2:1900:4::14","2001:df5:b800:bb00::80","2001:df6:480::1","2001:df6:480::50","2001:df6:480::95","2001:e48:44:100b:0:a500:8075:1","2001:e48:44:100b:0:a500:8075:2","202.12.243.11","202.12.243.14","202.7.0.220","202.77.88.54","202.77.88.55","202.77.90.24","202.77.90.25","202.89.224.0/21","203.163.222.15","203.163.222.85","203.190.227.22","203.190.227.23","203.190.230.24","203.190.230.34","203.32.10.0/24","203.32.11.0/24","203.84.134.0/24","203.84.135.0/24","204.14.180.0/22","204.152.140.0/23","204.79.135.0/24","204.79.179.0/24","204.79.195.0/24","204.79.252.0/24","204.95.96.0/20","205.135.211.0/24","205.135.212.0/24","205.143.44.0/24","205.143.45.0/24","206.108.115.47","206.108.236.10","206.108.236.110","206.108.255.156","206.108.255.157","206.108.34.160","206.108.35.109","206.126.114.32","206.126.115.23","206.126.115.85","206.126.236.148","206.126.236.17","206.138.168.0/21","206.191.224.0/19","206.197.210.37","206.223.116.17","206.223.118.17","206.223.118.65","206.223.123.17","206.41.104.41","206.41.104.42","206.41.106.72","206.41.108.25","206.41.110.57","206.41.110.58","206.51.43.35","206.51.43.36","206.51.46.100","206.51.46.72","206.53.143.7","206.53.170.12","206.53.171.13","206.53.172.12","206.53.174.12","206.53.175.43","206.53.175.44","206.53.202.15","206.53.203.7","206.53.205.6","206.55.196.62","206.55.196.63","206.71.12.47","206.71.12.48","206.72.210.143","206.72.211.133","206.72.211.94","206.81.80.30","206.81.80.68","206.82.104.133","206.82.104.215","206.83.10.14","207.231.240.7","207.46.0.0/19","207.46.128.0/17","207.46.36.0/22","207.46.40.0/21","207.46.48.0/20","207.46.64.0/18","207.68.128.0/18","208.115.128.45","208.115.128.46","208.115.136.27","208.115.137.61","208.66.228.0/24","208.68.136.0/21","208.76.45.0/24","208.76.46.0/24","208.80.20.0/24","208.80.21.0/24","208.84.0.0/21","209.124.52.65","209.124.52.66","209.199.0.0/16","209.240.192.0/19","210.171.224.110","210.171.224.116","210.173.176.16","210.173.177.11","210.173.178.16","210.173.178.26","210.173.184.16","210.173.184.26","212.1.218.0/24","212.1.219.0/24","212.1.222.0/24","212.1.223.0/24","212.237.193.181","212.46.57.0/24","212.91.0.147","212.91.0.148","213.156.248.0/24","213.199.128.0/18","213.218.48.0/22","216.220.203.0/24","216.220.204.0/24","216.220.208.0/20","216.32.180.0/22","216.73.183.0/24","217.29.66.112","217.29.66.212","218.100.44.154","218.100.44.214","218.100.52.4","218.100.53.70","218.100.76.122","218.100.76.49","218.100.78.2","218.100.78.51","218.100.9.28","218.100.9.75","223.31.200.106","223.31.200.19","23.100.0.0/15","23.102.0.0/16","23.103.128.0/17","23.103.160.0/20","23.103.64.0/18","23.96.0.0/14","2400:d180:67::5","2400:d180:67::6","2400:d180:68::5","2400:d180:68::6","2401:7500:fff6::22","2401:7500:fff6::5","2403:c780:b800:bb00::80","2404:c8:0:a::80","2404:f800::/32","2406:d400:1:133:203:163:222:15","2406:d400:1:133:203:163:222:85","2407:30c0:184::/48","2407:30c0:185::/48","2602:812:200a::/48","2602:fc31:4::/48","2602:fdeb:50::/48","2602:fdeb:52::/48","2602:fdeb:53::/48","2602:fdeb:54::/48","2602:fdeb:55::/48","2602:fdeb:61::/48","2602:fdeb:62::/48","2602:fdeb:63::/48","2602:fdeb:64::/48","2603:1000::/25","2603:1061:6::/48","2603:1062:7::/48","2605:6c00:303:303::10","2605:6c00:303:303::72","2606:7c80:3375:50::37","2606:a980:0:3::","2606:a980:0:4::","2606:a980:0:5::","2606:a980:0:7::","2606:a980:0:8::7","2606:a980:0:9::6","2607:33c0:a0::/48","2607:f790:100::65","2607:f790:100::66","2620:0:30::/45","2620:10c:5001::/48","2620:124:2000::12","2620:1ec:25::/48","2620:1ec:9::/48","2620:1ec::/36","27.111.228.57","27.111.229.172","27.111.230.41","27.111.230.89","2801:14:9000::80","2801:80:1d0::/48","2a01:111:2000::/36","2a01:111:4000::/36","2a01:111:4004::/48","2a01:111::/32","2a01:111:f000::/36","2a02:d10:80::","2a02:d10:80::13","2a02:d10:80::32","2a03:52a0:183::/48","2a03:5f80:4::22","2a05:f500:2::/48","2a07:54c4:1756::/48","2a12:dd47:84fc::/48","2a12:fc0::/48","2a12:fc7:ffef::/48","36.255.56.23","36.255.56.4","37.49.232.14","37.49.232.97","37.49.236.5","37.49.237.119","4.144.0.0/12","4.160.0.0/12","4.176.0.0/12","4.192.0.0/12","4.208.0.0/12","4.224.0.0/12","4.240.0.0/12","40.104.0.0/14","40.104.0.0/15","40.107.142.0/23","40.107.18.0/23","40.108.128.0/17","40.110.0.0/15","40.112.0.0/13","40.119.160.0/19","40.120.0.0/14","40.120.0.0/20","40.123.192.0/19","40.123.224.0/20","40.124.0.0/16","40.125.0.0/17","40.126.0.0/18","40.126.128.0/17","40.126.192.0/23","40.127.0.0/16","40.127.0.0/19","40.162.0.0/16","40.169.0.0/16","40.170.0.0/16","40.171.0.0/16","40.64.0.0/15","40.66.0.0/17","40.66.166.0/24","40.67.0.0/16","40.68.0.0/14","40.74.0.0/15","40.76.0.0/14","40.80.0.0/12","40.95.238.0/23","40.95.86.0/23","40.96.0.0/13","41.223.11.0/24","43.243.21.23","43.243.21.99","43.243.22.114","43.243.22.38","45.120.248.13","45.120.248.38","45.120.251.125","45.120.251.137","45.127.172.36","45.127.173.62","45.143.224.0/24","45.143.225.0/24","45.6.52.72","45.6.52.73","45.66.80.0/24","45.68.16.210","45.68.16.211","45.8.43.0/24","45.82.119.0/24","46.29.242.0/24","5.57.81.17","5.57.81.18","51.10.0.0/15","51.103.0.0/16","51.104.0.0/15","51.107.0.0/16","51.116.0.0/16","51.12.0.0/15","51.120.0.0/16","51.124.0.0/16","51.132.0.0/16","51.136.0.0/15","51.138.0.0/16","51.140.0.0/14","51.144.0.0/15","51.51.0.0/16","51.53.0.0/16","52.105.196.0/23","52.112.0.0/14","52.120.0.0/14","52.125.0.0/16","52.136.0.0/13","52.146.0.0/15","52.148.0.0/14","52.152.0.0/13","52.160.0.0/11","52.224.0.0/11","52.239.232.0/24","52.96.0.0/12","52.96.0.0/14","52.96.38.0/24","52.98.16.0/22","57.150.0.0/15","57.152.0.0/14","57.156.0.0/14","57.160.0.0/12","61.19.60.74","61.19.60.75","62.12.56.0/24","62.12.57.0/24","62.12.58.0/24","62.12.59.0/24","62.12.60.0/24","62.12.61.0/24","62.69.146.38","62.69.146.70","64.191.233.147","64.191.233.148","64.4.0.0/18","65.52.0.0/14","66.119.144.0/20","66.178.148.0/24","66.178.149.0/24","68.154.0.0/15","68.210.0.0/15","68.218.0.0/15","68.220.0.0/15","69.52.192.0/24","69.52.193.0/24","69.52.198.0/24","69.52.199.0/24","69.59.17.0/24","69.84.180.0/24","70.152.0.0/15","70.156.0.0/15","70.37.0.0/17","70.37.128.0/18","72.144.0.0/14","72.152.0.0/14","72.18.78.0/24","74.160.0.0/14","74.176.0.0/14","74.200.130.0/24","74.224.0.0/14","74.234.0.0/15","74.240.0.0/14","74.248.0.0/15","74.80.229.0/24","77.69.248.18","77.69.248.21","80.249.209.20","80.249.209.21","80.81.194.52","80.81.195.11","80.97.248.52","80.97.248.76","86.104.125.130","86.104.125.180","91.206.52.152","91.206.52.247","91.210.16.115","91.210.16.116","91.212.235.6","91.213.211.214","91.213.211.215","91.216.184.0/24","92.118.22.0/24","92.118.23.0/24","94.143.105.0/24","94.143.106.0/24","94.143.107.0/24","94.143.108.0/24","94.245.64.0/18","98.64.0.0/14","98.70.0.0/15"]
        formatLog('0', 'Got these IPS', IPS);
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

    interface Question {
        name: string;
        type: number;
    }

    interface Answer {
        name: string; // hostname
        type: number;
        TTL: number;
        data: string; // IP address
    }

    interface DNSQuery {
        Status: number;
        TC: boolean;
        RD: boolean;
        RA: boolean;
        AD: boolean;
        CD: boolean;
        Question: Question[];
        Answer: Answer[];
    }

    async function DNSQuery(query: string, type: string) {
        const required_headers = {headers: {'accept': 'application/dns-json'}}
        return await fetch(`https://cloudflare-dns.com/dns-query?name=${query}&type=${type}`, required_headers);
    }

    async function DomainLookup(domain: string): Promise<[string[], number, string]> {
        const A_TYPE = 1
        const AAAA_TYPE = 28
        const todaysDate = getDate()

        DNS_CACHE[todaysDate] = DNS_CACHE[todaysDate] || {}
        if (DNS_CACHE[todaysDate][domain]) {
            if (DEBUG)
                console.log("Hit cache for", domain)
            return [DNS_CACHE[todaysDate][domain], 0, '']
        } else {
            if (DEBUG)
                console.log("missed", DNS_CACHE)
        }
    
        try {
            const respA = await DNSQuery(domain, 'A');
            const respTextA = await respA.text();
            if (DEBUG)
                console.log("Alpaca| Sending IPv4 DNS query for", domain, "Got", respTextA)
            const respJSONA: DNSQuery = JSON.parse(respTextA);
            let answers: Answer[] = [];
            if (respJSONA.Status !== 0) {
                return [[], respJSONA.Status, JSON.stringify(respJSONA.Answer)]
            }
            if (respJSONA.Answer) {
                const ipv4_answers = respJSONA.Answer.filter((rr) => rr.type === A_TYPE)
                answers = answers.concat(ipv4_answers)
            } else {
                // get IPv6 addresses in addition to IPv4
                const respAAAA = await DNSQuery(domain, 'AAAA');
                const respTextAAAA = await respAAAA.text();
                if (DEBUG)
                    console.log("Alpaca| Sending IPv6 DNS query for", domain, "Got", respTextAAAA)
                const respJSONAAAA: DNSQuery = JSON.parse(respTextAAAA);
                if (respJSONAAAA.Status !== 0) {
                    return [[], respJSONAAAA.Status, JSON.stringify(respJSONAAAA.Answer)]
                }
                if (respJSONA.Question && respJSONAAAA.Question && !respJSONA.Answer && !respJSONAAAA.Answer) {
                    // We've exhausted both IPv4 and IPv6 record requests
                    return [[], 3, 'NXDOMAIN: Domain name not exist. No A or AAAA records found for ' + domain + '.'] 
                }
                if (respJSONAAAA.Status === 0 && respJSONAAAA.Answer) {
                    const ipv6_answers = respJSONAAAA.Answer.filter((rr) => rr.type === AAAA_TYPE)
                    answers = answers.concat(ipv6_answers)
                }
            }
            let ip_addrs = []
            for (const rr of answers) {
                ip_addrs.push(rr.data)
            }
            console.log("Alpaca| Found IP ADDRs", ip_addrs, "for domains", domain, ". Adding to cache")
            DNS_CACHE[todaysDate][domain] = ip_addrs
            return [ip_addrs, 0, '']
        } catch(e) {
            const err_msg = 'Encountered problem looking up DNS for ' + domain + ':' + e
            console.error();
            return [[], 0, err_msg];
        }
    }

    async function ASNLookup(ip: string): Promise<Array<cymru_asn | DNSError | null>> {
        let reversedIP = ip.split('.').reverse().join('.');
        let cymruDNSUrl = `${reversedIP}.origin.asn.cymru.com`
        let cymruHTTPRequest = await fetch("https://asn.cymru.com/cgi-bin/whois.cgi", {
            "headers": {
            "content-type": "multipart/form-data; boundary=----WebKitFormBoundaryXWfc8ARHxAstmqvn",
            },
            "body": `------WebKitFormBoundaryXWfc8ARHxAstmqvn\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\ndo_whois\r\n------WebKitFormBoundaryXWfc8ARHxAstmqvn\r\nContent-Disposition: form-data; name=\"family\"\r\n\r\nipv4\r\n------WebKitFormBoundaryXWfc8ARHxAstmqvn\r\nContent-Disposition: form-data; name=\"method_whois\"\r\n\r\nwhois\r\n------WebKitFormBoundaryXWfc8ARHxAstmqvn\r\nContent-Disposition: form-data; name=\"bulk_paste\"\r\n\r\n${ip}\r\n------WebKitFormBoundaryXWfc8ARHxAstmqvn\r\nContent-Disposition: form-data; name=\"submit_paste\"\r\n\r\nSubmit\r\n------WebKitFormBoundaryXWfc8ARHxAstmqvn--\r\n`,
            "method": "POST",
        });
        let cymruHTTPText = await cymruHTTPRequest.text(); 
        let cymruMatch = cymruHTTPText.match(/<PRE>.*?\n([\s\S]+?\|[\s\S]+?)\n<\/PRE>/i);
        if (!cymruMatch ||cymruMatch.length < 2) {
            let error = new DNSError('Got incorrect data to parse ASN data' + cymruHTTPText);
            console.log("With request for", ip, "Got", error);
            return [null, error];
        }
        let [httpAsn, httpIp, httpAsnName] = cymruMatch[1].replaceAll(' ', '').split('|');
        let asnHTTPData = {asn: httpAsn, ip: httpIp, asnName: httpAsnName}
        let resp = await DNSQuery(cymruDNSUrl, 'TXT')
        let asnData = await resp.json();
        if (asnData.Status !== 0) {
            let error = new DNSError(JSON.stringify(asnData));
            console.log("With request for", ip, "Got", error);
            return [null, error];
        }
        // Data field looks like "\"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11\""
        let [asn, prefix, countryCode, registry, registrationDate] = asnData.Answer[0].data.replaceAll(/[\\" ]+/g, '').split('|')
        let cymruAsn: cymru_asn = {asn, prefix, countryCode, registry, registrationDate, ip, asnName: asnHTTPData.asnName};
        console.log("Returning successfully from ASN Lookup with", cymruAsn);
        return [cymruAsn, null];
    }

    // Check the status code of a URL
    async function fetchURL(url: string) {
        const resp = await fetch(url, { method: 'GET', redirect: 'follow'});
        console.log("Got url and resp:", url, resp);
        return resp;
    }

    async function parseArgs(request: any, sender: any) {
        if (DEBUG)
            console.log(sender.tab ? "Alpaca| Got request from content script: " + sender.tab.url + JSON.stringify(request): "Got request from the extension");
        if (request.requestName === "IPS") {
            return {data: IPS};
        } else if (request.requestName === "PUBLIC_SUFFIX_LIST") {
            if (Object.keys(PUBLIC_SUFFIX_LIST).length === 0) {
                // For some reason, it doesn't get set sometimes
                PUBLIC_SUFFIX_LIST = await setPublicSuffixList();
            }
            return {data: PUBLIC_SUFFIX_LIST};
        } else if (request.requestName === "ASN_LOOKUP") { 
            let [data, error] = await ASNLookup(request.ip)
            return {data, error}
        } else if (request.requestName === "DNS_LOOKUP") { 
            // domain should match PSL because it's been checked in content script
            let domain = request.domain
            if (domain.includes('://')) { // Get rid of scheme
                domain = domain.split('://')[1]
            }
            const [ip_addrs, dns_code, err_msg] = await DomainLookup(domain)
            return {data: ip_addrs, dns_code: dns_code, error: err_msg};
        } else if (request.requestName === "URL_FETCH") {
            try {
                const resp = await fetchURL(request.url)
                return {status_code: resp.status, error: ''}
            } catch (e) {
                return {status_code: 404, error: e}
            }
        }
        return {data: "UNKNOWN REQUEST NAME"};
    }
} catch (err) {
    console.log(err);
}