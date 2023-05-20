export type cloudService = 'aws' | 'azure' | 'gcp' | 'cloudflare'
export type addrType = 'domain' | 'ipv4' | 'ipv6'
export type dns_response = {data: string[], error: string, dns_code: number}
export type cymru_asn = {
    asn: string,
    prefix: string,
    countryCode: string,
    registry: string,
    registrationDate: string
    ip: string,
    asnName: string
}