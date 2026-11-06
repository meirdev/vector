package metadata

services: netflow: {
	name:     "NetFlow"
	thing:    "NetFlow, IPFIX, and sFlow exporters"
	url:      urls.rfc_7011
	versions: null

	description: "NetFlow, [IPFIX](\(urls.rfc_7011)), and [sFlow](\(urls.sflow_v5)) are protocols that routers, switches, firewalls, and hosts use to export summaries of the network traffic they see, as flow records, to a collector."
}
