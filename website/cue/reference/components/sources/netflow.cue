package metadata

components: sources: netflow: {
	_port: 2055

	title: "NetFlow"

	classes: {
		delivery: "best_effort"
		deployment_roles: ["aggregator"]
		development:   "beta"
		egress_method: "stream"
		stateful:      false
	}

	features: {
		auto_generated:   true
		acknowledgements: false
		multiline: enabled: false
		receive: {
			from: {
				service: services.netflow
				interface: socket: {
					api: {
						title: "IPFIX"
						url:   urls.rfc_7011
					}
					direction: "incoming"
					port:      _port
					protocols: ["udp"]
					ssl: "disabled"
				}
			}
			receive_buffer_bytes: enabled: true
			keepalive: enabled:            false
			tls: enabled:                  false
		}
	}

	support: {
		requirements: []
		warnings: []
	}

	installation: {
		platform_name: null
	}

	configuration: generated.components.sources.netflow.configuration

	outputs: [
		components._default_output,
		{
			name: "options"
			description: """
				NetFlow v9 and IPFIX options records go to this output: what an exporter says about
				its interfaces, samplers, and observation domains, rather than about flows. Use
				`<component_id>.options` as an input to downstream transforms and sinks. Nothing is
				sent to this output for NetFlow v5 and sFlow, which have no options records.
				"""
		},
	]

	output: logs: flow: {
		description: """
			A flow record. With `format` set to `ipfix`, its fields are the record's IPFIX
			information elements, keyed by name; with `format` set to `common`, they are a fixed
			set of fields mapped from those elements.
			"""
		fields: {
			flow_type: {
				description: "The protocol the record arrived in."
				required:    true
				type: string: {
					enum: {
						netflow_v5: "NetFlow v5"
						netflow_v9: "NetFlow v9"
						ipfix:      "IPFIX"
						sflow_v5:   "sFlow v5"
					}
				}
			}
			host: {
				description: "The IP address of the exporter that sent the record."
				required:    true
				type: string: {
					examples: ["192.0.2.1"]
				}
			}
			source_type: {
				description: "The name of the source type."
				required:    true
				type: string: {
					examples: ["netflow"]
				}
			}
			timestamp: fields._current_timestamp
			"*": {
				description: """
					With `format` set to `ipfix`, every information element of the record, keyed
					by its name in [IANA's registry](\(urls.iana_ipfix_elements)), such as
					`sourceIPv4Address` or `octetDeltaCount`, or by a `custom_elements` name. An
					element the source does not know is keyed by its number, such as `(35632/80)`,
					and its value is hexadecimal. An element a record holds more than once is keyed
					by an array of its values.

					Integers and floats are numbers, date-times are timestamps, and addresses and
					octet arrays are strings in their [RFC 7373](\(urls.rfc_7373)) textual form.
					"""
				required:    false
				type: "*": {}
			}
		}
	}

	examples: [
		{
			title: "A NetFlow v5 flow"
			configuration: {}
			input: """
				A NetFlow v5 datagram from 192.0.2.10 with one TCP flow from 192.0.2.1:443 to
				198.51.100.2:51000 of 10 packets and 1500 bytes.
				"""
			output: log: {
				sourceIPv4Address:           "192.0.2.1"
				destinationIPv4Address:      "198.51.100.2"
				sourceTransportPort:         443
				destinationTransportPort:    51000
				protocolIdentifier:          6
				tcpControlBits:              18
				packetDeltaCount:            10
				octetDeltaCount:             1500
				ingressInterface:            1
				egressInterface:             2
				flowStartMilliseconds:       "2023-11-14T22:13:10Z"
				flowEndMilliseconds:         "2023-11-14T22:13:19Z"
				originalExporterIPv4Address: "192.0.2.10"
				exporterTransportPort:       2055
				collectionTimeMilliseconds:  "2023-11-14T22:13:20.104Z"
				flow_type:                   "netflow_v5"
				host:                        "192.0.2.10"
				source_type:                 "netflow"
				timestamp:                   "2023-11-14T22:13:20.104Z"
			}
		},
		{
			title: "The same flow in the common format"
			configuration: {
				format: "common"
			}
			input: """
				A NetFlow v5 datagram from 192.0.2.10 with one TCP flow from 192.0.2.1:443 to
				198.51.100.2:51000 of 10 packets and 1500 bytes.
				"""
			output: log: {
				flow_type:       "netflow_v5"
				time_received:   "2023-11-14T22:13:20.104Z"
				sequence_num:    42
				sampler_address: "192.0.2.10"
				time_flow_start: "2023-11-14T22:13:10Z"
				time_flow_end:   "2023-11-14T22:13:19Z"
				bytes:           1500
				packets:         10
				src_addr:        "192.0.2.1"
				dst_addr:        "198.51.100.2"
				etype:           2048
				proto:           6
				src_port:        443
				dst_port:        51000
				in_if:           1
				out_if:          2
				tcp_flags:       18
				host:            "192.0.2.10"
				source_type:     "netflow"
				timestamp:       "2023-11-14T22:13:20.104Z"
			}
		},
	]

	how_it_works: {
		protocols: {
			title: "Protocols"
			body:  """
				With `family` set to `netflow`, the default, the source reads NetFlow v5,
				[NetFlow v9](\(urls.rfc_3954)), and [IPFIX](\(urls.rfc_7011)) on one port, telling
				them apart by the version at the start of each datagram. With `family` set to
				`sflow`, it reads [sFlow v5](\(urls.sflow_v5)), which exporters send to a port of its
				own. Run one source for each.

				Whatever the protocol, each flow is converted to a record of IPFIX information
				elements, so that flows from different exporters have the same fields. The source
				adds the exporter's address, the time the datagram was received, absolute flow start
				and end times in place of NetFlow's uptime-relative ones, and the sampling rate the
				exporter stated. Decoding is done by [rustflow](\(urls.rustflow)).
				"""
		}
		templates: {
			title: "Templates"
			body: """
				NetFlow v9 and IPFIX exporters describe their records with templates, which they
				send periodically. Data that arrives before its template, such as right after Vector
				starts, cannot be decoded and is dropped, unless the `pending` option is set to hold
				it until the template arrives. Templates are kept for each exporter's address, port,
				and observation domain, and expire `template_timeout_secs` after they were last
				received.
				"""
		}
		options_records: {
			title: "Options records"
			body: """
				NetFlow v9 and IPFIX exporters also send options records, which describe the
				exporter rather than flows: interface names, sampler configurations, and so on. The
				source applies the sampling they state to the flows that follow, and sends the
				records themselves to the `options` output.
				"""
		}
	}

	telemetry: metrics: {
		component_errors_total:                       components.sources.internal_metrics.output.metrics.component_errors_total
		component_received_bytes_total:               components.sources.internal_metrics.output.metrics.component_received_bytes_total
		component_received_events_total:              components.sources.internal_metrics.output.metrics.component_received_events_total
		component_received_event_bytes_total:         components.sources.internal_metrics.output.metrics.component_received_event_bytes_total
		netflow_exporter_last_seen_timestamp_seconds: components.sources.internal_metrics.output.metrics.netflow_exporter_last_seen_timestamp_seconds
		netflow_flows_processed_total:                components.sources.internal_metrics.output.metrics.netflow_flows_processed_total
		netflow_parse_errors_total:                   components.sources.internal_metrics.output.metrics.netflow_parse_errors_total
		netflow_received_bytes_total:                 components.sources.internal_metrics.output.metrics.netflow_received_bytes_total
		netflow_received_packets_total:               components.sources.internal_metrics.output.metrics.netflow_received_packets_total
		netflow_unknown_version_packets_total:        components.sources.internal_metrics.output.metrics.netflow_unknown_version_packets_total
	}
}
