package metadata

generated: components: sources: netflow: configuration: {
	address: {
		description: """
			The socket address to listen for connections on, or `systemd{#N}` to use the Nth socket passed by
			systemd socket activation.

			If a socket address is used, it _must_ include a port.
			"""
		required: true
		type: string: examples: ["0.0.0.0:9000", "systemd", "systemd#3"]
	}
	custom_elements: {
		description: """
			Information elements to decode besides IANA's, such as an exporter's enterprise-specific
			elements.

			An element of an enterprise number and ID that IANA's registry or an earlier entry already
			has replaces it. Elements not listed are decoded as octet arrays and named by their
			number, such as `(35632/80)`.
			"""
		required: false
		type: array: {
			default: []
			items: type: object: options: {
				data_type: {
					description: """
						The data type of an information element's values, as IANA's IPFIX data types registry names
						them.
						"""
					required: true
					type: string: enum: {
						boolean:                "A boolean."
						date_time_microseconds: "A time, as an NTP timestamp of microsecond precision."
						date_time_milliseconds: "A time, in milliseconds since the UNIX epoch."
						date_time_nanoseconds:  "A time, as an NTP timestamp of nanosecond precision."
						date_time_seconds:      "A time, in seconds since the UNIX epoch."
						float32:                "A single-precision floating-point number."
						float64:                "A double-precision floating-point number."
						ipv4_address:           "An IPv4 address."
						ipv6_address:           "An IPv6 address."
						mac_address:            "A MAC address."
						octet_array:            "Bytes, written as hexadecimal."
						signed16:               "A signed 16-bit integer."
						signed32:               "A signed 32-bit integer."
						signed64:               "A signed 64-bit integer."
						signed8:                "A signed 8-bit integer."
						string:                 "A UTF-8 string."
						unsigned16:             "An unsigned 16-bit integer."
						unsigned32:             "An unsigned 32-bit integer."
						unsigned64:             "An unsigned 64-bit integer."
						unsigned8:              "An unsigned 8-bit integer."
					}
				}
				enterprise_number: {
					description: """
						The private enterprise number of the vendor that defines the element.

						`0` stands for IANA, for an element IANA's registry does not have yet.
						"""
					required: true
					type: uint: examples: [35632]
				}
				id: {
					description: "The element's ID within its enterprise."
					required:    true
					type: uint: examples: [80]
				}
				name: {
					description: "The name the element's values are keyed by."
					required:    true
					type: string: examples: ["ntopL7Protocol"]
				}
			}
		}
	}
	family: {
		description: """
			The flow protocols to listen for.

			NetFlow and IPFIX share the version field at the start of a datagram, so one port serves all
			three; sFlow has a port of its own.
			"""
		required: false
		type: string: {
			default: "netflow"
			enum: {
				netflow: "NetFlow v5, NetFlow v9, and IPFIX, told apart by the version of each datagram."
				sflow:   "sFlow v5."
			}
		}
	}
	format: {
		description: "The fields of the events flow records are decoded into."
		required:    false
		type: string: {
			default: "ipfix"
			enum: {
				common: """
					A fixed set of fields, such as `src_addr`, `dst_port`, `bytes`, and `sampling_rate`, mapped
					from the record's elements whatever protocol the flow arrived in.

					Elements outside that set are left out.
					"""
				ipfix: """
					The record's IPFIX information elements, keyed by name, such as `sourceIPv4Address` and
					`octetDeltaCount`, whatever protocol the flow arrived in.

					Every element the exporter sent is kept, along with the elements the collector adds:
					the exporter's address, the collection time, absolute flow start and end times, and the
					sampling the exporter stated.
					"""
			}
		}
	}
	host_key: {
		description: """
			Overrides the name of the log field used to add the exporter's IP address to each event.

			By default, the [global `log_schema.host_key` option][global_host_key] is used.

			Set to `""` to suppress this key.

			[global_host_key]: https://vector.dev/docs/reference/configuration/global-options/#log_schema.host_key
			"""
		required: false
		type: string: {}
	}
	pending: {
		description: """
			Holds NetFlow v9 and IPFIX data that arrives before its template.

			When set, data sets whose template has not been received yet are held, and decoded once the
			template arrives. When not set, such data is dropped. Data held past either limit is dropped.

			An exporter that reuses a template ID for another template while data for the old one is held
			gets that data decoded with the new template; a short `max_age_secs` narrows that window.
			"""
		required: false
		type: object: options: {
			max_age_secs: {
				description: "The maximum time, in seconds, a datagram is held waiting for its template."
				required:    false
				type: uint: {
					default: 60
					unit:    "seconds"
				}
			}
			max_bytes: {
				description: "The maximum size of the datagrams held for each protocol of an exporter."
				required:    false
				type: uint: {
					default: 1048576
					unit:    "bytes"
				}
			}
		}
	}
	receive_buffer_bytes: {
		description: "The size of the receive buffer used for the listening socket."
		required:    false
		type: uint: unit: "bytes"
	}
	template_timeout_secs: {
		description: """
			The time, in seconds, a NetFlow v9 or IPFIX template is kept after it was last received.

			Data that arrives after its template has expired cannot be decoded until the exporter
			sends the template again. Exporters resend their templates periodically; this should be
			longer than that interval.
			"""
		required: false
		type: uint: {
			default: 1800
			unit:    "seconds"
		}
	}
}
