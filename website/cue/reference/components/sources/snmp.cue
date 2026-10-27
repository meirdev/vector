package metadata

components: sources: snmp: {
	title: "SNMP"

	classes: {
		delivery:      "at_least_once"
		deployment_roles: ["aggregator", "daemon"]
		development:   "beta"
		egress_method: "batch"
		stateful:      false
	}

	features: {
		acknowledgements: false
		collect: {
			checkpoint: enabled: false
			from: {
				service: services.snmp

				interface: {
					socket: {
						api: {
							title: "SNMP"
							url:   urls.snmp
						}
						direction: "outgoing"
						protocols: ["udp"]
						ssl: "disabled"
					}
				}
			}
			proxy: enabled: false
		}
		multiline: enabled: false
	}

	support: {
		requirements: [
			"OIDs must be configured in dotted numeric form. MIB names are not resolved.",
		]

		warnings: []
	}

	installation: {
		platform_name: null
	}

	configuration: generated.components.sources.snmp.configuration

	how_it_works: {
		polling: {
			title: "Polling"
			body:  """
				On every scrape interval, the source polls all endpoints concurrently.
				Scalar `fields` are fetched with GET requests. Each table column is walked
				with GETBULK requests for SNMP `v2c` and `v3`, and with GETNEXT requests for `v1`.

				Each request is retried up to `retries` times on a new session when it times out.
				A table is skipped for a poll if any of its columns cannot be walked, so that rows
				never miss their tag columns.
				"""
		}
		metric_names: {
			title: "Metric names and tags"
			body:  """
				A scalar field produces a metric named after the field. A table column produces a
				metric named after the table and the column, joined with an underscore, such as
				`interface_in_octets`. Every metric uses the configured `namespace`.

				Fields and columns with `is_tag` set become tags instead of metrics. Scalar tags
				are added to every scalar metric, and to table metrics whose table lists them in
				`inherit_tags`. Table tag columns are added to the metrics of the same row, along
				with the row index in the tag set by `index_tag`.
				"""
		}
		value_types: {
			title: "Value types"
			body:  """
				`Counter32` and `Counter64` values become counters. `Integer`, `Gauge32`,
				`Unsigned32`, and `TimeTicks` values become gauges. Set `metric_type` to override
				this.

				Metric values must be numeric. Octet strings can be used as tags, or converted to
				numbers with the `int` and `float` conversions. Printable UTF-8 octet strings are
				used as is, and any other octet strings are hex-encoded, so they can be decoded in
				a `remap` transform with `decode_base16`. Use the `hwaddr` and `ipaddr`
				conversions to format hardware and IP addresses.
				"""
		}
	}

	output: metrics: {
		up: {
			description:       "Whether the agent responded to at least one request during the poll."
			type:              "gauge"
			default_namespace: "snmp"
			tags: {
				endpoint: {
					description: "The endpoint of the agent, as configured. The tag name is set by `endpoint_tag`."
					required:    false
					examples: ["udp://192.168.1.1:161"]
				}
			}
		}
	}

	telemetry: metrics: {
		collect_completed_total:  components.sources.internal_metrics.output.metrics.collect_completed_total
		collect_duration_seconds: components.sources.internal_metrics.output.metrics.collect_duration_seconds
	}
}
