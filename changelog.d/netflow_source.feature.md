Add a new `netflow` source that collects flow records from NetFlow v5, NetFlow v9, IPFIX, and sFlow v5 exporters over UDP. Each flow becomes a log event, keyed either by IPFIX information element names or by a fixed set of common fields. NetFlow v9 and IPFIX options records go to a separate `options` output. Per-exporter metrics count received datagrams and bytes, processed flows, parse errors, and unknown protocol versions, and a gauge records when each exporter was last seen.

authors: meirdev
