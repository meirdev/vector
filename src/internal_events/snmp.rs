use vector_lib::{
    NamedInternalEvent, counter,
    internal_event::{CounterName, InternalEvent, error_stage, error_type},
    json_size::JsonSize,
};

#[derive(Debug, NamedInternalEvent)]
pub struct SnmpEventsReceived<'a> {
    pub byte_size: JsonSize,
    pub count: usize,
    pub endpoint: &'a str,
}

impl InternalEvent for SnmpEventsReceived<'_> {
    fn emit(self) {
        trace!(
            message = "Events received.",
            byte_size = %self.byte_size,
            count = %self.count,
            endpoint = self.endpoint,
        );
        counter!(
            CounterName::ComponentReceivedEventsTotal,
            "endpoint" => self.endpoint.to_owned(),
        )
        .increment(self.count as u64);
        counter!(
            CounterName::ComponentReceivedEventBytesTotal,
            "endpoint" => self.endpoint.to_owned(),
        )
        .increment(self.byte_size.get() as u64);
    }
}

#[derive(Debug, NamedInternalEvent)]
pub struct SnmpRequestError<'a, E> {
    pub error: &'a E,
    pub endpoint: &'a str,
}

impl<E: std::fmt::Display> InternalEvent for SnmpRequestError<'_, E> {
    fn emit(self) {
        error!(
            message = "SNMP request failed.",
            endpoint = %self.endpoint,
            error = %self.error,
            error_type = error_type::REQUEST_FAILED,
            stage = error_stage::RECEIVING,
        );
        counter!(
            CounterName::ComponentErrorsTotal,
            "endpoint" => self.endpoint.to_owned(),
            "error_type" => error_type::REQUEST_FAILED,
            "stage" => error_stage::RECEIVING,
        )
        .increment(1);
    }
}

#[derive(Debug, NamedInternalEvent)]
pub struct SnmpValueError<'a> {
    pub field: &'a str,
    pub reason: &'a str,
    pub endpoint: &'a str,
}

impl InternalEvent for SnmpValueError<'_> {
    fn emit(self) {
        error!(
            message = "Failed to convert SNMP value.",
            endpoint = %self.endpoint,
            field = %self.field,
            error = %self.reason,
            error_type = error_type::CONVERSION_FAILED,
            stage = error_stage::PROCESSING,
        );
        counter!(
            CounterName::ComponentErrorsTotal,
            "endpoint" => self.endpoint.to_owned(),
            "error_type" => error_type::CONVERSION_FAILED,
            "stage" => error_stage::PROCESSING,
        )
        .increment(1);
    }
}
