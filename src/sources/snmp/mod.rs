//! The `snmp` source polls SNMP agents and emits the values it collects as metrics.

use std::time::{Duration, Instant};

use futures::{StreamExt, stream::FuturesUnordered};
use tokio::time::{self, Interval, MissedTickBehavior};
use tokio_stream::wrappers::IntervalStream;
use vector_lib::EstimatedJsonEncodedSizeOf;

use crate::{
    config::SourceContext,
    event::metric::Metric,
    internal_events::{
        CollectionCompleted, EndpointBytesReceived, SnmpEventsReceived, SnmpRequestError,
        SnmpValueError, StreamClosedError,
    },
};

mod config;
mod convert;
mod poller;

pub use config::SnmpConfig;
use poller::{Agent, PollPlan, up_metric};

fn run(
    mut agents: Vec<Agent>,
    plan: PollPlan,
    interval: Duration,
    cx: SourceContext,
) -> crate::sources::Source {
    let SourceContext {
        shutdown, mut out, ..
    } = cx;
    Box::pin(async move {
        let mut ticks = IntervalStream::new(poll_timer(interval)).take_until(shutdown.clone());
        while ticks.next().await.is_some() {
            let start = Instant::now();
            // Each agent's batch is sent as soon as it is ready, so a slow or unreachable agent
            // does not delay the others.
            let mut pending: FuturesUnordered<_> = agents
                .iter_mut()
                .map(|agent| collect(agent, &plan))
                .collect();
            loop {
                // A poll can take several timeouts and retries per request against a silent
                // agent, so shutdown must interrupt it rather than wait for the next tick.
                let metrics = tokio::select! {
                    next = pending.next() => match next {
                        Some(metrics) => metrics,
                        None => break,
                    },
                    _ = shutdown.clone() => return Ok(()),
                };
                let count = metrics.len();
                if let Err(error) = out.send_batch(metrics).await {
                    emit!(StreamClosedError { count });
                    return Err(error.into());
                }
            }
            emit!(CollectionCompleted {
                start,
                end: Instant::now()
            });
        }
        Ok(())
    })
}

/// Creates the poll timer.
///
/// When a poll runs past the next tick, that tick is skipped instead of being fired right away to
/// catch up, so polls stay aligned to the interval and never run back to back.
fn poll_timer(interval: Duration) -> Interval {
    let mut timer = time::interval(interval);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    timer
}

async fn collect(agent: &mut Agent, plan: &PollPlan) -> Vec<Metric> {
    let outcome = agent.poll(plan).await;
    let endpoint = agent.endpoint.as_str();

    for error in outcome.request_errors {
        emit!(SnmpRequestError {
            error: &error,
            endpoint,
        });
    }
    for error in outcome.value_errors {
        emit!(SnmpValueError {
            field: &error.field,
            reason: &error.reason,
            endpoint,
        });
    }
    if outcome.bytes > 0 {
        emit!(EndpointBytesReceived {
            byte_size: outcome.bytes,
            protocol: "udp",
            endpoint,
        });
    }

    let mut metrics = outcome.metrics;
    metrics.push(up_metric(plan, endpoint, outcome.reachable));
    let byte_size = metrics.estimated_json_encoded_size_of();
    emit!(SnmpEventsReceived {
        count: metrics.len(),
        byte_size,
        endpoint,
    });
    metrics
}

#[cfg(all(test, feature = "snmp-integration-tests"))]
mod integration_tests;
#[cfg(test)]
mod tests;
