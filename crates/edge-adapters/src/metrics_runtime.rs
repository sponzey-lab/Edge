//! Loopback Prometheus listener and bounded in-process metric collector adapter.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use edge_application::{
    MetricRegistry, MetricSeriesValue, MetricSnapshot, METRIC_MAX_RESPONSE_BYTES,
};
use edge_domain::{AppError, ErrorCode, MetricsConfig};
use edge_ports::{MetricEvent, MetricPublishOutcome, MetricPublisher, StructuredLogEvent};

#[derive(Debug, Clone)]
pub struct MetricChannelPublisher {
    sender: SyncSender<MetricEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricCollectorState {
    Created,
    Running,
    Draining,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsListenerState {
    Disabled,
    Binding,
    Serving,
    Draining,
    Stopped,
    Failed,
}

pub struct MetricsListenerHandle {
    address: Option<SocketAddr>,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<MetricsListenerState>>,
    thread: Option<JoinHandle<()>>,
}

impl MetricsListenerHandle {
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.address
    }

    pub fn state(&self) -> MetricsListenerState {
        self.state
            .lock()
            .map(|state| *state)
            .unwrap_or(MetricsListenerState::Failed)
    }

    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MetricsListenerHandle {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

pub fn spawn_metrics_listener(
    config: &MetricsConfig,
    snapshot: MetricSnapshotReader,
    product_log: Option<SyncSender<StructuredLogEvent>>,
) -> io::Result<MetricsListenerHandle> {
    let stop = Arc::new(AtomicBool::new(false));
    let state = Arc::new(Mutex::new(if config.enabled {
        MetricsListenerState::Binding
    } else {
        MetricsListenerState::Disabled
    }));
    if !config.enabled {
        return Ok(MetricsListenerHandle {
            address: None,
            stop,
            state,
            thread: None,
        });
    }
    let address = config
        .bind
        .parse::<SocketAddr>()
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "invalid metrics bind"))?;
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "metrics bind must be loopback",
        ));
    }
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    let local_addr = listener.local_addr()?;
    let worker_stop = Arc::clone(&stop);
    let worker_state = Arc::clone(&state);
    let thread = thread::spawn(move || {
        run_metrics_listener(listener, snapshot, product_log, worker_stop, worker_state)
    });
    Ok(MetricsListenerHandle {
        address: Some(local_addr),
        stop,
        state,
        thread: Some(thread),
    })
}

fn run_metrics_listener(
    listener: TcpListener,
    snapshot: MetricSnapshotReader,
    product_log: Option<SyncSender<StructuredLogEvent>>,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<MetricsListenerState>>,
) {
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(16);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let receiver = Arc::clone(&receiver);
        let snapshot = snapshot.clone();
        let stop = Arc::clone(&stop);
        workers.push(thread::spawn(move || {
            while !stop.load(Ordering::Acquire) {
                let stream = receiver
                    .lock()
                    .ok()
                    .and_then(|receiver| receiver.recv_timeout(Duration::from_millis(25)).ok());
                if let Some(stream) = stream {
                    handle_metrics_connection(stream, &snapshot);
                }
            }
        }));
    }
    if let Ok(mut current) = state.lock() {
        *current = MetricsListenerState::Serving;
    }
    emit_metric_collector_log(&product_log, "metrics.listener.serving");
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = sender.try_send(stream);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(_) => {
                if let Ok(mut current) = state.lock() {
                    *current = MetricsListenerState::Failed;
                }
                break;
            }
        }
    }
    if state
        .lock()
        .is_ok_and(|current| *current != MetricsListenerState::Failed)
    {
        if let Ok(mut current) = state.lock() {
            *current = MetricsListenerState::Draining;
        }
    }
    drop(sender);
    for worker in workers {
        let _ = worker.join();
    }
    if state
        .lock()
        .is_ok_and(|current| *current != MetricsListenerState::Failed)
    {
        if let Ok(mut current) = state.lock() {
            *current = MetricsListenerState::Stopped;
        }
    }
    emit_metric_collector_log(&product_log, "metrics.listener.stopped");
}

fn handle_metrics_connection(mut stream: TcpStream, snapshot: &MetricSnapshotReader) {
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
    let timeout = Some(REQUEST_TIMEOUT);
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let read_deadline = Instant::now() + REQUEST_TIMEOUT;
    while request.len() <= 8 * 1024 && !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => request.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock && Instant::now() < read_deadline =>
            {
                thread::sleep(Duration::from_millis(1));
            }
            Err(_) => break,
        }
    }
    let line = std::str::from_utf8(&request)
        .ok()
        .and_then(|request| request.lines().next())
        .unwrap_or("");
    let mut request_parts = line.split_whitespace();
    let method = request_parts.next().unwrap_or("");
    let target = request_parts.next().unwrap_or("");
    let request_complete = request.windows(4).any(|window| window == b"\r\n\r\n");
    let (status, body) = if request.len() > 8 * 1024 {
        (431, String::new())
    } else if !request_complete || method.is_empty() || target.is_empty() {
        (400, String::new())
    } else if method == "GET" && target == "/metrics" {
        match encode_prometheus(&snapshot.snapshot()) {
            Ok(body) => (200, body),
            Err(_) => (500, String::new()),
        }
    } else if method == "GET" && target.starts_with("/metrics?") {
        (400, String::new())
    } else if method == "GET" {
        (404, String::new())
    } else {
        (405, String::new())
    };
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

#[derive(Clone)]
pub struct MetricSnapshotReader {
    snapshot: Arc<std::sync::RwLock<Arc<MetricSnapshot>>>,
    state: Arc<Mutex<MetricCollectorState>>,
}

pub struct MetricCollectorHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MetricCollectorHandle {
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MetricCollectorHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl MetricSnapshotReader {
    pub fn snapshot(&self) -> Arc<MetricSnapshot> {
        self.snapshot
            .read()
            .map(|snapshot| Arc::clone(&snapshot))
            .unwrap_or_else(|_| Arc::new(MetricSnapshot::default()))
    }

    pub fn state(&self) -> MetricCollectorState {
        self.state
            .lock()
            .map(|state| *state)
            .unwrap_or(MetricCollectorState::Failed)
    }
}

impl edge_application::MetricSnapshotReaderPort for MetricSnapshotReader {
    fn read_metric_snapshot(&self) -> Result<Arc<MetricSnapshot>, AppError> {
        Ok(self.snapshot())
    }
}

pub fn spawn_metric_registry_collector(
    receiver: Receiver<MetricEvent>,
    product_log: Option<SyncSender<StructuredLogEvent>>,
) -> (MetricSnapshotReader, MetricCollectorHandle) {
    let snapshot = Arc::new(std::sync::RwLock::new(Arc::new(MetricSnapshot::default())));
    let state = Arc::new(Mutex::new(MetricCollectorState::Created));
    let reader = MetricSnapshotReader {
        snapshot: Arc::clone(&snapshot),
        state: Arc::clone(&state),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let thread = thread::spawn(move || {
        if let Ok(mut current) = state.lock() {
            *current = MetricCollectorState::Running;
        }
        emit_metric_collector_log(&product_log, "metrics.collector.running");
        let mut registry = MetricRegistry::default();
        while !worker_stop.load(Ordering::Acquire) {
            match receiver.recv_timeout(Duration::from_millis(25)) {
                Ok(observation) => {
                    let _ = registry.observe(observation);
                    if let Ok(mut current) = snapshot.write() {
                        *current = Arc::new(registry.snapshot());
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        if let Ok(mut current) = state.lock() {
            *current = MetricCollectorState::Draining;
        }
        if let Ok(mut current) = state.lock() {
            *current = MetricCollectorState::Stopped;
        }
        emit_metric_collector_log(&product_log, "metrics.collector.stopped");
    });
    (
        reader,
        MetricCollectorHandle {
            stop,
            thread: Some(thread),
        },
    )
}

fn emit_metric_collector_log(publisher: &Option<SyncSender<StructuredLogEvent>>, event: &str) {
    if let Some(publisher) = publisher {
        let _ = publisher.try_send(StructuredLogEvent {
            component: "metrics-collector".to_string(),
            event: event.to_string(),
            fields: Vec::new(),
        });
    }
}

pub fn encode_prometheus(snapshot: &MetricSnapshot) -> Result<String, AppError> {
    let mut output = String::new();
    for descriptor in edge_ports::MetricDescriptor::ALL {
        let definition = descriptor.definition();
        output.push_str(&format!("# HELP {} {}\n", definition.name, definition.help));
        let kind = match definition.kind {
            edge_ports::MetricKind::Counter => "counter",
            edge_ports::MetricKind::Gauge => "gauge",
            edge_ports::MetricKind::Histogram => "histogram",
        };
        output.push_str(&format!("# TYPE {} {kind}\n", definition.name));
        for series in snapshot
            .series
            .iter()
            .filter(|series| series.key.descriptor == descriptor)
        {
            encode_metric_series(
                &mut output,
                definition.name,
                &series.key.labels,
                &series.value,
            );
        }
        if descriptor == edge_ports::MetricDescriptor::MetricEventsDroppedTotal {
            for (reason, count) in &snapshot.dropped {
                let reason = match reason {
                    edge_application::MetricDropReason::SeriesLimit => "series_limit",
                    edge_application::MetricDropReason::ResponseBudget => "response_budget",
                };
                encode_sample(
                    &mut output,
                    definition.name,
                    &[("reason".into(), reason.into())],
                    &count.to_string(),
                );
            }
        }
        if descriptor == edge_ports::MetricDescriptor::MetricsReady {
            encode_sample(
                &mut output,
                definition.name,
                &[],
                if snapshot.ready { "1" } else { "0" },
            );
        }
        if output.len() > METRIC_MAX_RESPONSE_BYTES {
            return Err(AppError::new(
                ErrorCode::InternalBug,
                "encoded metrics response exceeds 4 MiB",
            ));
        }
    }
    Ok(output)
}

fn encode_metric_series(
    output: &mut String,
    name: &str,
    labels: &[(String, String)],
    value: &MetricSeriesValue,
) {
    match value {
        MetricSeriesValue::Counter(value) => {
            encode_sample(output, name, labels, &value.to_string())
        }
        MetricSeriesValue::Gauge(value) => encode_sample(output, name, labels, &value.to_string()),
        MetricSeriesValue::Histogram(value) => {
            let boundaries = edge_ports::MetricDescriptor::RequestDuration
                .definition()
                .histogram_buckets_ms;
            for (index, count) in value.cumulative_buckets.iter().enumerate() {
                let le = boundaries
                    .get(index)
                    .map(|ms| format_seconds(*ms))
                    .unwrap_or_else(|| "+Inf".to_string());
                let mut bucket_labels = labels.to_vec();
                bucket_labels.push(("le".into(), le));
                bucket_labels.sort();
                encode_sample(
                    output,
                    &format!("{name}_bucket"),
                    &bucket_labels,
                    &count.to_string(),
                );
            }
            encode_sample(
                output,
                &format!("{name}_sum"),
                labels,
                &format_seconds(value.sum_ms),
            );
            encode_sample(
                output,
                &format!("{name}_count"),
                labels,
                &value.count.to_string(),
            );
        }
    }
}

fn encode_sample(output: &mut String, name: &str, labels: &[(String, String)], value: &str) {
    output.push_str(name);
    if !labels.is_empty() {
        output.push('{');
        for (index, (key, label_value)) in labels.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str(key);
            output.push_str("=\"");
            output.push_str(&prometheus_escape(label_value));
            output.push('"');
        }
        output.push('}');
    }
    output.push(' ');
    output.push_str(value);
    output.push('\n');
}

fn format_seconds(milliseconds: u64) -> String {
    format!("{}.{:03}", milliseconds / 1_000, milliseconds % 1_000)
}

fn prometheus_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

impl MetricChannelPublisher {
    pub fn new(sender: SyncSender<MetricEvent>) -> Self {
        Self { sender }
    }
}

impl MetricPublisher for MetricChannelPublisher {
    fn try_publish(&self, metric: MetricEvent) -> MetricPublishOutcome {
        match self.sender.try_send(metric) {
            Ok(()) => MetricPublishOutcome::Accepted,
            Err(TrySendError::Full(_)) => MetricPublishOutcome::Full,
            Err(TrySendError::Disconnected(_)) => MetricPublishOutcome::Stopped,
        }
    }
}
