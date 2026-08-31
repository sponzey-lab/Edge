//! Pure structured-log JSON line rendering.

use edge_ports::StructuredLogEvent;

pub(crate) fn render_log_json_line(event: &StructuredLogEvent) -> String {
    let fields = event
        .fields
        .iter()
        .map(|(key, value)| format!("\"{}\":\"{}\"", json_escape(key), json_escape(value)))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"component\":\"{}\",\"event\":\"{}\",\"fields\":{{{}}}}}",
        json_escape(&event.component),
        json_escape(&event.event),
        fields
    )
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped
}
