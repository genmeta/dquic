use std::sync::Arc;

use qbase::cid::ConnectionId;
use qevent::{
    BeEventData, CommonFields, Event, EventData, EventImportance, GroupID, ProtocolType,
    ProtocolTypeList, ReferenceTime, TimeFormat, build, event, legacy,
    loglevel::Warning,
    quic::{ConnectionID, connectivity::ConnectionStarted},
    span,
    telemetry::ExportEvent,
};

#[test]
fn custom_fields() {
    let odcid = ConnectionID::from(ConnectionId::from_slice(&[
        0x61, 0xb6, 0x91, 0x78, 0x80, 0xf7, 0x95, 0xee,
    ]));
    let common_fields = build!(CommonFields {
        path: "".to_owned(),
        time_format: TimeFormat::default(),
        reference_time: ReferenceTime::default(),
        protocol_types: ProtocolTypeList::from(vec![ProtocolType::quic()]),
        group_id: GroupID::from(odcid),
    });
    let expect = r#"{
  "path": "",
  "time_format": "relative_to_epoch",
  "reference_time": {
    "clock_type": "system",
    "epoch": "1970-01-01T00:00:00.000Z"
  },
  "protocol_types": [
    "QUIC"
  ],
  "group_id": "61b6917880f795ee"
}"#;
    assert_eq!(
        serde_json::to_string_pretty(&common_fields).unwrap(),
        expect
    );
    let with_custom_fields = r#"{
  "path": "",
  "time_format": "relative_to_epoch",
  "reference_time": {
    "clock_type": "system",
    "epoch": "1970-01-01T00:00:00.000Z"
  },
  "protocol_types": [
    "QUIC"
  ],
  "group_id": "61b6917880f795ee",
  "pathway": "from A to relay",
  "customB": "some other extensions"
}"#;
    let des = serde_json::from_str::<CommonFields>(with_custom_fields).unwrap();
    let filed_string = serde_json::to_string_pretty(&des).unwrap();
    let des2 = serde_json::from_str::<CommonFields>(&filed_string).unwrap();
    assert_eq!(des, des2);
}

#[test]
fn event_data() {
    let data = EventData::from(build!(Warning {
        message: "deepseek（已深度思考（用时0秒））：服务器繁忙，请稍后再试。",
        code: 255u64,
    }));
    let event = build!(Event {
        time: 1.0,
        data: data.clone(),
    });
    let expect = r#"{
  "time": 1.0,
  "name": "loglevel:warning",
  "data": {
    "code": 255,
    "message": "deepseek（已深度思考（用时0秒））：服务器繁忙，请稍后再试。"
  }
}"#;
    assert_eq!(serde_json::to_string_pretty(&event).unwrap(), expect);
    assert_eq!(data.importance(), EventImportance::Base);
}

#[test]
fn rollback() {
    fn group_id() -> GroupID {
        GroupID::from(ConnectionID::from(ConnectionId::from_slice(&[
            0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x32,
        ])))
    }

    fn protocol_types() -> Vec<String> {
        vec!["QUIC".to_owned(), "UNKNOW".to_owned()]
    }

    struct TestBroker;

    impl ExportEvent for TestBroker {
        fn emit(&self, event: Event) {
            let legacy = legacy::Event::try_from(event).unwrap();
            let event = serde_json::to_value(legacy).unwrap();

            let data = serde_json::json!({
                "ip_version": "v4",
                "src_ip": "127.0.0.1",
                "dst_ip": "192.168.31.1",
                "protocol": "QUIC",
                "src_port": 23456,
                "dst_port": 21
            });
            // in 10: this callde protocol_types
            let protocol_type = serde_json::json!(["QUIC", "UNKNOW"]);

            assert_eq!(event["data"], data);
            assert_eq!(event["protocol_types"], serde_json::Value::Null);
            assert_eq!(event["protocol_type"], protocol_type);
            assert_eq!(event["to_router"], true);
        }
    }

    span!(
        Arc::new(TestBroker),
        group_id = group_id(),
        protocol_types = protocol_types()
    )
    .in_scope(|| {
        let src = "127.0.0.1:23456".parse().unwrap();
        let dst = "192.168.31.1:21".parse().unwrap();
        event!(ConnectionStarted { socket: (src, dst) }, to_router = true)
    })
}
