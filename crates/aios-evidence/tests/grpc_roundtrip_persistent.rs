//! T-012 — end-to-end gRPC roundtrip integration test against the
//! `RocksDbEvidenceLog` persistent backend.
//!
//! Mirrors `grpc_roundtrip.rs` (the in-memory backend's roundtrip suite)
//! but instantiates [`RocksDbEvidenceLog`] over a `TempDir`. Both backends
//! share the same `EvidenceLog` trait so the wire-level behaviour MUST be
//! identical — that's the contract this test pins.

#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "test code; panic-on-failure is the idiomatic test signal"
)]

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tonic::transport::Server;

use aios_evidence::persistence::RocksDbEvidenceLog;
use aios_evidence::service::proto::evidence_log_client::EvidenceLogClient;
use aios_evidence::service::proto::evidence_log_server::EvidenceLogServer;
use aios_evidence::service::proto::{
    AppendRequest, QueryRequest, ReadReceiptRequest, RebuildIndexRequest, RecordType,
    SubscribeRequest, VerifyChainRequest,
};

async fn pick_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    addr
}

fn test_backend(seed: u8) -> (RocksDbEvidenceLog, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let b = RocksDbEvidenceLog::open(dir.path(), sk).expect("open");
    (b, dir)
}

async fn spawn_server(
    backend: RocksDbEvidenceLog,
) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let addr = pick_port().await;
    let (tx, rx) = oneshot::channel::<()>();
    let server = Server::builder().add_service(EvidenceLogServer::new(backend));
    let handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = rx.await;
        };
        server
            .serve_with_shutdown(addr, shutdown)
            .await
            .expect("server should serve");
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    (addr, tx, handle)
}

fn append_request(rt: RecordType, subject: &str) -> AppendRequest {
    AppendRequest {
        schema_version: "aios.evidence.v1alpha1".to_owned(),
        payload: None,
        record_type: i32::from(rt),
        subject: subject.to_owned(),
        action_id: String::new(),
        correlation_id: String::new(),
        trace_id: String::new(),
        simulated: false,
    }
}

// -----------------------------------------------------------------------
// 1. Happy-path roundtrip across every RPC against RocksDB.
// -----------------------------------------------------------------------

#[tokio::test]
async fn grpc_evidence_log_full_roundtrip_over_rocksdb() {
    let (backend, _dir) = test_backend(201);
    let (addr, shutdown, handle) = spawn_server(backend).await;

    let endpoint = format!("http://{addr}");
    let mut client = EvidenceLogClient::connect(endpoint.clone())
        .await
        .expect("client connect");

    let mut minted_ids = Vec::new();
    for i in 0..5_u32 {
        let rt = if i % 2 == 0 {
            RecordType::ActionReceived
        } else {
            RecordType::PolicyDecision
        };
        let r = client
            .append(append_request(rt, &format!("human:operator-{i}")))
            .await
            .expect("append rpc")
            .into_inner();
        assert!(r.receipt_id.starts_with("evr_"));
        if i == 0 {
            assert!(r.previous_receipt_hash.is_empty());
        } else {
            assert_eq!(r.previous_receipt_hash.len(), 32);
        }
        minted_ids.push(r.receipt_id);
    }
    assert_eq!(minted_ids.len(), 5);

    for id in &minted_ids {
        let r = client
            .read_receipt(ReadReceiptRequest {
                receipt_id: id.clone(),
            })
            .await
            .expect("read rpc")
            .into_inner();
        assert_eq!(&r.receipt_id, id);
    }

    let miss = client
        .read_receipt(ReadReceiptRequest {
            receipt_id: "evr_does_not_exist_zzz".to_owned(),
        })
        .await
        .expect_err("must miss");
    assert_eq!(miss.code(), tonic::Code::NotFound);

    let q_all = client
        .query(QueryRequest {
            record_types_filter: vec![],
            subject_filter: String::new(),
            correlation_id_filter: String::new(),
            action_id_filter: String::new(),
            from_time: None,
            to_time: None,
            text_match: String::new(),
            limit: 0,
            subject: String::new(),
            caller_primary_group: String::new(),
            caller_is_ai: false,
            caller_is_recovery_mode: false,
        })
        .await
        .expect("query rpc")
        .into_inner();
    let q_all_collected: Vec<_> = q_all.collect::<Vec<_>>().await;
    assert_eq!(q_all_collected.len(), 5);

    let q_filtered = client
        .query(QueryRequest {
            record_types_filter: vec![i32::from(RecordType::PolicyDecision)],
            subject_filter: String::new(),
            correlation_id_filter: String::new(),
            action_id_filter: String::new(),
            from_time: None,
            to_time: None,
            text_match: String::new(),
            limit: 0,
            subject: String::new(),
            caller_primary_group: String::new(),
            caller_is_ai: false,
            caller_is_recovery_mode: false,
        })
        .await
        .expect("query rpc")
        .into_inner();
    let q_filtered_collected: Vec<_> = q_filtered.collect::<Vec<_>>().await;
    assert_eq!(q_filtered_collected.len(), 2);

    let verify = client
        .verify_chain(VerifyChainRequest {
            segment_id_from: String::new(),
            segment_id_to: String::new(),
        })
        .await
        .expect("verify rpc")
        .into_inner();
    assert!(verify.consistent);
    assert_eq!(verify.receipts_checked, 5);

    let rebuild = client
        .rebuild_index(RebuildIndexRequest {
            include_full_text: false,
        })
        .await
        .expect("rebuild rpc")
        .into_inner();
    // record_type_index has one row per append; 5 receipts -> 5 rows.
    assert_eq!(rebuild.receipts_indexed, 5);

    let info = client
        .get_log_info(())
        .await
        .expect("info rpc")
        .into_inner();
    assert!(info.log_id.starts_with("aios-evidence-log/"));
    assert_eq!(info.active_segment_record_count, 5);
    assert!(!info.degraded);

    drop(client);
    shutdown.send(()).expect("shutdown signal sends");
    handle.await.expect("server task joins cleanly");
}

// -----------------------------------------------------------------------
// 2. Subscribe replay + live event over RocksDB backend.
// -----------------------------------------------------------------------

#[tokio::test]
async fn grpc_subscribe_replays_then_streams_live_over_rocksdb() {
    let (backend, _dir) = test_backend(202);
    let (addr, shutdown, handle) = spawn_server(backend.clone()).await;

    let endpoint = format!("http://{addr}");
    let mut client = EvidenceLogClient::connect(endpoint.clone())
        .await
        .expect("client connect");

    let mut ids = Vec::new();
    for i in 0..3_u32 {
        let r = client
            .append(append_request(
                RecordType::ActionReceived,
                &format!("human:operator-{i}"),
            ))
            .await
            .expect("append rpc")
            .into_inner();
        ids.push(r.receipt_id);
    }

    let bookmark = ids[1].clone();
    let stream = client
        .subscribe(SubscribeRequest {
            record_types_filter: vec![],
            subject_filter: String::new(),
            correlation_id_filter: String::new(),
            resume_from_receipt_id: bookmark,
            max_buffered: 0,
            caller_subject: String::new(),
            caller_primary_group: String::new(),
            caller_is_ai: false,
            caller_is_recovery_mode: false,
        })
        .await
        .expect("subscribe rpc")
        .into_inner();

    let mut prod_client = EvidenceLogClient::connect(endpoint)
        .await
        .expect("producer connect");
    let producer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(80)).await;
        prod_client
            .append(append_request(RecordType::PolicyDecision, "service:policy"))
            .await
            .expect("live append");
    });

    // Generous budget: loaded CI runners exceeded a tight 800ms window
    let collected = tokio::time::timeout(Duration::from_secs(10), async move {
        let mut s = stream;
        let mut out = Vec::new();
        while let Some(item) = s.next().await {
            out.push(item.expect("ok"));
            if out.len() == 2 {
                break;
            }
        }
        out
    })
    .await
    .expect("did not hang");

    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0].receipt_id, ids[2]);
    assert_eq!(
        collected[1].record_type,
        i32::from(RecordType::PolicyDecision)
    );

    producer.await.expect("producer completes");
    drop(client);
    shutdown.send(()).expect("shutdown signal sends");
    handle.await.expect("server task joins");
}

// -----------------------------------------------------------------------
// 3. Receipts persisted via gRPC survive a backend restart.
// -----------------------------------------------------------------------

#[tokio::test]
async fn receipts_persisted_via_grpc_survive_restart() {
    let dir = TempDir::new().expect("tempdir");
    let sk = SigningKey::from_bytes(&[203u8; 32]);

    // Phase 1: open + spawn server + append.
    let phase1_ids: Vec<String> = {
        let b = RocksDbEvidenceLog::open(dir.path(), sk.clone()).expect("open p1");
        let (addr, shutdown, handle) = spawn_server(b).await;
        let endpoint = format!("http://{addr}");
        let mut client = EvidenceLogClient::connect(endpoint).await.expect("connect");
        let mut ids = Vec::new();
        for i in 0..4_u32 {
            let r = client
                .append(append_request(
                    RecordType::ActionReceived,
                    &format!("human:operator-{i}"),
                ))
                .await
                .expect("append")
                .into_inner();
            ids.push(r.receipt_id);
        }
        drop(client);
        shutdown.send(()).expect("shutdown");
        handle.await.expect("server joins");
        ids
    };

    // Phase 2: reopen the same path with the same key; serve again; read.
    let b2 = RocksDbEvidenceLog::open(dir.path(), sk).expect("open p2");
    let (addr, shutdown, handle) = spawn_server(b2).await;
    let endpoint = format!("http://{addr}");
    let mut client = EvidenceLogClient::connect(endpoint)
        .await
        .expect("p2 connect");
    for id in &phase1_ids {
        let back = client
            .read_receipt(ReadReceiptRequest {
                receipt_id: id.clone(),
            })
            .await
            .expect("read after restart")
            .into_inner();
        assert_eq!(&back.receipt_id, id);
    }
    drop(client);
    shutdown.send(()).expect("shutdown p2");
    handle.await.expect("server p2 joins");
}

// -----------------------------------------------------------------------
// 4. Append rejects malformed inputs over the wire (parity with in-memory).
// -----------------------------------------------------------------------

#[tokio::test]
async fn grpc_append_rejects_unspecified_record_type_and_empty_subject_over_rocksdb() {
    let (backend, _dir) = test_backend(204);
    let (addr, shutdown, handle) = spawn_server(backend).await;

    let endpoint = format!("http://{addr}");
    let mut client = EvidenceLogClient::connect(endpoint.clone())
        .await
        .expect("connect");

    let err = client
        .append(AppendRequest {
            schema_version: "aios.evidence.v1alpha1".to_owned(),
            payload: None,
            record_type: 0,
            subject: "human:operator-1".to_owned(),
            action_id: String::new(),
            correlation_id: String::new(),
            trace_id: String::new(),
            simulated: false,
        })
        .await
        .expect_err("must reject");
    assert_eq!(err.code(), tonic::Code::Internal);

    let err = client
        .append(append_request(RecordType::ActionReceived, ""))
        .await
        .expect_err("must reject");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    drop(client);
    shutdown.send(()).expect("shutdown signal sends");
    handle.await.expect("server task joins");
}
