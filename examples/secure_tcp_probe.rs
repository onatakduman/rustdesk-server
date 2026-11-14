//! Probe for the secure TCP key exchange of hbbs. A test tool, not part of the server.
//!
//! It talks to a rendezvous server the way RustDesk client 1.5.3 does. The handshake
//! is ported from the client (src/common.rs: `key_exchange`, `create_symmetric_key_msg`,
//! `get_next_nonkeyexchange_msg`; src/client.rs: `_start_inner`;
//! src/rendezvous_mediator.rs: `handle_intranet_`, `handle_punch_hole`) and runs on the
//! hbb_common this server is built with. Clients 1.2.6 to 1.4.x send the same bytes.
//!
//!   cargo run --example secure_tcp_probe -- <mode> <host:port> <server public key>
//!
//!   secure      a client with an access token: key exchange, then an encrypted
//!               PunchHoleRequest for an id that is not registered, and a NAT type test
//!   plain       a client without a token: the same request, no key exchange
//!   bad         wrong answers to the key exchange, the server has to drop them
//!   nat         the NAT type test in plain, on the main port and on the NAT test port
//!               (the latter not from 127.0.0.1, where that port is the admin console)
//!   ws          the plain request over the WebSocket port, which has no key exchange
//!   e2e-secure  a whole punch hole round and a relay round between two simulated
//!   e2e-plain   clients. These register a throwaway id over UDP: test servers only.

use hbb_common::{
    anyhow::{anyhow, Context},
    bail,
    bytes::Bytes,
    config::{Config, CONNECT_TIMEOUT, READ_TIMEOUT},
    futures::{SinkExt, StreamExt},
    message_proto::IdPk,
    protobuf::{Message as _, UnknownValueRef},
    rendezvous_proto::{rendezvous_message::Union, *},
    tcp::FramedStream,
    timeout, tokio,
    udp::FramedSocket,
    AddrMangle, ResultType,
};
use sodiumoxide::crypto::{box_, secretbox, sign};

const CLIENT_VERSION: &str = "1.5.3";
const TOKEN: &str = "probe-access-token";
const UNKNOWN_ID: &str = "nosuchpeer";

// src/common.rs: get_pk
fn get_pk(pk: &[u8]) -> Option<[u8; 32]> {
    pk.try_into().ok()
}

// src/common.rs: get_rs_pk
fn get_rs_pk(str_base64: &str) -> Option<sign::PublicKey> {
    get_pk(&base64::decode(str_base64).ok()?).map(sign::PublicKey)
}

// src/common.rs: create_symmetric_key_msg
fn create_symmetric_key_msg(their_pk_b: [u8; 32]) -> (Bytes, Bytes, secretbox::Key) {
    let their_pk_b = box_::PublicKey(their_pk_b);
    let (our_pk_b, out_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &out_sk_b);
    (Vec::from(our_pk_b.0).into(), sealed_key.into(), key)
}

/// src/common.rs: `key_exchange`, which is what `secure_tcp` runs. `Ok(Some(key))` once
/// the stream is encrypted, `Ok(None)` when the server sent something else first.
/// `tamper` is not in the client: it lets the `bad` mode spoil the answer.
async fn key_exchange(
    conn: &mut FramedStream,
    key: &str,
    tamper: fn(&mut Vec<Bytes>),
) -> ResultType<Option<secretbox::Key>> {
    let Some(rs_pk) = get_rs_pk(key) else {
        bail!("Handshake failed: invalid public key from rendezvous server");
    };
    if let Some(Ok(bytes)) = timeout(READ_TIMEOUT, conn.next()).await? {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
            if let Some(Union::KeyExchange(ex)) = msg_in.union {
                if ex.keys.len() != 1 {
                    bail!("Handshake failed: invalid key exchange message");
                }
                let their_pk_b = sign::verify(&ex.keys[0], &rs_pk)
                    .map_err(|_| anyhow!("Signature mismatch in key exchange"))?;
                let their_pk_b =
                    get_pk(&their_pk_b).context("Wrong their public length in key exchange")?;
                // 1.5.3 only runs its versioned exchange when the server marks its key
                // (bit 255) or sends `version` (field 2) or `signed_params` (field 3).
                // The proto of this build is older, so those would be unknown fields.
                let (mut version, mut signed_params) = (0, false);
                for (number, value) in ex.special_fields.unknown_fields().iter() {
                    match (number, value) {
                        (2, UnknownValueRef::Varint(v)) => version = v,
                        (3, UnknownValueRef::LengthDelimited(b)) => signed_params = !b.is_empty(),
                        _ => {}
                    }
                }
                println!(
                    "  server KeyExchange: {} key, signature verifies against the server key, \
                     box pk bit 255 = {}, version = {}, signed_params = {}",
                    ex.keys.len(),
                    their_pk_b[31] >> 7,
                    version,
                    signed_params
                );
                if their_pk_b[31] & 0x80 != 0 || signed_params || version != 0 {
                    bail!("the server offers a versioned key exchange, not covered here");
                }
                // kx_version_for(0) == 0: the original scheme, one key for both directions.
                let (asymmetric_value, symmetric_value, key) = create_symmetric_key_msg(their_pk_b);
                let mut keys = vec![asymmetric_value, symmetric_value];
                tamper(&mut keys);
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_key_exchange(KeyExchange {
                    keys,
                    ..Default::default()
                });
                timeout(CONNECT_TIMEOUT, conn.send(&msg_out)).await??;
                // set_negotiated_key() with the picked version 0 is set_key().
                conn.set_key(key.clone());
                return Ok(Some(key));
            }
        }
    }
    Ok(None)
}

/// src/common.rs: `secure_tcp`, with the error text of src/client.rs. Unlike the client
/// the probe also fails when the server sent something other than a key exchange.
async fn secure_tcp(conn: &mut FramedStream, key: &str) -> ResultType<()> {
    secure_tcp_key(conn, key).await.map(|_| ())
}

/// `secure_tcp` that also hands out the exchanged key, to look at frames on the wire.
async fn secure_tcp_key(conn: &mut FramedStream, key: &str) -> ResultType<secretbox::Key> {
    key_exchange(conn, key, |_| {})
        .await
        .map_err(|e| anyhow!("Failed to secure tcp: {}", e))?
        .context("the server did not start a key exchange")
}

/// src/common.rs: `get_next_nonkeyexchange_msg`
async fn get_next_nonkeyexchange_msg(
    conn: &mut FramedStream,
    timeout: Option<u64>,
) -> Option<RendezvousMessage> {
    let timeout = timeout.unwrap_or(READ_TIMEOUT);
    for _ in 0..2 {
        if let Some(Ok(bytes)) = conn.next_timeout(timeout).await {
            if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                match &msg_in.union {
                    Some(Union::KeyExchange(_)) => {
                        println!("  skipped the KeyExchange the server sent on accept");
                        continue;
                    }
                    _ => {
                        return Some(msg_in);
                    }
                }
            }
        }
        break;
    }
    None
}

/// src/client.rs: the request of `_start_inner`, with the fields this proto has.
fn punch_hole_request(id: &str, key: &str, token: &str) -> RendezvousMessage {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_punch_hole_request(PunchHoleRequest {
        id: id.to_owned(),
        token: token.to_owned(),
        nat_type: NatType::ASYMMETRIC.into(),
        licence_key: key.to_owned(),
        conn_type: ConnType::DEFAULT_CONN.into(),
        version: CLIENT_VERSION.to_owned(),
        ..Default::default()
    });
    msg_out
}

async fn connect(host: &str) -> ResultType<FramedStream> {
    FramedStream::new(host, None, CONNECT_TIMEOUT).await
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn describe(msg: &RendezvousMessage) -> String {
    match &msg.union {
        Some(Union::PunchHoleResponse(ph)) if ph.socket_addr.is_empty() => format!(
            "PunchHoleResponse {{ failure: {:?}, other_failure: {:?} }}",
            ph.failure.enum_value(),
            ph.other_failure
        ),
        Some(Union::PunchHoleResponse(ph)) => format!(
            "PunchHoleResponse {{ socket_addr: {}, is_local: {}, relay_server: {:?}, pk: {} bytes }}",
            AddrMangle::decode(&ph.socket_addr),
            ph.is_local(),
            ph.relay_server,
            ph.pk.len()
        ),
        Some(Union::RegisterPeerResponse(r)) => {
            format!("RegisterPeerResponse {{ request_pk: {} }}", r.request_pk)
        }
        Some(Union::RegisterPkResponse(r)) => {
            format!("RegisterPkResponse {{ result: {:?} }}", r.result.enum_value())
        }
        Some(Union::FetchLocalAddr(f)) => format!(
            "FetchLocalAddr {{ socket_addr: {}, relay_server: {:?} }}",
            AddrMangle::decode(&f.socket_addr),
            f.relay_server
        ),
        Some(Union::PunchHole(p)) => format!(
            "PunchHole {{ socket_addr: {}, relay_server: {:?} }}",
            AddrMangle::decode(&p.socket_addr),
            p.relay_server
        ),
        other => format!("{:?}", other),
    }
}

fn expect_id_not_exist(msg: &RendezvousMessage) -> ResultType<()> {
    match &msg.union {
        Some(Union::PunchHoleResponse(ph))
            if ph.socket_addr.is_empty()
                && ph.other_failure.is_empty()
                && ph.failure.enum_value() == Ok(punch_hole_response::Failure::ID_NOT_EXIST) =>
        {
            Ok(())
        }
        _ => bail!("expected a PunchHoleResponse with ID_NOT_EXIST"),
    }
}

async fn secure(host: &str, key: &str) -> ResultType<()> {
    // What a signed-in client does: secure_tcp() before its first message.
    let mut conn = connect(host).await?;
    secure_tcp(&mut conn, key).await?;
    println!(
        "  answered with our KeyExchange, stream secured: {}",
        conn.is_secured()
    );
    conn.send(&punch_hole_request(UNKNOWN_ID, key, TOKEN))
        .await?;
    let msg_in = get_next_nonkeyexchange_msg(&mut conn, Some(3000))
        .await
        .context("no response that decrypts to the encrypted request")?;
    println!("  response after decryption: {}", describe(&msg_in));
    expect_id_not_exist(&msg_in)?;

    // The same again, this time reading the response frame as it is on the wire.
    let mut conn = connect(host).await?;
    let key2 = secure_tcp_key(&mut conn, key).await?;
    conn.send(&punch_hole_request(UNKNOWN_ID, key, TOKEN))
        .await?;
    let frame = timeout(3000, StreamExt::next(&mut *conn))
        .await?
        .context("connection closed")??;
    let plain = msg_in.write_to_bytes()?;
    println!(
        "  the same response on the wire: {} bytes {} (in plain it is {} bytes {})",
        frame.len(),
        hex(&frame),
        plain.len(),
        hex(&plain)
    );
    // First message from the server under this key: sequence number 1 as the nonce.
    let mut nonce = secretbox::Nonce([0u8; secretbox::NONCEBYTES]);
    nonce.0[..8].copy_from_slice(&1u64.to_le_bytes());
    let opened = secretbox::open(&frame, &nonce, &key2)
        .map_err(|_| anyhow!("the frame does not open with the exchanged key"))?;
    if frame[..] == plain[..] || opened != plain {
        bail!("the response on the wire is not the encrypted form of the expected response");
    }
    println!(
        "  it opens with the exchanged key and nonce 1 into those {} bytes",
        opened.len()
    );

    // An answer that comes straight from the read loop instead of through tcp_punch.
    let mut conn = connect(host).await?;
    secure_tcp(&mut conn, key).await?;
    test_nat(&mut conn).await
}

async fn plain(host: &str, key: &str) -> ResultType<()> {
    // What a client without a token does: the request is the first thing it sends.
    let mut conn = connect(host).await?;
    conn.send(&punch_hole_request(UNKNOWN_ID, key, "")).await?;
    let msg_in = get_next_nonkeyexchange_msg(&mut conn, Some(3000))
        .await
        .context("no response to the plain request")?;
    println!(
        "  response, read with no key on the stream (secured: {}): {}",
        conn.is_secured(),
        describe(&msg_in)
    );
    expect_id_not_exist(&msg_in)
}

/// The server has to close the connection without sending anything more.
async fn expect_closed(conn: &mut FramedStream, case: &str) -> ResultType<()> {
    match timeout(3000, StreamExt::next(&mut **conn)).await {
        Ok(None) | Ok(Some(Err(_))) => {
            println!("  {}: connection closed by the server", case);
            Ok(())
        }
        Ok(Some(Ok(frame))) => bail!("{}: the server answered with {} bytes", case, frame.len()),
        Err(_) => bail!("{}: the server kept the connection open", case),
    }
}

async fn bad(host: &str, key: &str) -> ResultType<()> {
    let cases: [(&str, fn(&mut Vec<Bytes>)); 5] = [
        ("answer with one key", |keys| keys.truncate(1)),
        ("answer with three keys", |keys| {
            keys.push(Bytes::from_static(b"x"))
        }),
        ("public key of 31 bytes", |keys| {
            keys[0] = keys[0].slice(..31)
        }),
        ("sealed key cut to 10 bytes", |keys| {
            keys[1] = keys[1].slice(..10)
        }),
        ("sealed key that does not open", |keys| {
            let mut sealed = keys[1].to_vec();
            sealed[0] ^= 1;
            keys[1] = sealed.into();
        }),
    ];
    for (case, tamper) in cases {
        let mut conn = connect(host).await?;
        if key_exchange(&mut conn, key, tamper).await?.is_none() {
            bail!("the server did not start a key exchange");
        }
        expect_closed(&mut conn, case).await?;
    }

    let mut conn = connect(host).await?;
    secure_tcp(&mut conn, key).await?;
    conn.set_key(secretbox::gen_key());
    conn.send(&punch_hole_request(UNKNOWN_ID, key, TOKEN))
        .await?;
    expect_closed(&mut conn, "request under another key after the exchange").await?;

    let mut conn = connect(host).await?;
    secure_tcp(&mut conn, key).await?;
    let request = punch_hole_request(UNKNOWN_ID, key, TOKEN).write_to_bytes()?;
    conn.send_bytes(request.into()).await?;
    expect_closed(&mut conn, "plain request after the exchange").await?;

    println!("  the server still answers:");
    plain(host, key).await
}

/// src/common.rs: `test_nat_type_`, the main port half of it.
async fn test_nat(conn: &mut FramedStream) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_test_nat_request(TestNatRequest::new());
    conn.send(&msg_out).await?;
    let msg_in = get_next_nonkeyexchange_msg(conn, Some(3000)).await;
    match msg_in.and_then(|msg_in| msg_in.union) {
        Some(Union::TestNatResponse(tnr)) if tnr.port == conn.local_addr().port() as i32 => {
            println!(
                "  NAT type test on the main port (stream secured: {}): TestNatResponse \
                 with our port {}",
                conn.is_secured(),
                tnr.port
            );
            Ok(())
        }
        _ => bail!("expected a TestNatResponse with our port"),
    }
}

async fn nat(host: &str) -> ResultType<()> {
    test_nat(&mut connect(host).await?).await?;

    // The NAT test port: the other half of `test_nat_type_`, and `query_online_states`
    // of src/client.rs. Neither skips a KeyExchange there, so none may come.
    let server = tokio::net::lookup_host(host)
        .await?
        .next()
        .context("host does not resolve")?;
    if server.ip().is_loopback() {
        println!("  NAT test port: skipped, from 127.0.0.1 it is the admin console");
        return Ok(());
    }
    let nat_port = std::net::SocketAddr::new(server.ip(), server.port() - 1).to_string();
    let mut test_nat_request = RendezvousMessage::new();
    test_nat_request.set_test_nat_request(TestNatRequest::new());
    let mut online_request = RendezvousMessage::new();
    online_request.set_online_request(OnlineRequest {
        peers: vec![UNKNOWN_ID.to_owned()],
        ..Default::default()
    });
    for request in [test_nat_request, online_request] {
        let mut conn = connect(&nat_port).await?;
        conn.send(&request).await?;
        let bytes = conn
            .next_timeout(3000)
            .await
            .context("no answer from the NAT test port")??;
        match RendezvousMessage::parse_from_bytes(&bytes)?.union {
            Some(Union::TestNatResponse(tnr)) if tnr.port == conn.local_addr().port() as i32 => {
                println!(
                    "  NAT test port {}: first message is TestNatResponse",
                    nat_port
                );
            }
            Some(Union::OnlineResponse(or)) if or.states[..] == [0u8] => {
                println!(
                    "  NAT test port {}: first message is OnlineResponse",
                    nat_port
                );
            }
            _ => bail!("unexpected first message from the NAT test port"),
        }
    }
    Ok(())
}

/// The WebSocket port (main port + 2): the client skips secure_tcp() there.
async fn ws(host: &str, key: &str) -> ResultType<()> {
    let server = tokio::net::lookup_host(host)
        .await?
        .next()
        .context("host does not resolve")?;
    let url = format!(
        "ws://{}",
        std::net::SocketAddr::new(server.ip(), server.port() + 2)
    );
    let (mut stream, _) = tokio_tungstenite::connect_async(&url).await?;
    let request = punch_hole_request(UNKNOWN_ID, key, "").write_to_bytes()?;
    stream.send(tungstenite::Message::Binary(request)).await?;
    let msg = timeout(3000, stream.next())
        .await?
        .context("connection closed")??;
    let tungstenite::Message::Binary(bytes) = msg else {
        bail!("expected a binary message");
    };
    let msg_in = RendezvousMessage::parse_from_bytes(&bytes)?;
    println!("  first message from {}: {}", url, describe(&msg_in));
    expect_id_not_exist(&msg_in)
}

async fn udp_next(udp: &mut FramedSocket) -> ResultType<RendezvousMessage> {
    let (bytes, _) = udp
        .next_timeout(3000)
        .await
        .context("no udp message from the server")??;
    Ok(RendezvousMessage::parse_from_bytes(&bytes)?)
}

async fn e2e(host: &str, key: &str, secure: bool) -> ResultType<()> {
    let server = tokio::net::lookup_host(host)
        .await?
        .next()
        .context("host does not resolve")?;
    let rs_pk = get_rs_pk(key).context("invalid server public key")?;

    // B, the controlled side, registers over UDP (rendezvous_mediator.rs).
    let id = (100_000_000 + hbb_common::rand::random::<u32>() % 900_000_000).to_string();
    let (pk_b, _) = sign::gen_keypair();
    let uuid: [u8; 16] = hbb_common::rand::random();
    let mut udp = FramedSocket::new(Config::get_any_listen_addr(server.is_ipv4())).await?;
    let expected = [
        "RegisterPeerResponse { request_pk: true }",
        "RegisterPkResponse { result: Ok(OK) }",
        "RegisterPeerResponse { request_pk: false }",
    ];
    for (step, expected) in expected.iter().enumerate() {
        let mut msg_out = RendezvousMessage::new();
        if step == 1 {
            msg_out.set_register_pk(RegisterPk {
                id: id.clone(),
                uuid: uuid.to_vec().into(),
                pk: pk_b.0.to_vec().into(),
                ..Default::default()
            });
        } else {
            msg_out.set_register_peer(RegisterPeer {
                id: id.clone(),
                ..Default::default()
            });
        }
        udp.send(&msg_out, server).await?;
        let answer = describe(&udp_next(&mut udp).await?);
        println!("  B {} udp registration step {}: {}", id, step + 1, answer);
        if answer != *expected {
            bail!("expected {}", expected);
        }
    }

    // A, the controlling side (client.rs: _start_inner).
    let mut a = connect(host).await?;
    if secure {
        secure_tcp(&mut a, key).await?;
    }
    println!("  A {} stream secured: {}", a.local_addr(), a.is_secured());
    let token = if secure { TOKEN } else { "" };
    let request = punch_hole_request(&id, key, token);
    // First attempt: B stays silent, as when its answer is lost on the way.
    a.send(&request).await?;
    println!("  B got over udp: {}", describe(&udp_next(&mut udp).await?));
    if let Some(msg_in) = get_next_nonkeyexchange_msg(&mut a, Some(1000)).await {
        bail!("A got {} before B answered", describe(&msg_in));
    }
    // Second attempt on the same socket, which is what the client does next.
    a.send(&request).await?;
    let msg_in = udp_next(&mut udp).await?;
    println!(
        "  A sent the request again, B got over udp: {}",
        describe(&msg_in)
    );

    // B answers over a TCP connection of its own, in plain, and drops it without
    // reading what the server sent there (handle_intranet_ / handle_punch_hole).
    let mut b = connect(host).await?;
    let mut msg_out = RendezvousMessage::new();
    match msg_in.union {
        Some(Union::FetchLocalAddr(fla)) => msg_out.set_local_addr(LocalAddr {
            id: id.clone(),
            socket_addr: AddrMangle::encode(AddrMangle::decode(&fla.socket_addr)).into(),
            local_addr: AddrMangle::encode(b.local_addr()).into(),
            relay_server: fla.relay_server,
            version: CLIENT_VERSION.to_owned(),
            ..Default::default()
        }),
        Some(Union::PunchHole(ph)) => msg_out.set_punch_hole_sent(PunchHoleSent {
            socket_addr: ph.socket_addr,
            id: id.clone(),
            relay_server: ph.relay_server,
            nat_type: ph.nat_type,
            version: CLIENT_VERSION.to_owned(),
            ..Default::default()
        }),
        _ => bail!("B expected FetchLocalAddr or PunchHole"),
    }
    b.send(&msg_out).await?;
    println!(
        "  B {} answered over its own tcp connection and closed it",
        b.local_addr()
    );
    drop(b);

    // The answer reaches A through the connection its request came in on.
    let msg_in = get_next_nonkeyexchange_msg(&mut a, Some(5000))
        .await
        .context("A got no response")?;
    println!("  A got: {}", describe(&msg_in));
    let Some(Union::PunchHoleResponse(ph)) = msg_in.union else {
        bail!("A expected a PunchHoleResponse");
    };
    // src/common.rs: decode_id_pk
    let id_pk = IdPk::parse_from_bytes(
        &sign::verify(&ph.pk, &rs_pk).map_err(|_| anyhow!("Signature mismatch"))?,
    )?;
    if ph.socket_addr.is_empty() || id_pk.id != id || id_pk.pk[..] != pk_b.0[..] {
        bail!("the response does not carry B's address and signed id/pk");
    }
    println!("  the signed id/pk in it verifies against the server key and is B's");

    // The relay round, on a socket of its own (client.rs: request_relay).
    let mut a = connect(host).await?;
    if secure {
        secure_tcp(&mut a, key).await?;
    }
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_request_relay(RequestRelay {
        id: id.clone(),
        token: token.to_owned(),
        uuid: "probe-relay-uuid".to_owned(),
        relay_server: "127.0.0.1:21117".to_owned(),
        secure: true,
        ..Default::default()
    });
    a.send(&msg_out).await?;
    let Some(Union::RequestRelay(rr)) = udp_next(&mut udp).await?.union else {
        bail!("B expected a RequestRelay");
    };
    println!(
        "  relay: B got over udp: RequestRelay {{ socket_addr: {}, uuid: {:?}, token: {:?} }}",
        AddrMangle::decode(&rr.socket_addr),
        rr.uuid,
        rr.token
    );
    // B answers over a TCP connection of its own (rendezvous_mediator.rs: create_relay).
    let mut b = connect(host).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_relay_response(RelayResponse {
        socket_addr: rr.socket_addr,
        version: CLIENT_VERSION.to_owned(),
        ..Default::default()
    });
    b.send(&msg_out).await?;
    drop(b);
    let msg_in = get_next_nonkeyexchange_msg(&mut a, Some(5000)).await;
    match msg_in.and_then(|msg_in| msg_in.union) {
        Some(Union::RelayResponse(rr))
            if rr.refuse_reason.is_empty() && rr.version == CLIENT_VERSION =>
        {
            println!(
                "  relay: A (stream secured: {}) got: RelayResponse {{ version: {:?} }}",
                a.is_secured(),
                rr.version
            );
            Ok(())
        }
        _ => bail!("A expected a RelayResponse"),
    }
}

#[tokio::main]
async fn main() {
    sodiumoxide::init().ok();
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: secure_tcp_probe <mode> <host:port> <server public key>");
        std::process::exit(2);
    }
    let (host, key) = (args[2].as_str(), args[3].as_str());
    let res = match args[1].as_str() {
        "secure" => secure(host, key).await,
        "plain" => plain(host, key).await,
        "bad" => bad(host, key).await,
        "nat" => nat(host).await,
        "ws" => ws(host, key).await,
        "e2e-secure" => e2e(host, key, true).await,
        "e2e-plain" => e2e(host, key, false).await,
        mode => Err(anyhow!("unknown mode {}", mode)),
    };
    match res {
        Ok(()) => println!("  PASS"),
        Err(err) => {
            println!("  FAIL: {}", err);
            std::process::exit(1);
        }
    }
}
