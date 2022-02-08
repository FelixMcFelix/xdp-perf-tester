use pnet::{
	datalink::{Channel, Config as DlConfig, DataLinkReceiver, DataLinkSender},
	packet::{
		ethernet::{
			EtherTypes,
			EthernetPacket,
			MutableEthernetPacket,
		},
		ip::IpNextHeaderProtocols,
		ipv4::{
			self,
			Ipv4Packet,
			MutableIpv4Packet,
		},
		udp::MutableUdpPacket,
		Packet,
	}
};
use protocol::messages::*;
use std::{
	error::Error,
	io::{Read, Write},
	time::{Duration, Instant},
};
use tungstenite::{error::Error as WsError, WebSocket};

type AnyRes<A> = Result<A, Box<dyn Error>>;

pub const ETH_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;

fn main() -> AnyRes<()> {
	let interfaces = pnet::datalink::interfaces();

	let iface: Option<&str> = None;
	let iface = iface.and_then(|name| {
		interfaces
			.iter()
			.find_map(|el| if el.name == name { Some(el) } else { None })
	});

	if iface.is_none() {
		for iface in interfaces.iter() {
			println!("IFACE: {:?}", iface);
		}

		return Ok(());
	}

	let iface = iface.unwrap();
	let channel = pnet::datalink::channel(iface, Default::default()).unwrap();

	// let prog = EbpfProg::CKern;
	let prog = EbpfProg::RustKern {
		n_cores: Some(1),
		n_ops: Some(0),
		tx_chance: Some(1.0),
	};

	setup_target(EbpfProg::CKern)?;

	time_pkts(channel);

	wipe_target()
}

fn time_pkts(chan: Channel) {
	let n_pkts = 100_000;

	let (mut pkt_tx, mut pkt_rx) = match chan {
		Channel::Ethernet(tx, rx) => (tx, rx),
		_ => unimplemented!(),
	};

	let h1 = std::thread::spawn(move || {
		// Send thread
		let mut space = Vec::with_capacity(n_pkts);
		let mut pkt_buf = [0u8; 1560];

		let len = build_pkt(&mut pkt_buf[..], 0);

		for i in 0..(n_pkts as u64) {
			modify_pkt(&mut pkt_buf[..len], i);
			let t = Instant::now();
			pkt_tx.send_to(&pkt_buf[..len], None);
			space.push(t);
		}

		space
	});
	let h2 = std::thread::spawn(move || {
		// Rx thread.
		let mut space = vec![None; n_pkts];
		let mut good_rxd = 0;

		while let Ok(bytes) = pkt_rx.next() {
			let t = Instant::now();
			let eth_pkt = EthernetPacket::new(bytes)
				.expect("Plenty of room...");
			let src = eth_pkt.get_source().octets();
			let dst = eth_pkt.get_destination().octets();
			
			let skipped_user = match (src, dst) {
				([0xaa,0xaa,0xaa,0xaa,0xaa,0xaa], [0xbb,0xbb,0xbb,0xbb,0xbb,0xbb]) => true,
				([0xbb,0xbb,0xbb,0xbb,0xbb,0xbb], [0xaa,0xaa,0xaa,0xaa,0xaa,0xaa]) => false,
				_ => continue,
			};

			let ipv4_pkt = Ipv4Packet::new(eth_pkt.payload())
				.expect("Plenty of room...");
			let pkt_id = ((u32::from_be_bytes(ipv4_pkt.get_source().octets()) as u64) << 32)
				| (u32::from_be_bytes(ipv4_pkt.get_destination().octets()) as u64);

			space[pkt_id as usize] = Some((skipped_user, t));

			good_rxd += 1;

			if good_rxd == n_pkts {
				break;
			}
		}

		space
	});

	let ts1 = h1.join().unwrap();
	let ts2 = h2.join().unwrap();

	let mut kern_ts = vec![];
	let mut user_ts = vec![];

	for (t1, maybe_dat) in ts1.iter().zip(ts2.iter()) {
		let (xdp_only, t2) = maybe_dat.unwrap();
		let dt = (t2 - *t1).as_nanos();
		if xdp_only {
			kern_ts.push(dt);
		} else {
			user_ts.push(dt);
		}
	}


}

fn build_pkt(buf: &mut [u8], payload_len: usize) -> usize {
	// sort of have to build from scratch if we want to write
	// straight over the NIC.
	{
		let mut eth_pkt = MutableEthernetPacket::new(buf)
			.expect("Plenty of room...");
		eth_pkt.set_destination([0xbb,0xbb,0xbb,0xbb,0xbb,0xbb].into());
		// not important to set source, not interested in receiving a reply...
		eth_pkt.set_ethertype(EtherTypes::Ipv4);
		eth_pkt.set_source([0xaa,0xaa,0xaa,0xaa,0xaa,0xaa].into());
	}

	{
		let mut ipv4_pkt = MutableIpv4Packet::new(&mut buf[ETH_HEADER_LEN..])
			.expect("Plenty of room...");
		ipv4_pkt.set_version(4);
		ipv4_pkt.set_header_length(5);
		ipv4_pkt.set_ttl(64);
		ipv4_pkt.set_next_level_protocol(IpNextHeaderProtocols::Udp);
		ipv4_pkt.set_destination(0.into());
		ipv4_pkt.set_source(0.into());
		ipv4_pkt.set_total_length((IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len) as u16);
	}

	{
		let mut udp_pkt = MutableUdpPacket::new(&mut buf[ETH_HEADER_LEN + IPV4_HEADER_LEN..])
			.expect("Plenty of room...");
		udp_pkt.set_source(3000);
		udp_pkt.set_destination(3000);
		// checksum is optional in udp
		udp_pkt.set_checksum(0);

		udp_pkt.set_length((UDP_HEADER_LEN + payload_len) as u16);
	}

	ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len
}

fn modify_pkt(buf: &mut [u8], pkt_idx: u64) {
	let mut ipv4_pkt = MutableIpv4Packet::new(&mut buf[ETH_HEADER_LEN..])
		.expect("Plenty of room...");

	ipv4_pkt.set_source(((pkt_idx >> 32) as u32).into());
	ipv4_pkt.set_destination((pkt_idx as u32).into());

	let csum = ipv4::checksum(&ipv4_pkt.to_immutable());
	ipv4_pkt.set_checksum(csum);
}

fn setup_target(prog: EbpfProg) -> AnyRes<()> {
	let (mut ws, _resp) =
		tungstenite::connect(format!("ws://{}:{}", "gozo", protocol::DEFAULT_PORT))?;

	ws.write_message(for_ws(&ClientToHost::BpfBuildInstall(prog)))?;

	while let Ok(msg) = read_msg(&mut ws) {
		match msg {
			Some(HostToClient::Success) => break,
			Some(HostToClient::Fail(f)) => return Err(format!("Failed: {:?}", f).into()),
			Some(HostToClient::IllegalRequest) => return Err("IllegalRequest".to_string().into()),
			_ => {},
		}
	}

	let _ = ws.close(None)?;

	Ok(())
}

fn wipe_target() -> AnyRes<()> {
	let (mut ws, _resp) =
		tungstenite::connect(format!("ws://{}:{}", "gozo", protocol::DEFAULT_PORT))?;

	ws.write_message(for_ws(&ClientToHost::BpfClose))?;

	while let Ok(msg) = read_msg(&mut ws) {
		match msg {
			Some(HostToClient::Success) => break,
			Some(HostToClient::Fail(f)) => break,
			Some(HostToClient::IllegalRequest) => return Err("IllegalRequest".to_string().into()),
			_ => {},
		}
	}

	let _ = ws.close(None)?;

	Ok(())
}

fn read_msg<A: Read + Write>(ws: &mut WebSocket<A>) -> AnyRes<Option<HostToClient>> {
	let msg = ws.read_message();
	match msg {
		Ok(msg) =>
			if let Ok(text) = msg.to_text() {
				let decoded = serde_json::from_str::<HostToClient>(text);

				match decoded {
					Ok(a) => Ok(Some(a)),
					Err(e) => Err(e.into()),
				}
			} else {
				Ok(None)
			},
		a @ Err(WsError::ConnectionClosed) | a @ Err(WsError::AlreadyClosed) =>
			a.map(|_| None).map_err(|e| e.into()),
		Err(_) => Ok(None),
	}
}
