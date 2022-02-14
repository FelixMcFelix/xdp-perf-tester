use pnet::{
	datalink::{Channel, Config as DlConfig},
	packet::{
		ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
		ip::IpNextHeaderProtocols,
		ipv4::{self, Ipv4Packet, MutableIpv4Packet},
		udp::{MutableUdpPacket, UdpPacket},
		MutablePacket,
		Packet,
	},
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

	// let iface: Option<&str> = None;
	let iface = Some("\\Device\\NPF_{A9F99251-A118-4386-B7A3-0A0604ACC11C}");
	let iface = iface.and_then(|name| {
		interfaces
			.iter()
			.find_map(|el| if el.name == name { Some(el) } else { None })
	});

	for iface in interfaces.iter() {
		println!("IFACE: {:?}", iface);
	}

	if iface.is_none() {
		return Ok(());
	}

	let iface = iface.unwrap();
	let mac = iface.mac.unwrap();
	let mut config = DlConfig::default();
	config.read_timeout = Some(Duration::from_secs(10));
	let channel = pnet::datalink::channel(iface, config).unwrap();

	// let prog = EbpfProg::CKern;
	let prog = EbpfProg::RustKern {
		n_cores: Some(4),
		n_ops: Some(200),
		tx_chance: Some(0.2),
	};

	let _ = wipe_target();

	std::thread::sleep(Duration::from_millis(20));

	setup_target(prog)?;

	time_pkts(channel, mac.octets());

	wipe_target();

	Ok(())
}

fn time_pkts(chan: Channel, src_mac: [u8; 6]) {
	// let dst_mac = [0xbb,0xbb,0xbb,0xbb,0xbb,0xbb];
	let dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
	let n_pkts = 10_000;

	let (mut pkt_tx, mut pkt_rx) = match chan {
		Channel::Ethernet(tx, rx) => (tx, rx),
		_ => unimplemented!(),
	};

	let h1 = std::thread::spawn(move || {
		// Send thread
		let mut space = Vec::with_capacity(n_pkts);
		let mut pkt_buf = [0u8; 1560];

		let len = build_pkt(&mut pkt_buf[..], 200, src_mac, dst_mac);

		for i in 0..(n_pkts as u64) {
			modify_pkt(&mut pkt_buf[..len], i);
			let t = Instant::now();
			// println!("S{}", i);
			pkt_tx.send_to(&pkt_buf[..len], None);
			// println!("S{}'", i);
			space.push(t);

			// std::thread::sleep(Duration::from_millis(20));
		}

		println!("All sent");

		space
	});
	let h2 = std::thread::spawn(move || {
		// Rx thread.
		let mut space: Vec<Option<(bool, Instant)>> = vec![None; n_pkts];
		let mut good_rxd = 0;

		while let Ok(bytes) = pkt_rx.next() {
			let t = Instant::now();
			let eth_pkt = EthernetPacket::new(bytes).expect("Plenty of room...");

			if eth_pkt.get_ethertype() != EtherTypes::Ipv4 {
				continue;
			}

			let src = eth_pkt.get_source().octets();
			let dst = eth_pkt.get_destination().octets();

			// swapped == hit user-level.
			let skipped_user = match (src, dst) {
				a if a == (src_mac, dst_mac) => true,
				a if a == (dst_mac, src_mac) => false,
				_ => continue,
			};

			// println!("SRC {:x?} vs {src_mac:x?} -- {} {}", src, src==src_mac, src==dst_mac);
			// println!("DST {:x?} vs {dst_mac:x?} -- {} {}", dst, dst==src_mac, dst==dst_mac);
			// println!("tx in xdp? {skipped_user}",);

			let ipv4_pkt = Ipv4Packet::new(eth_pkt.payload()).expect("Plenty of room...");

			if ipv4_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Udp
				|| ipv4_pkt.get_ttl() != 63
			{
				continue;
			}

			let udp_pkt = UdpPacket::new(ipv4_pkt.payload()).expect("roomy...");

			if !(udp_pkt.get_source() == 3000 && udp_pkt.get_destination() == 3000) {
				continue;
			}

			let pkt_id = u64::from_be_bytes((&udp_pkt.payload()[..8]).try_into().unwrap());

			let empty = space[pkt_id as usize].is_none();

			space[pkt_id as usize] = Some((skipped_user, t));

			good_rxd += 1;

			if !empty {
				println!("DOUBLE COUNT FOR {}", pkt_id);
			}

			// if good_rxd % 500 == 0 {
			// 	println!("{} times", good_rxd);
			// }

			if good_rxd >= n_pkts - 500 {
				break;
			}
		}

		space
	});

	let ts1 = h1.join().unwrap();
	let ts2 = h2.join().unwrap();

	let mut kern_ts = vec![];
	let mut user_ts = vec![];

	for (i, (t1, maybe_dat)) in ts1.iter().zip(ts2.iter()).enumerate() {
		let (xdp_only, t2) = match maybe_dat {
			Some(a) => a,
			_ => {
				println!("Missing TS for pkt {}", i);
				continue;
			},
		};
		let dt = (*t2 - *t1).as_nanos();
		if *xdp_only {
			kern_ts.push(dt);
		} else {
			user_ts.push(dt);
		}
	}

	println!("K: {:?}", kern_ts);
	println!("U: {:?}", user_ts);

	println!("Kmed: {:?}", stats::median(kern_ts.clone().drain(..)));
	println!("Umed: {:?}", stats::median(user_ts.clone().drain(..)));
}

fn build_pkt(buf: &mut [u8], payload_len: usize, src_mac: [u8; 6], dst_mac: [u8; 6]) -> usize {
	// sort of have to build from scratch if we want to write
	// straight over the NIC.
	{
		let mut eth_pkt = MutableEthernetPacket::new(buf).expect("Plenty of room...");
		eth_pkt.set_destination(dst_mac.into());
		// not important to set source, not interested in receiving a reply...
		eth_pkt.set_ethertype(EtherTypes::Ipv4);
		eth_pkt.set_source(src_mac.into());
	}

	{
		let mut ipv4_pkt =
			MutableIpv4Packet::new(&mut buf[ETH_HEADER_LEN..]).expect("Plenty of room...");
		ipv4_pkt.set_version(4);
		ipv4_pkt.set_header_length(5);
		ipv4_pkt.set_ttl(64);
		ipv4_pkt.set_next_level_protocol(IpNextHeaderProtocols::Udp);
		// ipv4_pkt.set_destination(0.into());
		ipv4_pkt.set_destination([169, 254, 7, 44].into());
		// ipv4_pkt.set_source(0.into());
		ipv4_pkt.set_source([169, 254, 7, 45].into());
		ipv4_pkt.set_total_length((IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len) as u16);
		let csum = ipv4::checksum(&ipv4_pkt.to_immutable());
		ipv4_pkt.set_checksum(csum);
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
	let mut ipv4_pkt =
		MutableIpv4Packet::new(&mut buf[ETH_HEADER_LEN..]).expect("Plenty of room...");

	// ipv4_pkt.set_source(((pkt_idx >> 32) as u32).into());
	// ipv4_pkt.set_destination((pkt_idx as u32).into());

	// let csum = ipv4::checksum(&ipv4_pkt.to_immutable());
	// ipv4_pkt.set_checksum(csum);

	let mut udp_pkt = MutableUdpPacket::new(ipv4_pkt.payload_mut()).expect("Space ahoy!");

	(&mut udp_pkt.payload_mut()[..std::mem::size_of::<u64>()])
		.copy_from_slice(&pkt_idx.to_be_bytes());
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
			Some(HostToClient::Fail(_f)) => break,
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
