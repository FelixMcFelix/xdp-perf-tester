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
#[cfg(feature = "xdp")]
use std::{cell::UnsafeCell, collections::VecDeque, sync::Arc};
use std::{
	error::Error,
	io::{Read, Write},
	time::{Duration, Instant},
};
use tungstenite::{error::Error as WsError, WebSocket};
#[cfg(feature = "xdp")]
use xsk_rs::{
	config::{LibbpfFlags, SocketConfig, UmemConfig},
	socket::Socket,
	umem::Umem,
	CompQueue,
	FillQueue,
	FrameDesc,
	RxQueue,
	TxQueue,
};

type AnyRes<A> = Result<A, Box<dyn Error>>;

pub const ETH_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;

pub const PKT_SIZE: usize = 64;
pub const NB_PKTS: usize = 1_000_000;
pub const UMEM_SZ: usize = 4096;

fn main() -> AnyRes<()> {
	let interfaces = pnet::datalink::interfaces();

	// let iface: Option<&str> = None;
	//let iface = Some("\\Device\\NPF_{A9F99251-A118-4386-B7A3-0A0604ACC11C}");
	let iface_name = Some("enp1s0f0");

	// let prog = EbpfProg::CKern;
	let prog = EbpfProg::RustKern {
		//n_cores: Some(4),
		n_cores: Some(1),
		//n_ops: Some(200),
		n_ops: Some(0),
		tx_chance: Some(0.5),
		user_ops: Some(0),
	};

	let xsk_cfg = XskConfig {
		skb_mode: false,
		//skb_mode: true,
		zero_copy: true,
		//zero_copy: false,
	};

	//let _ = wipe_target();

	std::thread::sleep(Duration::from_millis(20));

	//let tgt_mac = get_target_mac()?;
	let tgt_mac = [0x3C, 0xFD, 0xFE, 0x9E, 0xA3, 0x20];

	std::thread::sleep(Duration::from_millis(20));

	setup_target(prog, xsk_cfg)?;

	// KILL HERE IF USING PKTGEN
	// return Ok(());

	//std::thread::sleep(Duration::from_secs(1));

	let iface = iface_name.clone().and_then(|name| {
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
	if !cfg!(feature = "xdp") {
		let mut config = DlConfig::default();
		config.read_timeout = Some(Duration::from_secs(10));
		let channel = pnet::datalink::channel(iface, config).unwrap();

		time_pkts(channel, mac.octets(), tgt_mac, PKT_SIZE, NB_PKTS);
	} else {
		drop(iface);
		#[cfg(feature = "xdp")]
		{
			let iface_name = iface_name.unwrap();
			//assumption: n_rx qs == n_cores
			let handlers = std::thread::available_parallelism()?.get();
			let mut skt_cfg = SocketConfig::builder()
                //.libbpf_flags(xsk_rs::config::LibbpfFlags::XSK_LIBBPF_FLAGS_INHIBIT_PROG_LOAD)
                //.xdp_flags(xsk_rs::config::XdpFlags::XDP_FLAGS_UPDATE_IF_NOEXIST)
                .build();

			let mut sockets: Vec<(
				usize,
				Umem,
				Vec<FrameDesc>,
				TxQueue,
				RxQueue,
				FillQueue,
				CompQueue,
			)> = (0..handlers)
				.map(|i| {
					println!("Go {i}");
					let (umem, descs) = Umem::new(
						UmemConfig::default(),
						(UMEM_SZ as u32).try_into().unwrap(),
						false,
					)
					.expect("failed to create UMEM");

					let (tx_q, rx_q, maybe_fq_and_cq) =
						Socket::new(skt_cfg, &umem, &iface_name.parse().unwrap(), i as u32)
							.expect("failed to create dev2 socket");

					let (mut fq, cq) =
						maybe_fq_and_cq.expect(&format!("Failed to get FQ and CQ for Queue {i}."));

					// half for send, half for rx...
					unsafe {
						fq.produce(&descs[(UMEM_SZ / 2)..]);
					}

					(i, umem, descs, tx_q, rx_q, fq, cq)
				})
				.collect();

			time_pkts_xdp(sockets, mac.octets(), tgt_mac, PKT_SIZE, NB_PKTS);
		}
	}

	//wipe_target();

	Ok(())
}

fn time_pkts(chan: Channel, src_mac: [u8; 6], dst_mac: [u8; 6], pkt_size: usize, n_pkts: usize) {
	let (mut pkt_tx, mut pkt_rx) = match chan {
		Channel::Ethernet(tx, rx) => (tx, rx),
		_ => unimplemented!(),
	};

	let h1 = std::thread::spawn(move || {
		// Send thread
		let mut space = Vec::with_capacity(n_pkts);
		let mut pkt_buf = [0u8; 1560];

		let payload_len = pkt_size - 42;

		let len = build_pkt(&mut pkt_buf[..], payload_len, src_mac, dst_mac);

		for i in 0..(n_pkts as u64) {
			modify_pkt(&mut pkt_buf[..len], i);
			let t = Instant::now();
			// println!("S{}", i);
			pkt_tx.send_to(&pkt_buf[..len], None);
			// println!("S{}'", i);
			space.push(t);

			// std::thread::sleep(Duration::from_millis(20));
		}

		// estimate speed here?
		let dt = space[space.len() - 1] - space[0];
		let bits = (n_pkts as f64) * (pkt_size as f64) * 8.0;
		let speed = bits / dt.as_secs_f64();

		println!("All sent: {}Mbps", speed / 1e6);

		space
	});
	let h2 = std::thread::spawn(move || {
		// Rx thread.
		let mut space: Vec<Option<(bool, Instant)>> = vec![None; n_pkts];
		let mut good_rxd = 0;

		while let Ok(bytes) = pkt_rx.next() {
			let t = Instant::now();

			let (pkt_id, skipped_user) = if let Some(a) = check_pkt(bytes, &src_mac, &dst_mac) {
				a
			} else {
				continue;
			};

			let empty = space[pkt_id as usize].is_none();

			space[pkt_id as usize] = Some((skipped_user, t));

			good_rxd += 1;

			if !empty {
				println!("DOUBLE COUNT FOR {}", pkt_id);
			}

			// if good_rxd % 500 == 0 {
			// 	println!("{} times", good_rxd);
			// }

			//if good_rxd >= n_pkts - 500 {
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
	let mut losses = 0;

	for (i, (t1, maybe_dat)) in ts1.iter().zip(ts2.iter()).enumerate() {
		let (xdp_only, t2) = match maybe_dat {
			Some(a) => a,
			_ => {
				//println!("Missing TS for pkt {}", i);
				losses += 1;
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

	// println!("K: {:?}", kern_ts);
	// println!("U: {:?}", user_ts);

	println!("Kmed: {:?}", stats::median(kern_ts.clone().drain(..)));
	println!("Umed: {:?}", stats::median(user_ts.clone().drain(..)));
	println!("Losses: {}", losses);
}

#[cfg(feature = "xdp")]
struct Wrap<T>(T);

#[cfg(feature = "xdp")]
unsafe impl<T> Sync for Wrap<T> {}

#[cfg(feature = "xdp")]
fn time_pkts_xdp(
	sockets: Vec<(
		usize,
		Umem,
		Vec<FrameDesc>,
		TxQueue,
		RxQueue,
		FillQueue,
		CompQueue,
	)>,
	src_mac: [u8; 6],
	dst_mac: [u8; 6],
	pkt_size: usize,
	n_pkts: usize,
) {
	// need: shared store. for all threads.
	let mut space: Vec<Wrap<UnsafeCell<Option<(bool, Instant)>>>> = vec![];
	space.resize_with(n_pkts, || Wrap(UnsafeCell::new(None)));
	let sharespace = Arc::new(space);

	let mut hs = vec![];
	let n_senders = sockets.len();

	for (i, umem, mut descs, mut tx_q, mut rx_q, mut fq, mut cq) in sockets {
		let my_space = sharespace.clone();
		let h = std::thread::spawn(move || {
			// loop:
			// try rx. take time.
			//  for each, insert timestamp in correct loc.
			// send a batch of pkts w/ same send_ts
			// drain cq: maintain own sendlist and keep len in kernel correct.
			// prioritise giving frames to kernel.
			// 10s since spawn? break!

			const SEND_BATCH: usize = 1;

			let mut pkts_in_kern = UMEM_SZ / 2;
			let mut rx_desc_scratch = descs.clone();
			rx_desc_scratch.truncate(UMEM_SZ / 2);
			// let mut tx_descs = VecDeque::from(descs);
			descs.truncate(UMEM_SZ / 2);
			let mut tx_descs = descs;
			let mut last_evt = Instant::now();

			// how to manage tx-descs?
			// send from back
			// fill to back?
			let mut tx_descs_len = tx_descs.len();

			let per_sender = n_pkts / n_senders;
			let mut ids: std::ops::Range<usize> = (i * per_sender)..(if i == (n_senders - 1) {
				n_pkts
			} else {
				(i + 1) * per_sender
			});

			let mut pkt_buf = [0u8; 1560];
			let payload_len = pkt_size - 42;
			let len = build_pkt(&mut pkt_buf[..], payload_len, src_mac, dst_mac);

			// pre-prep all pkts with most of the data they need.
			// we can probably expect that the kernel will return these frames
			// intact, allowing decent reuse.
			for desc in &mut tx_descs[..] {
				let mut data = unsafe { umem.data_mut(desc) };
				let mut cursor = data.cursor();

				cursor
					.write_all(&pkt_buf[..len])
					.expect("Trivially enough space for this...");

				println!("I have put in {}/{}", cursor.pos(), cursor.buf_len());
			}

			let mut send_times = Vec::with_capacity(ids.end - ids.start);

			loop {
				let mut evt = false;
				let pkts_recvd = unsafe { rx_q.poll_and_consume(&mut rx_desc_scratch, 1).unwrap() };
				let t = Instant::now();
				for recv_desc in rx_desc_scratch.iter().take(pkts_recvd) {
					let data = unsafe { umem.data(recv_desc) };
					let body = data.contents();

					// chk packet.
					// put time into right slot.
					if let Some((id, skipped_user)) = check_pkt(body, &src_mac, &dst_mac) {
						let val_ptr = &my_space[id as usize].0.get();
						unsafe {
							val_ptr.replace(Some((skipped_user, t)));
						};
					}

					evt = true;
				}

				// pass back read frames to kern
				unsafe {
					fq.produce(&rx_desc_scratch[..pkts_recvd]);
				}

				// prep and send packets
				if tx_descs_len != 0 && !ids.is_empty() {
					let pkts_to_send = SEND_BATCH.min(tx_descs_len).min(ids.end - ids.start);
					let pkt_range = (tx_descs_len - pkts_to_send)..tx_descs_len;

					// actual prep over pkt_range.
					for desc in &mut tx_descs[pkt_range.clone()] {
						let mut data = unsafe { umem.data_mut(desc) };
						let mut body = data.contents_mut();
						modify_pkt(body, ids.start as u64);
						ids.start += 1;
					}

					unsafe { tx_q.produce_and_wakeup(&tx_descs[pkt_range]).unwrap() };
					let send_time = Instant::now();

					for i in 0..pkts_to_send {
						send_times.push(send_time);
					}

					//println!("Sent {pkts_to_send} pkts.");

					tx_descs_len -= pkts_to_send;
					evt = true;
				}

				// get sent frames back.
				// if tx_descs_len != tx_descs.len() {
				let rd = unsafe { cq.consume(&mut tx_descs[tx_descs_len..]) };
				tx_descs_len += rd;

				if i == 0 {
					println!("Got {rd} back from CQ");
				}
				// }

				if evt {
					last_evt = Instant::now();
				}

				if last_evt.elapsed() > Duration::from_secs(10) {
					break;
				}
			}

			send_times
		});

		hs.push(h);
	}

	// await all.
	// stack end_time vecs together.
	let mut all_sends = vec![];
	for handle in hs.drain(..) {
		let mut times = handle.join().expect("Thread panicked!");
		all_sends.append(&mut times);
	}

	let mut kern_ts = vec![];
	let mut user_ts = vec![];
	let mut losses = 0;

	for (i, (t1, maybe_dat)) in all_sends.iter().zip(sharespace.iter()).enumerate() {
		let val_ptr = maybe_dat.0.get();
		let val_space = unsafe { &*val_ptr };

		let maybe_dat = val_space.as_ref();
		let (xdp_only, t2) = match maybe_dat {
			Some(a) => a,
			_ => {
				//println!("Missing TS for pkt {}", i);
				losses += 1;
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

	// println!("K: {:?}", kern_ts);
	// println!("U: {:?}", user_ts);

	println!("Kmed: {:?}", stats::median(kern_ts.clone().drain(..)));
	println!("Umed: {:?}", stats::median(user_ts.clone().drain(..)));
	println!("Losses: {}", losses);
}

#[inline]
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

#[inline]
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

#[inline]
fn check_pkt(buf: &[u8], src_mac: &[u8; 6], dst_mac: &[u8; 6]) -> Option<(u64, bool)> {
	let eth_pkt = EthernetPacket::new(buf)?;

	if eth_pkt.get_ethertype() != EtherTypes::Ipv4 {
		return None;
	}

	let src = eth_pkt.get_source().octets();
	let dst = eth_pkt.get_destination().octets();

	// mac swap required on seen pkts
	if !(src == *dst_mac && dst == *src_mac) {
		return None;
	}

	// println!("SRC {:x?} vs {src_mac:x?} -- {} {}", src, src==src_mac, src==dst_mac);
	// println!("DST {:x?} vs {dst_mac:x?} -- {} {}", dst, dst==src_mac, dst==dst_mac);
	// println!("tx in xdp? {skipped_user}",);

	let ipv4_pkt = Ipv4Packet::new(eth_pkt.payload())?;

	if ipv4_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
		return None;
	}

	let skipped_user = ipv4_pkt.get_ttl() == 64;

	let udp_pkt = UdpPacket::new(ipv4_pkt.payload())?;

	if !(udp_pkt.get_source() == 3000 && udp_pkt.get_destination() == 3000) {
		return None;
	}

	let pkt_id = u64::from_be_bytes((&udp_pkt.payload()[..8]).try_into().unwrap());

	Some((pkt_id, skipped_user))
}

fn setup_target(prog: EbpfProg, cfg: XskConfig) -> AnyRes<()> {
	let (mut ws, _resp) =
	//	tungstenite::connect(format!("ws://{}:{}", "ava7", protocol::DEFAULT_PORT))?;
		tungstenite::connect(format!("ws://{}:{}", "192.168.0.86", protocol::DEFAULT_PORT))?;

	ws.write_message(for_ws(&ClientToHost::BpfBuildInstall(prog, cfg)))?;

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
		tungstenite::connect(format!("ws://{}:{}", "ava7", protocol::DEFAULT_PORT))?;

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

fn get_target_mac() -> AnyRes<[u8; 6]> {
	let (mut ws, _resp) =
		tungstenite::connect(format!("ws://{}:{}", "ava7", protocol::DEFAULT_PORT))?;

	ws.write_message(for_ws(&ClientToHost::MacRequest))?;

	let mut out = None;

	while let Ok(msg) = read_msg(&mut ws) {
		match msg {
			Some(HostToClient::MacReply(bytes)) => {
				out = Some(bytes);
				break;
			},
			Some(HostToClient::Fail(f)) => return Err(format!("Failed: {:?}", f).into()),
			Some(HostToClient::IllegalRequest) => return Err("IllegalRequest".to_string().into()),
			_ => {},
		}
	}

	let _ = ws.close(None)?;

	Ok(out.unwrap())
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
