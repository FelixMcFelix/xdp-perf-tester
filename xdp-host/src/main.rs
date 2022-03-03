use bus::{Bus, BusReader};
use flume::{Receiver, Sender};
use libbpf_rs::{Link, MapFlags, Object, ObjectBuilder};
use pnet::packet::{ethernet::MutableEthernetPacket, ipv4::MutableIpv4Packet, MutablePacket};
use protocol::messages::*;
use std::{
	convert::TryInto,
	error::Error,
	io::Result as IoResult,
	os::unix::io::AsRawFd,
	process::Command,
	sync::{Arc, Barrier},
};
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

const IFACE: &str = "enp1s0f0";
const TABLE: &str = "xsks_map";

fn build_ebpf(request: &EbpfProg) -> IoResult<UserProgramNeeds> {
	use EbpfProg::*;

	println!("Building prog {:?}", request);

	match request {
		CKern => Ok(UserProgramNeeds {
			program: "xskmaptest.elf".into(),
			handler: "xdp_sock_prog".into(),
			n_sks: 2,
			n_user_ops: 0,
		}),
		RustKern {
			n_cores,
			n_ops,
			tx_chance,
			user_ops,
		} => {
			let mut cmd = Command::new("/home/clouduser/redbpf/target/release/cargo-bpf");

			cmd.current_dir("red-probes/")
				.args(["bpf", "build", "--target-dir=../target"]);

			if let Some(n_cores) = n_cores {
				cmd.env("XPP_TEST_CORES", n_cores.to_string());
			}

			if let Some(n_ops) = n_ops {
				cmd.env("XPP_TEST_OPS", n_ops.to_string());
			}

			if let Some(tx_chance) = tx_chance {
				let int_chance = tx_chance.clamp(0.0, 1.0) * (u32::MAX as f64);
				cmd.env("XPP_TEST_TX_RATE", (int_chance as u32).to_string());
			}

			cmd.output().map(|d| {
				println!("{:#?}", d);

				UserProgramNeeds {
					program: "./target/bpf/programs/xskmaptest/xskmaptest.elf".into(),
					handler: "outer_xdp_sock_prog".into(),
					n_sks: n_cores.unwrap_or(1) as usize,
					n_user_ops: user_ops.unwrap_or(0) as usize,
				}
			})
		},
	}
}

struct UserProgramNeeds {
	program: String,
	handler: String,
	n_sks: usize,
	n_user_ops: usize,
}

impl UserProgramNeeds {
	fn load(&self, iface_name: &str) -> (Object, Link) {
		let iface = nix::net::if_::if_nametoindex(iface_name).unwrap();

		let obj = ObjectBuilder::default().open_file(&self.program).unwrap();
		let mut load_obj = obj.load().unwrap();

		for map in load_obj.maps_iter() {
			println!("MAP: {} [{}]", map.name(), map.map_type());
		}

		for prog in load_obj.progs_iter() {
			println!("PRO: {} [{}]", prog.name(), prog.prog_type());
		}

		let link = load_obj
			.prog_mut(&self.handler)
			.unwrap()
			.attach_xdp(iface as i32)
			.unwrap();

		(load_obj, link)
	}
}

fn main() -> Result<(), Box<dyn Error>> {
	sudo::with_env(&["CARGO_", "PATH"])?;

	let (tx, rx) = protocol::host::host_server(protocol::DEFAULT_PORT);
	let mut prog = None;
	let mut first_time = true;

	for msg in rx.iter() {
		use ClientToHost::*;

		match msg {
			BpfBuildInstall(params, xsk_cfg) => {
				let (kill_tx, kill_rx) = flume::bounded(1);
				let (live_tx, live_rx) = flume::bounded(1);
				let handle = std::thread::spawn(move || {
					run_ebpf(params, xsk_cfg, kill_rx, live_tx, first_time);
				});

				first_time = false;

				prog = Some((handle, kill_tx));

				live_rx.recv()?;

				let _ = tx.send(HostToClient::Success);
			},
			BpfClose => {
				let take = if let Some((handle, kill_tx)) = &prog {
					let _ = kill_tx.send(());

					true
				} else {
					let _ = tx.send(HostToClient::Fail(FailReason::Generic(
						"No live experiment to kill.".to_string(),
					)));

					false
				};

				if take {
					let (handle, _) = prog.take().unwrap();

					handle.join();
					let _ = tx.send(HostToClient::Success);
				}
			},
			MacRequest => {
				let _ = tx.send(match get_mac() {
					Ok(mac) => HostToClient::MacReply(mac),
					Err(e) => HostToClient::Fail(FailReason::Generic(e.to_string())),
				});
			},
		}
	}

	Ok(())
}

fn get_mac() -> Result<[u8; 6], Box<dyn Error>> {
	for iface in pnet::datalink::interfaces() {
		if iface.name == IFACE {
			return if let Some(mac) = iface.mac {
				Ok(mac.octets())
			} else {
				Err(format!("Interface {IFACE} has no MAC address.").into())
			};
		}
	}

	Err(format!("Interface {IFACE} not found.").into())
}

fn run_ebpf(
	req: EbpfProg,
	xsk_cfg: XskConfig,
	kill_rx: Receiver<()>,
	live_tx: Sender<()>,
	first_time: bool,
) -> Result<(), Box<dyn Error>> {
	let (umem, descs) = Umem::new(UmemConfig::default(), 1024.try_into().unwrap(), false)
		.expect("failed to create UMEM");

	for iface in pnet::datalink::interfaces() {
		println!("IFACE: {:?}", iface)
	}

	let mut skt_cfg = SocketConfig::builder();

	skt_cfg.libbpf_flags(LibbpfFlags::XSK_LIBBPF_FLAGS_INHIBIT_PROG_LOAD);

	if xsk_cfg.zero_copy {
		print!("Zero-copy ");
		skt_cfg.bind_flags(xsk_rs::config::BindFlags::XDP_ZEROCOPY);
	} else {
		print!("Force copy ");
		skt_cfg.bind_flags(xsk_rs::config::BindFlags::XDP_COPY);
	}

	if xsk_cfg.skb_mode {
		println!("SKB mode.");
		skt_cfg.xdp_flags(xsk_rs::config::XdpFlags::XDP_FLAGS_SKB_MODE);
	} else {
		println!("DRV mode.");
		skt_cfg.xdp_flags(xsk_rs::config::XdpFlags::XDP_FLAGS_DRV_MODE);
	}

	let skt_cfg = skt_cfg.build();

	let prog_details = build_ebpf(&req).unwrap();

	let (mut prog, _link) = prog_details.load(IFACE);

	// Bind an AF_XDP socket to the interface named `xsk_dev2`, on
	// queue 0.
	let mut fq_and_cq = None;

	let mut sockets: Vec<(TxQueue, RxQueue)> = (0..prog_details.n_sks)
		.map(|_| {
			let (tx_q, rx_q, maybe_fq_and_cq) =
				Socket::new(skt_cfg, &umem, &IFACE.parse().unwrap(), 2) //0)
					.expect("failed to create dev2 socket");

			if maybe_fq_and_cq.is_some() {
				fq_and_cq = maybe_fq_and_cq;
			}

			(tx_q, rx_q)
		})
		.collect();

	let (mut fq, cq) = fq_and_cq.expect("missing dev2 fill queue and comp queue");

	let map_fd = prog.map(TABLE).map(|v| v.fd()).unwrap();

	// 1. Add frames to dev2's fill queue so we are ready to receive
	// some packets.
	unsafe {
		fq.produce(&descs);
	}

	let mut bus = Bus::new(1);
	let barrier = Arc::new(Barrier::new(1 + sockets.len()));

	let user_ops = prog_details.n_user_ops;
	let cores = core_affinity::get_core_ids();

	for (i, (tx_q, rx_q)) in sockets.drain(..).enumerate() {
		println!(
			"Inserting FD {} into map: {}[{}]",
			tx_q.fd().as_raw_fd(),
			map_fd,
			i
		);

		let fd_to_use = tx_q.fd().as_raw_fd();

		let _x = prog
			.map_mut(TABLE)
			.unwrap()
			.update(
				&((i as u32).to_le_bytes()),
				&(fd_to_use.to_le_bytes()),
				MapFlags::ANY,
			)
			.unwrap();

		let my_descs = descs.clone();
		let my_umem = umem.clone();
		let my_bus = bus.add_rx();
		let my_barrier = barrier.clone();

		let my_core = cores.as_ref().map(|v| v[i % v.len()]);

		let _ = std::thread::spawn(move || {
			if let Some(core) = my_core {
				core_affinity::set_for_current(core);
			}
			pkt_loop(
				i, user_ops, tx_q, rx_q, my_descs, my_umem, my_bus, my_barrier,
			)
		});
	}

	let _ = live_tx.send(());

	fq_cq_mediator(cq, fq, descs, kill_rx, bus, barrier);

	Ok(())
}

fn fq_cq_mediator(
	mut cq: CompQueue,
	mut fq: FillQueue,
	mut descs: Vec<FrameDesc>,
	kill_rx: Receiver<()>,
	mut bus: Bus<()>,
	barrier: Arc<Barrier>,
) {
	loop {
		match kill_rx.try_recv() {
			Ok(()) | Err(flume::TryRecvError::Disconnected) => break,
			_ => {},
		}

		unsafe {
			let pkts_to_send = cq.consume(&mut descs);
			fq.produce(&descs[..pkts_to_send]);
		}
	}

	bus.broadcast(());
	barrier.wait();

	eprintln!("Mediator dropped.");
}

fn pkt_loop(
	idx: usize,
	user_ops: usize,
	mut tx: TxQueue,
	mut rx: RxQueue,
	mut descs: Vec<FrameDesc>,
	umem: Umem,
	mut kill_rx: BusReader<()>,
	barrier: Arc<Barrier>,
) {
	eprintln!("Thread {idx} entering.");
	let mut ct: u64 = 0;

	loop {
		match kill_rx.try_recv() {
			Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
			_ => {},
		}

		let pkts_recvd = unsafe { rx.poll_and_consume(&mut descs, 100).unwrap() };

		// TODO: make this do the send per-batch?
		for recv_desc in descs.iter_mut().take(pkts_recvd) {
			let mut data = unsafe { umem.data_mut(recv_desc) };
			let body = data.contents_mut();

			{
				if let Some(mut ether) = MutableEthernetPacket::new(body) {
					//println!("thread {} decing: {:#?}", idx, ether);
					if let Some(mut ip) = MutableIpv4Packet::new(ether.payload_mut()) {
						ip.set_ttl(ip.get_ttl() - 1);
					}

					for _i in 0..user_ops {
						ct = ct.wrapping_add(1);
					}
				}
			}
		}

		unsafe { tx.produce_and_wakeup(&descs[..pkts_recvd]).unwrap() };
	}

	barrier.wait();

	eprintln!("Thread {idx} dropping umem.");
	drop(umem);
	eprintln!("Thread {idx} dropped umem.");

	eprintln!("Thread {idx} dropping tx.");
	drop(tx);
	eprintln!("Thread {idx} dropped tx.");

	eprintln!("Thread {idx} dropping rx.");
	drop(rx);
	eprintln!("Thread {idx} dropped rx.");
}
