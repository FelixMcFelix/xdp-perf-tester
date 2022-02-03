use libbpf_rs::{Link, Object, ObjectBuilder, MapFlags};
use pnet::packet::ethernet::MutableEthernetPacket;
use std::{
    convert::TryInto,
    error::Error,
    io::Result as IoResult,
    os::unix::io::AsRawFd,
    process::Command,
    path::Path,
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

// const IFACE: &str = "eno1";
// const PROG: &str = "ebpf_output/kern.o";
// const HANDLER: &str = "upcall";
// const TABLE: &str = "XSK_MAP";

const IFACE: &str = "eno1";
// const PROG: &str = "c-xdp.o";
const PROG: &str = "xskmaptest.elf";
const HANDLER: &str = "outer_xdp_sock_prog";
const TABLE: &str = "xsks_map";

enum EbpfTest {
    CKern,
    RKern {
        n_cores: Option<usize>,
        n_ops: Option<usize>,
        tx_chance: Option<f64>,
    },
}

impl EbpfTest {
    fn build(&self) -> IoResult<UserProgramNeeds> {
        use EbpfTest::*;

        match self {
            CKern => Ok(UserProgramNeeds {
                program: "xskmaptest.elf".into(),
                handler: "xdp_sock_prog".into(),
                n_sks: 2,
            }),
            RKern { n_cores, n_ops, tx_chance } => {
                let mut cmd = Command::new("/home/netlab/gits/redbpf/target/release/cargo-bpf");

                cmd.current_dir("red-probes/")
                    .args([
                        "bpf",
                        "build",
                        "--target-dir=../target"
                    ]);
                    // .env("PATH", "/home/netlab/.cargo/bin/rustc");

                // set envs?
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

                cmd.output()
                    .map(|d| {
                        println!("{:#?}", d);

                        UserProgramNeeds{
                            program: "./target/bpf/programs/xskmaptest/xskmaptest.elf".into(),
                            handler: "outer_xdp_sock_prog".into(),
                            n_sks: n_cores.unwrap_or(1),
                        }
                    })
            }
        }
    }
}

struct UserProgramNeeds {
    program: String,
    handler: String,
    n_sks: usize,
}

impl UserProgramNeeds {
    fn load(&self, iface_name: &str) -> (Object, Link) {
        let iface = nix::net::if_::if_nametoindex(iface_name).unwrap();

        let mut obj = ObjectBuilder::default().open_file(&self.program).unwrap();
        let mut load_obj = obj.load().unwrap();

        for map in load_obj.maps_iter() {
            println!("MAP: {} [{}]", map.name(), map.map_type());
        }

        for prog in load_obj.progs_iter() {
            println!("PRO: {} [{}]", prog.name(), prog.prog_type());
        }

        let link = load_obj.prog_mut(&self.handler).unwrap()
            .attach_xdp(iface as i32).unwrap();

        (load_obj, link)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    sudo::with_env(&["CARGO_", "PATH"])?;
    /*// Create a UMEM for dev1 with 32 frames, whose sizes are
    // specified via the `UmemConfig` instance.
    let (dev1_umem, mut dev1_descs) =
        Umem::new(UmemConfig::default(), 32.try_into().unwrap(), false)
            .expect("failed to create UMEM");

    // Bind an AF_XDP socket to the interface named `xsk_dev1`, on
    // queue 0.
    let (mut dev1_tx_q, _dev1_rx_q, _dev1_fq_and_cq) = Socket::new(
        SocketConfig::default(),
        &dev1_umem,
        &"xsk_dev1".parse().unwrap(),
        0,
    )
    .expect("failed to create dev1 socket");*/

    // Create a UMEM for dev2. Another option is to use the same UMEM
    // as dev1 - to do that we'd just pass `dev1_umem` to the
    // `Socket::new` call. In this case the UMEM would be shared, and
    // so `dev1_descs` could be used in either context, but each
    // socket would have its own completion queue and fill queue.
    let (umem, mut descs) =
        Umem::new(UmemConfig::default(), 1024.try_into().unwrap(), false)
            .expect("failed to create UMEM");

    for iface in pnet::datalink::interfaces() {
        println!("IFACE: {:?}", iface)
    }

    let skt_cfg = SocketConfig::builder()
        .libbpf_flags(LibbpfFlags::XSK_LIBBPF_FLAGS_INHIBIT_PROG_LOAD)
        .build();

    let test_details = EbpfTest::RKern {
        n_cores: Some(8),
        n_ops: Some(128),
        tx_chance: Some(0.0),
    };

    let prog_details = test_details.build().unwrap();

    let (mut prog, mut link) = prog_details.load(IFACE);

    

    // Bind an AF_XDP socket to the interface named `xsk_dev2`, on
    // queue 0.
    let mut fq_and_cq = None;

    let mut sockets: Vec<(TxQueue, RxQueue)> = (0..prog_details.n_sks)
        .map(|i| {
            let (tx_q, rx_q, maybe_fq_and_cq) = Socket::new(
                skt_cfg.clone(),
                &umem,
                &IFACE.parse().unwrap(),
                0,
            )
            .expect("failed to create dev2 socket");

            if maybe_fq_and_cq.is_some() {
                fq_and_cq = maybe_fq_and_cq;
            }

            (tx_q, rx_q)
        }).collect();

    let (mut fq, mut cq) = fq_and_cq.expect("missing dev2 fill queue and comp queue");

    let map_fd = prog.map(TABLE).map(|v| v.fd()).unwrap();

    // 1. Add frames to dev2's fill queue so we are ready to receive
    // some packets.
    unsafe {
        fq.produce(&descs);
    }

    for (i, (tx_q, rx_q)) in sockets.drain(..).enumerate() {
        println!("Inserting FD {} into map: {}[{}]", tx_q.fd().as_raw_fd(), map_fd, i);

        let fd_to_use = tx_q.fd().as_raw_fd();

        let x = prog.map_mut(TABLE).unwrap().update(
            &((i as u32).to_le_bytes()),
            &(fd_to_use.to_le_bytes()),
            MapFlags::ANY
        ).unwrap();

        let my_descs = descs.clone();
        let my_umem = umem.clone();

        let _ = std::thread::spawn(move || {
            pkt_loop(i, tx_q, rx_q, my_descs, my_umem)
        });
    }

    fq_cq_mediator(cq, fq, descs);

    panic!("no matching packets received")
}

fn fq_cq_mediator(
    mut cq: CompQueue,
    mut fq: FillQueue,
    // desc_chan: Receiver<FrameDesc>,
    mut descs: Vec<FrameDesc>)
{
    loop {
        unsafe {
            let pkts_to_send = cq.consume(&mut descs);
            fq.produce(&descs[..pkts_to_send]);
        }
    }
}

fn pkt_loop(idx: usize, mut tx: TxQueue, mut rx: RxQueue, mut descs: Vec<FrameDesc>, mut umem: Umem) {
    loop {
        let pkts_recvd = unsafe { rx.poll_and_consume(&mut descs, 100).unwrap() };

        // TODO: make this do the send per-batch?
        for recv_desc in descs.iter_mut().take(pkts_recvd) {
            let mut data = unsafe { umem.data_mut(recv_desc) };
            let body = data.contents_mut();

            {
                if let Some(mut ether) = MutableEthernetPacket::new(body) {
                    println!("thread {} swapping: {:#?}", idx, ether);

                    let old_src = ether.get_source();
                    let old_dst = ether.get_destination();

                    ether.set_source(old_dst);
                    ether.set_destination(old_src);
                }
            }

            unsafe {tx.produce_one_and_wakeup(&recv_desc).unwrap()};
        }
    }
}
