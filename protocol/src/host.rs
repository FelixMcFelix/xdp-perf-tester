use super::messages::*;

use flume::{Receiver, Sender};
use std::{
	io::ErrorKind as IoErrorKind,
	net::TcpListener,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc,
	},
};
use tungstenite::error::Error as WsError;

pub fn host_server(port: u16) -> (Sender<HostToClient>, Receiver<ClientToHost>) {
	let (tx_h2c, rx_h2c) = flume::unbounded();
	let (tx_c2h, rx_c2h) = flume::unbounded();

	std::thread::spawn(move || {
		host_server_inner(port, tx_c2h, rx_h2c);
	});

	(tx_h2c, rx_c2h)
}

fn host_server_inner(port: u16, tx: Sender<ClientToHost>, rx: Receiver<HostToClient>) {
	let listener = TcpListener::bind(("0.0.0.0", port)).unwrap();
	eprintln!("Now hosting on port {}", port);
	let busy = Arc::new(AtomicBool::new(false));

	for stream in listener.incoming() {
		if let Ok(stream) = stream {
			eprintln!("Client arrived from {:?}", stream.peer_addr());

			let l_busy = busy.clone();
			let l_tx = tx.clone();
			let l_rx = rx.clone();

			stream.set_nonblocking(true).unwrap();

			std::thread::spawn(move || {
				eprintln!("WS Handler spawned.");
				let mut websocket = tungstenite::accept(stream).unwrap();

				let was_busy = l_busy.fetch_or(true, Ordering::Relaxed);

				if was_busy {
					// Send Message.
					let _ = websocket.write_message(for_ws(&HostToClient::Fail(FailReason::Busy)));
					// Close Conn.
					let _ = websocket.close(None);
					return;
				}

				loop {
					match l_rx.try_recv() {
						Ok(x) => {
							let _ = websocket.write_message(for_ws(&x));
						},
						_ => {},
					}

					match websocket.read_message() {
						Ok(msg) =>
							if let Ok(text) = msg.to_text() {
								match serde_json::from_str::<ClientToHost>(text) {
									Ok(x) => {
										let _ = l_tx.send(x);
									},
									_ => {
										let _ = websocket
											.write_message(for_ws(&HostToClient::IllegalRequest));
										let _ = websocket.close(None);

										break;
									},
								}
							},
						Err(WsError::Io(e)) if e.kind() == IoErrorKind::WouldBlock => {
							// falls out to do write queue etc.
						},
						Err(_) => {
							let _ = websocket.write_message(for_ws(&HostToClient::IllegalRequest));
							let _ = websocket.close(None);

							break;
						},
					}

					if websocket.write_pending().is_err() {
						break;
					}
					std::thread::sleep(std::time::Duration::from_millis(20));
				}

				l_busy.store(false, Ordering::Relaxed);
			});
		} else {
			eprintln!("Issue: {:?}", stream);
		}
	}
}
