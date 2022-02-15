use serde::{Deserialize, Serialize};
use tungstenite::protocol::Message;

#[derive(Clone, Deserialize, Serialize)]
pub enum ClientToHost {
	BpfBuildInstall(EbpfProg),
	BpfClose,
}

#[derive(Clone, Deserialize, Serialize)]
pub enum HostToClient {
	Success,
	Fail(FailReason),
	IllegalRequest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FailReason {
	Busy,
	Generic(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EbpfProg {
	CKern,
	RustKern {
		n_cores: Option<u64>,
		n_ops: Option<u64>,
		tx_chance: Option<f64>,
		user_ops: Option<u64>,
	},
}

pub fn for_ws(msg: &impl Serialize) -> Message {
	Message::Text(serde_json::to_string(msg).unwrap())
}
