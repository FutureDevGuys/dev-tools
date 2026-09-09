//! Disposable encrypted Secret Service for installed user-only acceptance.
//! All values are synthetic. It has no activation, unlock or prompt support.
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Type, Value};

const SERVICE: &str = "/org/freedesktop/secrets";

#[derive(Default)]
pub struct Observations {
    pub searches: Vec<HashMap<String, String>>,
    pub reads: Vec<String>,
    keys: BTreeMap<String, [u8; 16]>,
}

#[derive(Clone)]
struct Store {
    state: Arc<Mutex<Observations>>,
    slots: BTreeMap<String, String>,
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Store {
    fn open_session(&self, algorithm: &str, input: OwnedValue) -> (OwnedValue, OwnedObjectPath) {
        assert_eq!(algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
        let public: Vec<u8> = input.try_into().unwrap();
        // Fixture-only exponent 1: shared value equals the client's public value.
        // This is not a production cryptographic implementation.
        let mut shared = vec![0; 128 - public.len()];
        shared.extend(public);
        let mut key = [0; 16];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &shared)
            .expand(&[], &mut key)
            .unwrap();
        let mut state = self.state.lock().unwrap();
        let session = format!("{SERVICE}/session/s{}", state.keys.len());
        state.keys.insert(session.clone(), key);
        (
            Value::from(vec![2_u8]).try_to_owned().unwrap(),
            session.try_into().unwrap(),
        )
    }

    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        self.state.lock().unwrap().searches.push(attributes.clone());
        if attributes.get("service").map(String::as_str) != Some("dev-auth-v3") {
            return (vec![], vec![]);
        }
        let selected = attributes
            .get("username")
            .and_then(|name| name.strip_prefix("user-broker-service-account-token-"))
            .filter(|slot| self.slots.contains_key(*slot));
        (
            selected
                .map(|slot| format!("{SERVICE}/item/{slot}").try_into().unwrap())
                .into_iter()
                .collect(),
            vec![],
        )
    }
}

#[derive(Serialize, Deserialize, Type)]
struct SecretWire {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

struct Item {
    store: Store,
    slot: String,
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    fn get_secret(&self, session: OwnedObjectPath) -> SecretWire {
        let mut state = self.store.state.lock().unwrap();
        state.reads.push(self.slot.clone());
        let key = state.keys[session.as_str()];
        let iv = [7; 16];
        let value = cbc::Encryptor::<aes::Aes128>::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(self.store.slots[&self.slot].as_bytes());
        SecretWire {
            session,
            parameters: iv.to_vec(),
            value,
            content_type: "text/plain".into(),
        }
    }
}

pub struct EnrolledStore {
    child: Child,
    connection: Option<zbus::blocking::Connection>,
    pub observations: Arc<Mutex<Observations>>,
}

impl EnrolledStore {
    pub fn start(runtime: &Path, slots: BTreeMap<String, String>) -> Self {
        let config = runtime.join("bus.xml");
        let socket = runtime.join("bus");
        let address = format!("unix:path={}", socket.display());
        std::fs::write(&config, format!(
            "<busconfig><type>session</type><listen>{address}</listen><auth>EXTERNAL</auth><policy context=\"default\"><allow user=\"*\"/><allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>"
        )).unwrap();
        let child = Command::new("/usr/bin/dbus-daemon")
            .args(["--nofork", "--nopidfile"])
            .arg(format!("--config-file={}", config.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("installed fixture requires native dbus-daemon");
        let observations = Arc::new(Mutex::new(Observations::default()));
        let mut fixture = Self {
            child,
            connection: None,
            observations: Arc::clone(&observations),
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        while !socket.exists() {
            assert!(
                fixture.child.try_wait().unwrap().is_none(),
                "fixture bus exited"
            );
            assert!(Instant::now() < deadline, "fixture bus did not start");
            std::thread::sleep(Duration::from_millis(5));
        }
        let store = Store {
            state: observations,
            slots,
        };
        let mut builder = zbus::blocking::connection::Builder::address(address.as_str())
            .unwrap()
            .method_timeout(Duration::from_secs(2))
            .name("org.freedesktop.secrets")
            .unwrap()
            .serve_at(SERVICE, store.clone())
            .unwrap();
        for slot in store.slots.keys() {
            builder = builder
                .serve_at(
                    format!("{SERVICE}/item/{slot}"),
                    Item {
                        store: store.clone(),
                        slot: slot.clone(),
                    },
                )
                .unwrap();
        }
        fixture.connection = Some(builder.build().unwrap());
        fixture
    }
}

impl Drop for EnrolledStore {
    fn drop(&mut self) {
        self.connection.take();
        let _ = self.child.kill();
        self.child.wait().expect("reap owned fixture bus");
    }
}
