use super::*;
use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use serde::{Deserialize, Serialize};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Type, Value};

const SERVICE: &str = "/org/freedesktop/secrets";
const ITEM: &str = "/org/freedesktop/secrets/item/fixture";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/fixture";

#[derive(Clone, Copy, Debug)]
enum Mode {
    Unlocked,
    Missing,
    Locked,
    Ambiguous,
    Mixed,
    Relocked,
    StalledSearch,
    StalledRead,
    DelayedSearchThenStalledRead,
}

struct Observations {
    mode: Mode,
    value: Vec<u8>,
    searches: Vec<HashMap<String, String>>,
    reads: usize,
    unlocks: usize,
    prompts: usize,
    keys: BTreeMap<String, [u8; 16]>,
    senders: Vec<String>,
    stopping: bool,
    stalled: usize,
    wake: Option<std::task::Waker>,
    search_released: bool,
}

#[derive(Clone)]
struct Store(Arc<Mutex<Observations>>);

impl Store {
    async fn stall(&self) {
        self.wait(false).await;
    }

    async fn wait(&self, release_search: bool) {
        self.0.lock().unwrap().stalled += 1;
        std::future::poll_fn(|context| {
            let mut state = self.0.lock().unwrap();
            if state.stopping || (release_search && state.search_released) {
                std::task::Poll::Ready(())
            } else {
                state.wake = Some(context.waker().clone());
                std::task::Poll::Pending
            }
        })
        .await;
        self.0.lock().unwrap().stalled -= 1;
    }

    async fn shutdown(&self, connection: zbus::Connection) {
        {
            let mut state = self.0.lock().unwrap();
            state.stopping = true;
            if let Some(wake) = state.wake.take() {
                wake.wake();
            }
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while self.0.lock().unwrap().stalled != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fixture service retained a stalled method");
        connection.close().await.unwrap();
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Store {
    fn open_session(
        &self,
        algorithm: &str,
        input: OwnedValue,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> (OwnedValue, OwnedObjectPath) {
        assert_eq!(algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
        let public: Vec<u8> = input.try_into().unwrap();
        // Deliberately insecure fixture-only DH private exponent 1 makes the
        // shared value equal to the client's public value. Production retains
        // the existing secret-service implementation and its real random key.
        let mut shared = vec![0; 128 - public.len()];
        shared.extend(public);
        let mut key = [0; 16];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &shared)
            .expand(&[], &mut key)
            .unwrap();
        let mut state = self.0.lock().unwrap();
        let session = format!("{SERVICE}/session/s{}", state.keys.len());
        state.keys.insert(session.clone(), key);
        state.senders.push(header.sender().unwrap().to_string());
        (
            Value::from(vec![2u8]).try_to_owned().unwrap(),
            session.try_into().unwrap(),
        )
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let mode = {
            let mut state = self.0.lock().unwrap();
            state.searches.push(attributes);
            state.mode
        };
        let item = || OwnedObjectPath::try_from(ITEM).unwrap();
        match mode {
            Mode::Missing => (vec![], vec![]),
            Mode::Locked => (vec![], vec![item()]),
            Mode::Ambiguous => (vec![item(), item()], vec![]),
            Mode::Mixed => (vec![item()], vec![item()]),
            Mode::StalledSearch => {
                self.stall().await;
                (vec![], vec![])
            }
            Mode::DelayedSearchThenStalledRead => {
                self.wait(true).await;
                (vec![item()], vec![])
            }
            _ => (vec![item()], vec![]),
        }
    }

    fn unlock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.0.lock().unwrap().unlocks += 1;
        (vec![], PROMPT.try_into().unwrap())
    }
}

#[derive(Serialize, Deserialize, Type)]
struct SecretWire {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

struct Item(Store);

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    async fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<SecretWire> {
        let (mode, value, key) = {
            let mut state = self.0 .0.lock().unwrap();
            state.reads += 1;
            (
                state.mode,
                state.value.clone(),
                state.keys[session.as_str()],
            )
        };
        if matches!(mode, Mode::Relocked) {
            return Err(zbus::fdo::Error::Failed(
                "fixture backend text must not escape".into(),
            ));
        }
        if matches!(mode, Mode::StalledRead | Mode::DelayedSearchThenStalledRead) {
            self.0.stall().await;
            return Err(zbus::fdo::Error::Failed("fixture stopping".into()));
        }
        let iv = [7; 16];
        let encrypted = cbc::Encryptor::<aes::Aes128>::new(&key.into(), &iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(&value);
        Ok(SecretWire {
            session,
            parameters: iv.to_vec(),
            value: encrypted,
            content_type: "text/plain".into(),
        })
    }
}

struct Prompt(Store);

#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    fn prompt(&self, _window_id: &str) {
        self.0 .0.lock().unwrap().prompts += 1;
    }
}

struct Bus {
    child: Child,
    root: tempfile::TempDir,
}

impl Bus {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("bus.xml");
        let address = format!("unix:path={}", root.path().join("bus").display());
        // No service directories or activation helpers: a regression cannot
        // activate a real desktop credential service on this disposable bus.
        std::fs::write(&config, format!(
            "<busconfig><type>session</type><listen>{address}</listen><auth>EXTERNAL</auth><policy context=\"default\"><allow user=\"*\"/><allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>"
        )).unwrap();
        let child = Command::new("/usr/bin/dbus-daemon")
            .arg("--nofork")
            .arg("--nopidfile")
            .arg(format!("--config-file={}", config.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("native store test requires /usr/bin/dbus-daemon");
        let mut bus = Self { child, root };
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !bus.path().exists() {
            assert!(
                bus.child.try_wait().unwrap().is_none(),
                "fixture bus exited"
            );
            assert!(
                std::time::Instant::now() < deadline,
                "fixture bus did not start"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        bus
    }

    fn path(&self) -> std::path::PathBuf {
        self.root.path().join("bus")
    }

    async fn store(&self, mode: Mode, value: Vec<u8>) -> (zbus::Connection, Store) {
        let store = Store(Arc::new(Mutex::new(Observations {
            mode,
            value,
            searches: vec![],
            reads: 0,
            unlocks: 0,
            prompts: 0,
            keys: BTreeMap::new(),
            senders: vec![],
            stopping: false,
            stalled: 0,
            wake: None,
            search_released: false,
        })));
        let address = format!("unix:path={}", self.path().display());
        let connection = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .name("org.freedesktop.secrets")
            .unwrap()
            .serve_at(SERVICE, store.clone())
            .unwrap()
            .serve_at(ITEM, Item(store.clone()))
            .unwrap()
            .serve_at(PROMPT, Prompt(store.clone()))
            .unwrap()
            .build()
            .await
            .unwrap();
        (connection, store)
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        self.child.wait().expect("reap owned fixture bus");
    }
}

fn stores() -> BTreeMap<String, CredentialStore> {
    BTreeMap::from([(
        "fixture-slot".into(),
        CredentialStore {
            service: "dev-auth-v3".into(),
            account: "user-broker-service-account-token-fixture-slot".into(),
        },
    )])
}

fn run_test(future: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(15), future)
                .await
                .unwrap()
        });
}

async fn assert_disconnected(connection: &zbus::Connection, store: &Store) {
    let senders = store.0.lock().unwrap().senders.clone();
    let proxy = zbus::fdo::DBusProxy::new(connection).await.unwrap();
    for sender in senders {
        tokio::time::timeout(Duration::from_secs(2), async {
            while proxy
                .name_has_owner(sender.as_str().try_into().unwrap())
                .await
                .unwrap()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("credential connection survived its completed operation");
    }
}

#[test]
fn encrypted_unlocked_enrollment_uses_exact_attributes_and_disconnects() {
    let bus = Bus::new();
    run_test(async {
        let (connection, store) = bus
            .store(Mode::Unlocked, b"synthetic-fixture-token".to_vec())
            .await;
        let result = read_at(&bus.path(), &stores(), READ_BUDGET).await.unwrap();
        assert_eq!(result["fixture-slot"].expose(), "synthetic-fixture-token");
        {
            let state = store.0.lock().unwrap();
            assert_eq!(
                state.searches,
                vec![HashMap::from([
                    ("service".into(), "dev-auth-v3".into()),
                    (
                        "username".into(),
                        "user-broker-service-account-token-fixture-slot".into()
                    ),
                ])]
            );
            assert_eq!(state.reads, 1);
            assert_eq!((state.unlocks, state.prompts), (0, 0));
        }
        assert_disconnected(&connection, &store).await;
        store.shutdown(connection).await;
    });
}

#[test]
fn unavailable_or_ambiguous_enrollment_never_unlocks_prompts_or_falls_back() {
    for mode in [
        Mode::Missing,
        Mode::Locked,
        Mode::Ambiguous,
        Mode::Mixed,
        Mode::Relocked,
    ] {
        let bus = Bus::new();
        run_test(async {
            let (connection, store) = bus
                .store(mode, b"fixture backend text must not escape".to_vec())
                .await;
            let error = read_at(&bus.path(), &stores(), READ_BUDGET)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "enrolled credential is unavailable without interaction"
            );
            {
                let state = store.0.lock().unwrap();
                assert_eq!((state.unlocks, state.prompts), (0, 0), "{mode:?}");
                assert_eq!(
                    state.reads,
                    usize::from(matches!(mode, Mode::Relocked)),
                    "{mode:?}"
                );
            }
            assert_disconnected(&connection, &store).await;
            store.shutdown(connection).await;
        });
    }
}

#[test]
fn stalled_lookup_or_read_is_bounded_and_disconnects_without_retry() {
    for mode in [Mode::StalledSearch, Mode::StalledRead] {
        let bus = Bus::new();
        run_test(async {
            let (connection, store) = bus.store(mode, b"synthetic".to_vec()).await;
            let error = read_at(&bus.path(), &stores(), Duration::from_millis(300))
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "enrolled credential is unavailable without interaction"
            );
            {
                let state = store.0.lock().unwrap();
                assert_eq!(state.searches.len(), 1);
                assert_eq!((state.unlocks, state.prompts), (0, 0));
                assert_eq!(state.reads, usize::from(matches!(mode, Mode::StalledRead)));
            }
            assert_disconnected(&connection, &store).await;
            store.shutdown(connection).await;
        });
    }
}

#[test]
fn missing_service_and_stalled_authentication_fail_without_host_store_access() {
    let bus = Bus::new();
    run_test(async {
        assert!(read_at(&bus.path(), &stores(), READ_BUDGET).await.is_err());
    });
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("bus");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    run_test(async {
        assert!(read_at(&path, &stores(), Duration::from_millis(50))
            .await
            .is_err());
    });
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut bytes = Vec::new();
    use std::io::Read;
    peer.take(4096)
        .read_to_end(&mut bytes)
        .expect("timed-out authentication socket stayed open");
}

#[test]
fn malformed_and_oversized_secret_bytes_have_value_free_errors() {
    for bytes in [
        vec![],
        vec![0xff],
        b"synthetic\nvalue".to_vec(),
        vec![0],
        vec![b'x'; OP_SERVICE_TOKEN_LIMIT as usize + 1],
    ] {
        assert_eq!(
            token(bytes).unwrap_err().to_string(),
            "enrolled credential is unavailable without interaction"
        );
    }
    assert!(token(vec![b'x'; OP_SERVICE_TOKEN_LIMIT as usize]).is_ok());
}

#[test]
fn cancelled_inflight_read_closes_its_transport() {
    let bus = Bus::new();
    run_test(async {
        let (connection, store) = bus.store(Mode::StalledRead, b"synthetic".to_vec()).await;
        let path = bus.path();
        let stores = stores();
        let started = async {
            while store.0.lock().unwrap().reads == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        match select(
            Box::pin(read_at(&path, &stores, READ_BUDGET)),
            Box::pin(started),
        )
        .await
        {
            Either::Left(_) => panic!("stalled read returned before cancellation"),
            Either::Right(((), pending)) => drop(pending),
        }
        assert_disconnected(&connection, &store).await;
        {
            let state = store.0.lock().unwrap();
            assert_eq!((state.reads, state.unlocks, state.prompts), (1, 0, 0));
        }
        store.shutdown(connection).await;
    });
}

#[test]
fn encrypted_malformed_material_is_rejected_without_backend_diagnostics() {
    for value in [
        vec![0xff],
        b"synthetic\rvalue".to_vec(),
        vec![b'x'; OP_SERVICE_TOKEN_LIMIT as usize + 1],
    ] {
        let bus = Bus::new();
        run_test(async {
            let (connection, store) = bus.store(Mode::Unlocked, value).await;
            let error = read_at(&bus.path(), &stores(), READ_BUDGET)
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "enrolled credential is unavailable without interaction"
            );
            assert_eq!(store.0.lock().unwrap().reads, 1);
            assert_disconnected(&connection, &store).await;
            store.shutdown(connection).await;
        });
    }
}

#[test]
fn slot_read_does_not_receive_a_new_budget_after_slow_lookup() {
    let bus = Bus::new();
    run_test(async {
        let (connection, store) = bus
            .store(Mode::DelayedSearchThenStalledRead, b"synthetic".to_vec())
            .await;
        let path = bus.path();
        let stores = stores();
        let release_search = async {
            while store.0.lock().unwrap().searches.is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tokio::time::sleep(Duration::from_millis(1500)).await;
            {
                let mut state = store.0.lock().unwrap();
                state.search_released = true;
                if let Some(wake) = state.wake.take() {
                    wake.wake();
                }
            }
            std::future::pending::<()>().await;
        };
        // Per-call two-second timeouts would allow the second call to survive
        // this deadline. The actual whole-read budget must already be exhausted.
        let result = tokio::time::timeout(
            Duration::from_millis(2700),
            select(
                Box::pin(read_at(&path, &stores, Duration::from_secs(2))),
                Box::pin(release_search),
            ),
        )
        .await
        .expect("lookup renewed the credential-read budget");
        match result {
            Either::Left((result, _)) => assert!(result.is_err()),
            Either::Right(_) => panic!("fixture release unexpectedly completed"),
        }
        assert_eq!(
            store.0.lock().unwrap().reads,
            1,
            "lookup did not reach the second stage"
        );
        assert_disconnected(&connection, &store).await;
        store.shutdown(connection).await;
    });
}
