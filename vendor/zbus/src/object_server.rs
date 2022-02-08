use async_lock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::{
    collections::{hash_map::Entry, HashMap},
    convert::TryInto,
    fmt::Write,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use static_assertions::assert_impl_all;
use zbus_names::InterfaceName;
use zvariant::{ObjectPath, OwnedObjectPath};

use crate::{
    fdo,
    fdo::{Introspectable, Peer, Properties},
    Connection, DispatchResult, Error, Interface, Message, MessageType, Result, SignalContext,
    WeakConnection,
};

/// Opaque structure that derefs to an `Interface` type.
pub struct InterfaceDeref<'d, I> {
    iface: RwLockReadGuard<'d, dyn Interface>,
    phantom: PhantomData<I>,
}

impl<I> Deref for InterfaceDeref<'_, I>
where
    I: Interface,
{
    type Target = I;

    fn deref(&self) -> &I {
        self.iface.downcast_ref::<I>().unwrap()
    }
}

/// Opaque structure that mutably derefs to an `Interface` type.
pub struct InterfaceDerefMut<'d, I> {
    iface: RwLockWriteGuard<'d, dyn Interface>,
    phantom: PhantomData<I>,
}

impl<I> Deref for InterfaceDerefMut<'_, I>
where
    I: Interface,
{
    type Target = I;

    fn deref(&self) -> &I {
        self.iface.downcast_ref::<I>().unwrap()
    }
}

impl<I> DerefMut for InterfaceDerefMut<'_, I>
where
    I: Interface,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.iface.downcast_mut::<I>().unwrap()
    }
}

/// Wrapper over an interface, along with its corresponding `SignalContext`
/// instance. A reference to the underlying interface may be obtained via
/// [`InterfaceRef::get`] and [`InterfaceRef::get_mut`].
pub struct InterfaceRef<I> {
    ctxt: SignalContext<'static>,
    lock: Arc<RwLock<dyn Interface>>,
    phantom: PhantomData<I>,
}

impl<I> InterfaceRef<I>
where
    I: 'static,
{
    /// Get a reference to the underlying interface.
    pub async fn get(&self) -> InterfaceDeref<'_, I> {
        let iface = self.lock.read().await;

        iface
            .downcast_ref::<I>()
            .expect("Unexpected interface type");

        InterfaceDeref {
            iface,
            phantom: PhantomData,
        }
    }

    /// Get a reference to the underlying interface.
    ///
    /// **WARNINGS:** Since the `ObjectServer` will not be able to access the interface in question
    /// until the return value of this method is dropped, it is highly recommended that the scope
    /// of the interface returned is restricted.
    ///
    /// # Errors
    ///
    /// If the interface at this instance's path is not valid, `Error::InterfaceNotFound` error is
    /// returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    ///# use std::error::Error;
    ///# use async_io::block_on;
    ///# use zbus::{Connection, ObjectServer, SignalContext, dbus_interface};
    ///
    /// struct MyIface(u32);
    ///
    /// #[dbus_interface(name = "org.myiface.MyIface")]
    /// impl MyIface {
    ///    #[dbus_interface(property)]
    ///    async fn count(&self) -> u32 {
    ///        self.0
    ///    }
    /// }
    ///
    ///# block_on(async {
    /// // Setup connection and object_server etc here and then in another part of the code:
    ///# let connection = Connection::session().await?;
    ///#
    ///# let path = "/org/zbus/path";
    ///# connection.object_server().at(path, MyIface(22)).await?;
    /// let mut object_server = connection.object_server();
    /// let iface_ref = object_server.interface::<_, MyIface>(path).await?;
    /// let mut iface = iface_ref.get_mut().await;
    /// iface.0 = 42;
    /// iface.count_changed(iface_ref.signal_context()).await?;
    ///# Ok::<_, Box<dyn Error + Send + Sync>>(())
    ///# })?;
    ///#
    ///# Ok::<_, Box<dyn Error + Send + Sync>>(())
    /// ```
    pub async fn get_mut(&self) -> InterfaceDerefMut<'_, I> {
        let mut iface = self.lock.write().await;

        iface
            .downcast_ref::<I>()
            .expect("Unexpected interface type");
        iface
            .downcast_mut::<I>()
            .expect("Unexpected interface type");

        InterfaceDerefMut {
            iface,
            phantom: PhantomData,
        }
    }

    pub fn signal_context(&self) -> &SignalContext<'static> {
        &self.ctxt
    }
}

#[derive(Default, derivative::Derivative)]
#[derivative(Debug)]
pub(crate) struct Node {
    path: OwnedObjectPath,
    children: HashMap<String, Node>,
    #[derivative(Debug = "ignore")]
    interfaces: HashMap<InterfaceName<'static>, Arc<RwLock<dyn Interface>>>,
}

impl Node {
    pub(crate) fn new(path: OwnedObjectPath) -> Self {
        let mut node = Self {
            path,
            ..Default::default()
        };
        node.at(Peer::name(), Peer);
        node.at(Introspectable::name(), Introspectable);
        node.at(Properties::name(), Properties);

        node
    }

    // Get the child Node at path.
    pub(crate) fn get_child(&self, path: &ObjectPath<'_>) -> Option<&Node> {
        let mut node = self;

        for i in path.split('/').skip(1) {
            if i.is_empty() {
                continue;
            }
            match node.children.get(i) {
                Some(n) => node = n,
                None => return None,
            }
        }

        Some(node)
    }

    // Get the child Node at path. Optionally create one if it doesn't exist.
    fn get_child_mut(&mut self, path: &ObjectPath<'_>, create: bool) -> Option<&mut Node> {
        let mut node = self;
        let mut node_path = String::new();

        for i in path.split('/').skip(1) {
            if i.is_empty() {
                continue;
            }
            write!(&mut node_path, "/{}", i).unwrap();
            match node.children.entry(i.into()) {
                Entry::Vacant(e) => {
                    if create {
                        let path = node_path.as_str().try_into().expect("Invalid Object Path");
                        node = e.insert(Node::new(path));
                    } else {
                        return None;
                    }
                }
                Entry::Occupied(e) => node = e.into_mut(),
            }
        }

        Some(node)
    }

    pub(crate) fn interface_lock(
        &self,
        interface_name: InterfaceName<'_>,
    ) -> Option<Arc<RwLock<dyn Interface>>> {
        self.interfaces.get(&interface_name).cloned()
    }

    fn remove_interface(&mut self, interface_name: InterfaceName<'static>) -> bool {
        self.interfaces.remove(&interface_name).is_some()
    }

    fn is_empty(&self) -> bool {
        !self
            .interfaces
            .keys()
            .any(|k| *k != Peer::name() && *k != Introspectable::name() && *k != Properties::name())
    }

    fn remove_node(&mut self, node: &str) -> bool {
        self.children.remove(node).is_some()
    }

    fn at<I>(&mut self, name: InterfaceName<'static>, iface: I) -> bool
    where
        I: Interface,
    {
        match self.interfaces.entry(name) {
            Entry::Vacant(e) => e.insert(Arc::new(RwLock::new(iface))),
            Entry::Occupied(_) => return false,
        };

        true
    }

    // FIXME: Better name?
    fn at_ready(
        &mut self,
        name: InterfaceName<'static>,
        iface: Arc<RwLock<dyn Interface>>,
    ) -> bool {
        match self.interfaces.entry(name) {
            Entry::Vacant(e) => e.insert(iface),
            Entry::Occupied(_) => return false,
        };

        true
    }

    #[async_recursion::async_recursion]
    async fn introspect_to_writer<W: Write + Send>(&self, writer: &mut W, level: usize) {
        if level == 0 {
            writeln!(
                writer,
                r#"
<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>"#
            )
            .unwrap();
        }

        for iface in self.interfaces.values() {
            iface.read().await.introspect_to_writer(writer, level + 2);
        }

        for (path, node) in &self.children {
            let level = level + 2;
            writeln!(
                writer,
                "{:indent$}<node name=\"{}\">",
                "",
                path,
                indent = level
            )
            .unwrap();
            node.introspect_to_writer(writer, level).await;
            writeln!(writer, "{:indent$}</node>", "", indent = level).unwrap();
        }

        if level == 0 {
            writeln!(writer, "</node>").unwrap();
        }
    }

    pub(crate) async fn introspect(&self) -> String {
        let mut xml = String::with_capacity(1024);

        self.introspect_to_writer(&mut xml, 0).await;

        xml
    }
}

/// An object server, holding server-side D-Bus objects & interfaces.
///
/// Object servers hold interfaces on various object paths, and expose them over D-Bus.
///
/// All object paths will have the standard interfaces implemented on your behalf, such as
/// `org.freedesktop.DBus.Introspectable` or `org.freedesktop.DBus.Properties`.
///
/// # Example
///
/// This example exposes the `org.myiface.Example.Quit` method on the `/org/zbus/path`
/// path.
///
/// ```no_run
///# use std::error::Error;
/// use zbus::{Connection, ObjectServer, dbus_interface};
/// use std::sync::Arc;
/// use event_listener::Event;
///# use async_io::block_on;
///
/// struct Example {
///     // Interfaces are owned by the ObjectServer. They can have
///     // `&mut self` methods.
///     quit_event: Event,
/// }
///
/// impl Example {
///     fn new(quit_event: Event) -> Self {
///         Self { quit_event }
///     }
/// }
///
/// #[dbus_interface(name = "org.myiface.Example")]
/// impl Example {
///     // This will be the "Quit" D-Bus method.
///     async fn quit(&mut self) {
///         self.quit_event.notify(1);
///     }
///
///     // See `dbus_interface` documentation to learn
///     // how to expose properties & signals as well.
/// }
///
///# block_on(async {
/// let connection = Connection::session().await?;
///
/// let quit_event = Event::new();
/// let quit_listener = quit_event.listen();
/// let interface = Example::new(quit_event);
/// connection
///     .object_server()
///     .at("/org/zbus/path", interface)
///     .await?;
///
/// quit_listener.await;
///# Ok::<_, Box<dyn Error + Send + Sync>>(())
///# });
///# Ok::<_, Box<dyn Error + Send + Sync>>(())
/// ```
#[derive(Debug)]
pub struct ObjectServer {
    conn: WeakConnection,
    root: RwLock<Node>,
}

assert_impl_all!(ObjectServer: Send, Sync, Unpin);

impl ObjectServer {
    /// Creates a new D-Bus `ObjectServer`.
    pub(crate) fn new(conn: &Connection) -> Self {
        Self {
            conn: conn.into(),
            root: RwLock::new(Node::new("/".try_into().expect("zvariant bug"))),
        }
    }

    pub(crate) fn root(&self) -> &RwLock<Node> {
        &self.root
    }

    /// Register a D-Bus [`Interface`] at a given path. (see the example above)
    ///
    /// Typically you'd want your interfaces to be registered immediately after the associated
    /// connection is established and therefore use [`zbus::ConnectionBuilder::serve_at`] instead.
    /// However, there are situations where you'd need to register interfaces dynamically and that's
    /// where this method becomes useful.
    ///
    /// If the interface already exists at this path, returns false.
    pub async fn at<'p, P, I>(&self, path: P, iface: I) -> Result<bool>
    where
        I: Interface,
        P: TryInto<ObjectPath<'p>>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        Ok(self
            .root
            .write()
            .await
            .get_child_mut(&path, true)
            .unwrap()
            .at_ready(I::name(), Arc::new(RwLock::new(iface))))
    }

    /// Same as `at` but expects an interface already in `Arc<RwLock<dyn Interface>>` form.
    // FIXME: Better name?
    pub(crate) async fn at_ready<'node, P>(
        &'node self,
        path: P,
        name: InterfaceName<'static>,
        iface: Arc<RwLock<dyn Interface + 'static>>,
    ) -> Result<bool>
    where
        // Needs to be hardcoded as 'static instead of 'p like most other
        // functions, due to https://github.com/rust-lang/rust/issues/63033
        // (It doesn't matter a whole lot since this is an internal-only API
        // anyway.)
        P: TryInto<ObjectPath<'static>>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        Ok(self
            .root()
            .write()
            .await
            .get_child_mut(&path, true)
            .unwrap()
            .at_ready(name, iface))
    }

    /// Unregister a D-Bus [`Interface`] at a given path.
    ///
    /// If there are no more interfaces left at that path, destroys the object as well.
    /// Returns whether the object was destroyed.
    pub async fn remove<'p, I, P>(&self, path: P) -> Result<bool>
    where
        I: Interface,
        P: TryInto<ObjectPath<'p>>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        let mut root = self.root.write().await;
        let node = root
            .get_child_mut(&path, false)
            .ok_or(Error::InterfaceNotFound)?;
        if !node.remove_interface(I::name()) {
            return Err(Error::InterfaceNotFound);
        }
        if node.is_empty() {
            let mut path_parts = path.rsplit('/').filter(|i| !i.is_empty());
            let last_part = path_parts.next().unwrap();
            let ppath = ObjectPath::from_string_unchecked(
                path_parts.fold(String::new(), |a, p| format!("/{}{}", p, a)),
            );
            root.get_child_mut(&ppath, false)
                .unwrap()
                .remove_node(last_part);
            return Ok(true);
        }
        Ok(false)
    }

    /// Get the interface at the given path.
    ///
    /// # Errors
    ///
    /// If the interface is not registered at the given path, `Error::InterfaceNotFound` error is
    /// returned.
    ///
    /// # Examples
    ///
    /// The typical use of this is property changes outside of a dispatched handler:
    ///
    /// ```no_run
    ///# use std::error::Error;
    ///# use zbus::{Connection, InterfaceDerefMut, ObjectServer, SignalContext, dbus_interface};
    ///# use async_io::block_on;
    ///#
    /// struct MyIface(u32);
    ///
    /// #[dbus_interface(name = "org.myiface.MyIface")]
    /// impl MyIface {
    ///      #[dbus_interface(property)]
    ///      async fn count(&self) -> u32 {
    ///          self.0
    ///      }
    /// }
    ///
    ///# block_on(async {
    ///# let connection = Connection::session().await?;
    ///#
    ///# let path = "/org/zbus/path";
    ///# connection.object_server().at(path, MyIface(0)).await?;
    /// let iface_ref = connection
    ///     .object_server()
    ///     .interface::<_, MyIface>(path).await?;
    /// let mut iface = iface_ref.get_mut().await;
    /// iface.0 = 42;
    /// iface.count_changed(iface_ref.signal_context()).await?;
    ///# Ok::<_, Box<dyn Error + Send + Sync>>(())
    ///# })?;
    ///#
    ///# Ok::<_, Box<dyn Error + Send + Sync>>(())
    /// ```
    pub async fn interface<'p, P, I>(&self, path: P) -> Result<InterfaceRef<I>>
    where
        I: Interface,
        P: TryInto<ObjectPath<'p>>,
        P::Error: Into<Error>,
    {
        let path = path.try_into().map_err(Into::into)?;
        let root = self.root().read().await;
        let node = root.get_child(&path).ok_or(Error::InterfaceNotFound)?;

        let lock = node
            .interface_lock(I::name())
            .ok_or(Error::InterfaceNotFound)?
            .clone();

        // Ensure what we return can later be dowcasted safely.
        lock.read()
            .await
            .downcast_ref::<I>()
            .ok_or(Error::InterfaceNotFound)?;

        let conn = self.connection();
        // SAFETY: We know that there is a valid path on the node as we already converted w/o error.
        let ctxt = SignalContext::new(&conn, path).unwrap().into_owned();

        Ok(InterfaceRef {
            ctxt,
            lock,
            phantom: PhantomData,
        })
    }

    async fn dispatch_method_call_try(
        &self,
        connection: &Connection,
        msg: &Message,
    ) -> fdo::Result<Result<()>> {
        let path = msg
            .path()
            .ok_or_else(|| fdo::Error::Failed("Missing object path".into()))?;
        let iface = msg
            .interface()
            // TODO: In the absence of an INTERFACE field, if two or more interfaces on the same object
            // have a method with the same name, it is undefined which of those methods will be
            // invoked. Implementations may choose to either return an error, or deliver the message
            // as though it had an arbitrary one of those interfaces.
            .ok_or_else(|| fdo::Error::Failed("Missing interface".into()))?;
        let member = msg
            .member()
            .ok_or_else(|| fdo::Error::Failed("Missing member".into()))?;

        // Ensure the root lock isn't held while dispatching the message. That
        // way, the object server can be mutated during that time.
        let iface = {
            let root = self.root.read().await;
            let node = root
                .get_child(&path)
                .ok_or_else(|| fdo::Error::UnknownObject(format!("Unknown object '{}'", path)))?;

            node.interface_lock(iface.as_ref()).ok_or_else(|| {
                fdo::Error::UnknownInterface(format!("Unknown interface '{}'", iface))
            })?
        };

        let read_lock = iface.read().await;
        match read_lock.call(self, connection, msg, member.as_ref()) {
            DispatchResult::NotFound => {
                return Err(fdo::Error::UnknownMethod(format!(
                    "Unknown method '{}'",
                    member
                )));
            }
            DispatchResult::Async(f) => {
                return Ok(f.await);
            }
            DispatchResult::RequiresMut => {}
        }
        drop(read_lock);
        let mut write_lock = iface.write().await;
        match write_lock.call_mut(self, connection, msg, member.as_ref()) {
            DispatchResult::NotFound => {}
            DispatchResult::RequiresMut => {}
            DispatchResult::Async(f) => {
                return Ok(f.await);
            }
        }
        drop(write_lock);
        Err(fdo::Error::UnknownMethod(format!(
            "Unknown method '{}'",
            member
        )))
    }

    async fn dispatch_method_call(&self, connection: &Connection, msg: &Message) -> Result<()> {
        match self.dispatch_method_call_try(connection, msg).await {
            Err(e) => {
                let hdr = msg.header()?;
                connection.reply_dbus_error(&hdr, e).await?;
                Ok(())
            }
            Ok(r) => r,
        }
    }

    /// Dispatch an incoming message to a registered interface.
    ///
    /// The object server will handle the message by:
    ///
    /// - looking up the called object path & interface,
    ///
    /// - calling the associated method if one exists,
    ///
    /// - returning a message (responding to the caller with either a return or error message) to
    ///   the caller through the associated server connection.
    ///
    /// Returns an error if the message is malformed, true if it's handled, false otherwise.
    pub(crate) async fn dispatch_message(&self, msg: &Message) -> Result<bool> {
        match msg.message_type() {
            MessageType::MethodCall => {
                let conn = self.connection();
                self.dispatch_method_call(&conn, msg).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    pub(crate) fn connection(&self) -> Connection {
        self.conn
            .upgrade()
            .expect("ObjectServer can't exist w/o an associated Connection")
    }
}

impl From<crate::blocking::ObjectServer> for ObjectServer {
    fn from(server: crate::blocking::ObjectServer) -> Self {
        server.into_inner()
    }
}

#[cfg(test)]
#[allow(clippy::blacklisted_name)]
mod tests {
    #[cfg(all(unix, feature = "async-io"))]
    use std::os::unix::net::UnixStream;
    use std::{collections::HashMap, convert::TryInto};
    #[cfg(all(unix, not(feature = "async-io")))]
    use tokio::net::UnixStream;

    use crate::utils::block_on;
    use async_channel::{bounded, Sender};
    use event_listener::Event;
    use futures_util::StreamExt;
    use ntest::timeout;
    use serde::{Deserialize, Serialize};
    use test_log::test;
    use zbus::DBusError;
    use zvariant::{DeserializeDict, OwnedValue, SerializeDict, Type, Value};

    use crate::{
        dbus_interface, dbus_proxy, CacheProperties, Connection, ConnectionBuilder, InterfaceRef,
        MessageHeader, MessageType, ObjectServer, SignalContext,
    };

    #[derive(Deserialize, Serialize, Type)]
    pub struct ArgStructTest {
        foo: i32,
        bar: String,
    }

    // Mimic a NetworkManager interface property that's a dict. This tests ability to use a custom
    // dict type using the `Type` And `*Dict` macros (issue #241).
    #[derive(DeserializeDict, SerializeDict, Type, Debug, Value, OwnedValue, PartialEq)]
    #[zvariant(signature = "dict")]
    pub struct IP4Adress {
        prefix: u32,
        address: String,
    }

    #[dbus_proxy(gen_blocking = false)]
    trait MyIface {
        fn ping(&self) -> zbus::Result<u32>;

        fn quit(&self) -> zbus::Result<()>;

        fn test_header(&self) -> zbus::Result<()>;

        fn test_error(&self) -> zbus::Result<()>;

        fn test_single_struct_arg(&self, arg: ArgStructTest) -> zbus::Result<()>;

        fn test_single_struct_ret(&self) -> zbus::Result<ArgStructTest>;

        fn test_multi_ret(&self) -> zbus::Result<(i32, String)>;

        fn test_hashmap_return(&self) -> zbus::Result<HashMap<String, String>>;

        fn create_obj(&self, key: &str) -> zbus::Result<()>;

        fn destroy_obj(&self, key: &str) -> zbus::Result<()>;

        #[dbus_proxy(property)]
        fn count(&self) -> zbus::Result<u32>;

        #[dbus_proxy(property)]
        fn set_count(&self, count: u32) -> zbus::Result<()>;

        #[dbus_proxy(property)]
        fn hash_map(&self) -> zbus::Result<HashMap<String, String>>;

        #[dbus_proxy(property)]
        fn address_data(&self) -> zbus::Result<IP4Adress>;

        #[dbus_proxy(property)]
        fn address_data2(&self) -> zbus::Result<IP4Adress>;
    }

    #[derive(Debug, Clone)]
    enum NextAction {
        Quit,
        CreateObj(String),
        DestroyObj(String),
    }

    struct MyIfaceImpl {
        next_tx: Sender<NextAction>,
        count: u32,
    }

    impl MyIfaceImpl {
        fn new(next_tx: Sender<NextAction>) -> Self {
            Self { next_tx, count: 0 }
        }
    }

    /// Custom D-Bus error type.
    #[derive(Debug, DBusError)]
    #[dbus_error(prefix = "org.freedesktop.MyIface.Error")]
    enum MyIfaceError {
        SomethingWentWrong(String),
        #[dbus_error(zbus_error)]
        ZBus(zbus::Error),
    }

    #[dbus_interface(interface = "org.freedesktop.MyIface")]
    impl MyIfaceImpl {
        async fn ping(&mut self, #[zbus(signal_context)] ctxt: SignalContext<'_>) -> u32 {
            self.count += 1;
            if self.count % 3 == 0 {
                MyIfaceImpl::alert_count(&ctxt, self.count)
                    .await
                    .expect("Failed to emit signal");
            }
            self.count
        }

        async fn quit(&self) {
            self.next_tx.send(NextAction::Quit).await.unwrap();
        }

        fn test_header(&self, #[zbus(header)] header: MessageHeader<'_>) {
            assert_eq!(header.message_type().unwrap(), MessageType::MethodCall);
            assert_eq!(header.member().unwrap().unwrap(), "TestHeader");
        }

        fn test_error(&self) -> zbus::fdo::Result<()> {
            Err(zbus::fdo::Error::Failed("error raised".to_string()))
        }

        fn test_custom_error(&self) -> Result<(), MyIfaceError> {
            Err(MyIfaceError::SomethingWentWrong("oops".to_string()))
        }

        fn test_single_struct_arg(
            &self,
            arg: ArgStructTest,
            #[zbus(header)] header: MessageHeader<'_>,
        ) -> zbus::fdo::Result<()> {
            assert_eq!(header.signature()?.unwrap(), "(is)");
            assert_eq!(arg.foo, 1);
            assert_eq!(arg.bar, "TestString");

            Ok(())
        }

        fn test_single_struct_ret(&self) -> zbus::fdo::Result<ArgStructTest> {
            Ok(ArgStructTest {
                foo: 42,
                bar: String::from("Meaning of life"),
            })
        }

        #[dbus_interface(out_args("foo", "bar"))]
        fn test_multi_ret(&self) -> zbus::fdo::Result<(i32, String)> {
            Ok((42, String::from("Meaning of life")))
        }

        async fn test_hashmap_return(&self) -> zbus::fdo::Result<HashMap<String, String>> {
            let mut map = HashMap::new();
            map.insert("hi".into(), "hello".into());
            map.insert("bye".into(), "now".into());

            Ok(map)
        }

        async fn create_obj(&self, key: String) {
            self.next_tx.send(NextAction::CreateObj(key)).await.unwrap();
        }

        async fn create_obj_inside(
            &self,
            #[zbus(object_server)] object_server: &ObjectServer,
            key: String,
        ) {
            object_server
                .at(
                    format!("/zbus/test/{}", key),
                    MyIfaceImpl::new(self.next_tx.clone()),
                )
                .await
                .unwrap();
        }

        async fn destroy_obj(&self, key: String) {
            self.next_tx
                .send(NextAction::DestroyObj(key))
                .await
                .unwrap();
        }

        #[dbus_interface(property)]
        fn set_count(&mut self, val: u32) -> zbus::fdo::Result<()> {
            if val == 42 {
                return Err(zbus::fdo::Error::InvalidArgs("Tsss tsss!".to_string()));
            }
            self.count = val;
            Ok(())
        }

        #[dbus_interface(property)]
        fn count(&self) -> u32 {
            self.count
        }

        #[dbus_interface(property)]
        async fn hash_map(&self) -> HashMap<String, String> {
            self.test_hashmap_return().await.unwrap()
        }

        #[dbus_interface(property)]
        fn address_data(&self) -> IP4Adress {
            IP4Adress {
                address: "127.0.0.1".to_string(),
                prefix: 1234,
            }
        }

        // On the bus, this should return the same value as address_data above. We want to test if
        // this works both ways.
        #[dbus_interface(property)]
        fn address_data2(&self) -> HashMap<String, OwnedValue> {
            let mut map = HashMap::new();
            map.insert("address".into(), Value::from("127.0.0.1").into());
            map.insert("prefix".into(), 1234u32.into());

            map
        }

        #[dbus_interface(signal)]
        async fn alert_count(ctxt: &SignalContext<'_>, val: u32) -> zbus::Result<()>;
    }

    fn check_hash_map(map: HashMap<String, String>) {
        assert_eq!(map["hi"], "hello");
        assert_eq!(map["bye"], "now");
    }

    fn check_ipv4_address(address: IP4Adress) {
        assert_eq!(
            address,
            IP4Adress {
                address: "127.0.0.1".to_string(),
                prefix: 1234,
            }
        );
    }

    async fn my_iface_test(conn: Connection, event: Event) -> zbus::Result<u32> {
        let proxy = MyIfaceProxy::builder(&conn)
            .destination("org.freedesktop.MyService")?
            .path("/org/freedesktop/MyService")?
            // the server isn't yet running
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let props_proxy = zbus::fdo::PropertiesProxy::builder(&conn)
            .destination("org.freedesktop.MyService")?
            .path("/org/freedesktop/MyService")?
            .build()
            .await?;

        let mut props_changed_stream = props_proxy.receive_properties_changed().await?;
        event.notify(1);

        match props_changed_stream.next().await {
            Some(changed) => {
                assert_eq!(
                    *changed.args()?.changed_properties().keys().next().unwrap(),
                    "Count"
                );
            }
            None => panic!(""),
        };

        proxy.ping().await?;
        assert_eq!(proxy.count().await?, 1);
        assert_eq!(proxy.cached_count()?, None);

        proxy.test_header().await?;
        proxy
            .test_single_struct_arg(ArgStructTest {
                foo: 1,
                bar: "TestString".into(),
            })
            .await?;
        check_hash_map(proxy.test_hashmap_return().await?);
        check_hash_map(proxy.hash_map().await?);
        check_ipv4_address(proxy.address_data().await?);
        check_ipv4_address(proxy.address_data2().await?);

        #[cfg(feature = "xml")]
        {
            let xml = proxy.introspect().await?;
            let node = crate::xml::Node::from_reader(xml.as_bytes())?;
            let ifaces = node.interfaces();
            let iface = ifaces
                .iter()
                .find(|i| i.name() == "org.freedesktop.MyIface")
                .unwrap();
            let methods = iface.methods();
            for method in methods {
                if method.name() != "TestSingleStructRet" && method.name() != "TestMultiRet" {
                    continue;
                }
                let args = method.args();
                let mut out_args = args.iter().filter(|a| a.direction().unwrap() == "out");

                if method.name() == "TestSingleStructRet" {
                    assert_eq!(args.len(), 1);
                    assert_eq!(out_args.next().unwrap().ty(), "(is)");
                    assert!(out_args.next().is_none());
                } else {
                    assert_eq!(args.len(), 2);
                    let foo = out_args.find(|a| a.name() == Some("foo")).unwrap();
                    assert_eq!(foo.ty(), "i");
                    let bar = out_args.find(|a| a.name() == Some("bar")).unwrap();
                    assert_eq!(bar.ty(), "s");
                }
            }
        }
        // build-time check to see if macro is doing the right thing.
        let _ = proxy.test_single_struct_ret().await?.foo;
        let _ = proxy.test_multi_ret().await?.1;

        let val = proxy.ping().await?;

        proxy.create_obj("MyObj").await?;
        // issue#207: interface panics on incorrect number of args.
        assert!(proxy.call_method("CreateObj", &()).await.is_err());

        let my_obj_proxy = MyIfaceProxy::builder(&conn)
            .destination("org.freedesktop.MyService")?
            .path("/zbus/test/MyObj")?
            .build()
            .await?;
        my_obj_proxy.receive_count_changed().await;
        // Calling this after creating the stream was panicking (MR !460)
        assert_eq!(my_obj_proxy.cached_count()?, None);
        assert_eq!(my_obj_proxy.count().await?, 0);
        assert_eq!(my_obj_proxy.cached_count()?, Some(0));
        assert_eq!(
            my_obj_proxy.cached_property_raw("Count").as_deref(),
            Some(&Value::from(0u32))
        );
        my_obj_proxy.ping().await?;
        proxy.destroy_obj("MyObj").await?;
        assert!(my_obj_proxy.introspect().await.is_err());
        assert!(my_obj_proxy.ping().await.is_err());

        // Make sure methods modifying the ObjectServer can be called without
        // deadlocks.
        proxy
            .call_method("CreateObjInside", &("CreatedInside"))
            .await?;
        let created_inside_proxy = MyIfaceProxy::builder(&conn)
            .destination("org.freedesktop.MyService")?
            .path("/zbus/test/CreatedInside")?
            .build()
            .await?;
        created_inside_proxy.ping().await?;
        proxy.destroy_obj("CreatedInside").await?;

        proxy.quit().await?;
        Ok(val)
    }

    #[test]
    #[timeout(15000)]
    fn basic_iface() {
        block_on(basic_iface_(false));
    }

    #[cfg(unix)]
    #[test]
    #[timeout(15000)]
    fn basic_iface_unix_p2p() {
        block_on(basic_iface_(true));
    }

    async fn basic_iface_(p2p: bool) {
        let event = event_listener::Event::new();
        let guid = zbus::Guid::generate();

        let (service_conn_builder, client_conn_builder) = if p2p {
            #[cfg(unix)]
            {
                let (p0, p1) = UnixStream::pair().unwrap();

                (
                    ConnectionBuilder::unix_stream(p0).server(&guid).p2p(),
                    ConnectionBuilder::unix_stream(p1).p2p(),
                )
            }
            #[cfg(windows)]
            {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let addr = listener.local_addr().unwrap();
                let p1 = std::net::TcpStream::connect(addr).unwrap();
                let p0 = listener.incoming().next().unwrap().unwrap();

                (
                    ConnectionBuilder::tcp_stream(p0).server(&guid).p2p(),
                    ConnectionBuilder::tcp_stream(p1).p2p(),
                )
            }
        } else {
            let service_conn_builder = ConnectionBuilder::session()
                .unwrap()
                .name("org.freedesktop.MyService")
                .unwrap()
                .name("org.freedesktop.MyService.foo")
                .unwrap()
                .name("org.freedesktop.MyService.bar")
                .unwrap();
            let client_conn_builder = ConnectionBuilder::session().unwrap();

            (service_conn_builder, client_conn_builder)
        };
        let (next_tx, next_rx) = bounded(64);
        let iface = MyIfaceImpl::new(next_tx.clone());
        let service_conn_builder = service_conn_builder
            .serve_at("/org/freedesktop/MyService", iface)
            .unwrap();

        let (service_conn, client_conn) =
            futures_util::try_join!(service_conn_builder.build(), client_conn_builder.build(),)
                .unwrap();

        let listen = event.listen();
        let child = async_std::task::spawn(my_iface_test(client_conn, event));
        // Wait for the listener to be ready
        listen.await;

        let iface: InterfaceRef<MyIfaceImpl> = service_conn
            .object_server()
            .interface("/org/freedesktop/MyService")
            .await
            .unwrap();
        iface
            .get()
            .await
            .count_changed(iface.signal_context())
            .await
            .unwrap();

        loop {
            MyIfaceImpl::alert_count(iface.signal_context(), 51)
                .await
                .unwrap();

            match next_rx.recv().await.unwrap() {
                NextAction::Quit => break,
                NextAction::CreateObj(key) => {
                    let path = format!("/zbus/test/{}", key);
                    service_conn
                        .object_server()
                        .at(path, MyIfaceImpl::new(next_tx.clone()))
                        .await
                        .unwrap();
                }
                NextAction::DestroyObj(key) => {
                    let path = format!("/zbus/test/{}", key);
                    service_conn
                        .object_server()
                        .remove::<MyIfaceImpl, _>(path)
                        .await
                        .unwrap();
                }
            }
        }

        let val = child.await.unwrap();
        assert_eq!(val, 2);

        if p2p {
            return;
        }

        // Release primary name explicitly and let others be released implicitly.
        assert_eq!(
            service_conn.release_name("org.freedesktop.MyService").await,
            Ok(true)
        );
        assert_eq!(
            service_conn
                .release_name("org.freedesktop.MyService.foo")
                .await,
            Ok(true)
        );
        assert_eq!(
            service_conn
                .release_name("org.freedesktop.MyService.bar")
                .await,
            Ok(true)
        );

        // Let's ensure all names were released.
        let proxy = zbus::fdo::DBusProxy::new(&service_conn).await.unwrap();
        assert_eq!(
            proxy
                .name_has_owner("org.freedesktop.MyService".try_into().unwrap())
                .await,
            Ok(false)
        );
        assert_eq!(
            proxy
                .name_has_owner("org.freedesktop.MyService.foo".try_into().unwrap())
                .await,
            Ok(false)
        );
        assert_eq!(
            proxy
                .name_has_owner("org.freedesktop.MyService.bar".try_into().unwrap())
                .await,
            Ok(false)
        );
    }
}
