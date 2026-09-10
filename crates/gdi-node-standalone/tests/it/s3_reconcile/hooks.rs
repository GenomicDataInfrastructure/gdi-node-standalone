//! One fault-injecting [`ObjectStore`] wrapper, shared by every submodule that needs one.
//!
//! `ObjectStore` has seven required methods, and a submodule that wants to deny a put, stall
//! a get or fail a list has to delegate the other six verbatim. [`HookStore`] writes the
//! delegation once and takes the interesting part as a hook, so an `object_store` upgrade
//! that touches the trait is one edit rather than five identical ones.
//!
//! The get and list hooks return a future, because the behaviours they encode have to await:
//! `tokio::time::sleep` for a slow but progressing download, and `Notify` for the one-shot
//! gate that parks a read mid-reconcile so another task can race it. A synchronous
//! `-> Option<Error>` would cover the deny cases only.

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt as _;
use futures::future::BoxFuture;
use futures::stream::BoxStream;
use object_store::memory::InMemory;
use object_store::path::Path as ObjPath;
use object_store::{
    CopyOptions, GetOptions, GetResult, ListResult, ObjectMeta, ObjectStore, PutMultipartOptions,
    PutOptions, PutPayload, PutResult,
};

/// Decide, from the target path, whether a put/multipart-put is refused.
type PutHook = Box<dyn Fn(&ObjPath) -> Option<object_store::Error> + Send + Sync>;
/// Observe (and optionally stall or refuse) a get before it reaches the inner store.
type GetHook =
    Box<dyn Fn(&ObjPath) -> BoxFuture<'static, Option<object_store::Error>> + Send + Sync>;
/// Stall or refuse a list before it reaches the inner store.
///
/// Takes the listed prefix (`None` is the whole bucket), because refusing a list is how a
/// test models a scoped credential. A hook that could not see what was being listed could
/// only refuse every listing, which cannot tell "the node listed the bucket root" apart from
/// "the node listed its own prefix".
type ListHook =
    Box<dyn Fn(Option<&ObjPath>) -> BoxFuture<'static, Option<object_store::Error>> + Send + Sync>;
/// Serve `list` from a synthetic stream instead of the inner store.
type ListItems =
    Box<dyn Fn() -> BoxStream<'static, object_store::Result<ObjectMeta>> + Send + Sync>;

/// An [`InMemory`] store with optional per-operation hooks.
///
/// Build with [`HookStore::new`], attach the one behaviour under test, and finish with
/// [`HookStore::into_store`]. Unhooked operations delegate straight through, so a store
/// with no hooks is behaviourally an `InMemory`.
pub(crate) struct HookStore {
    inner: InMemory,
    on_put: Option<PutHook>,
    on_get: Option<GetHook>,
    on_list: Option<ListHook>,
    list_items: Option<ListItems>,
    label: &'static str,
}

impl HookStore {
    /// An empty store with no hooks. `label` is what `Display` prints — `object_store`
    /// requires `Display`, and the node surfaces it in some error strings.
    pub(crate) fn new(label: &'static str) -> Self {
        Self {
            inner: InMemory::new(),
            on_put: None,
            on_get: None,
            on_list: None,
            list_items: None,
            label,
        }
    }

    /// Refuse puts (and multipart puts) for which `f` yields an error.
    ///
    /// Both entry points consult the same hook: a denial that covered only `put_opts`
    /// would be silently bypassed the moment the code under test crossed the multipart
    /// threshold, which is exactly the kind of hole a writeback-denied test must not have.
    pub(crate) fn on_put(
        mut self,
        f: impl Fn(&ObjPath) -> Option<object_store::Error> + Send + Sync + 'static,
    ) -> Self {
        self.on_put = Some(Box::new(f));
        self
    }

    /// Run `f` before each get; if it resolves to an error, the get fails with it.
    pub(crate) fn on_get(
        mut self,
        f: impl Fn(&ObjPath) -> BoxFuture<'static, Option<object_store::Error>> + Send + Sync + 'static,
    ) -> Self {
        self.on_get = Some(Box::new(f));
        self
    }

    /// Run `f` before each list, with the prefix being listed; if it resolves to an
    /// error, the list yields that error as its single item.
    pub(crate) fn on_list(
        mut self,
        f: impl Fn(Option<&ObjPath>) -> BoxFuture<'static, Option<object_store::Error>>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.on_list = Some(Box::new(f));
        self
    }

    /// Serve `list` from `f`'s stream instead of the inner store.
    ///
    /// Unlike [`Self::on_list`] this replaces the listing rather than gating it, which is
    /// what a test needs to present a listing far larger than any store it could actually
    /// populate — `f` can yield lazily, so a million-object bucket costs no memory.
    pub(crate) fn list_items(
        mut self,
        f: impl Fn() -> BoxStream<'static, object_store::Result<ObjectMeta>> + Send + Sync + 'static,
    ) -> Self {
        self.list_items = Some(Box::new(f));
        self
    }

    /// Finish building and erase the type, which is how the node accepts a store.
    pub(crate) fn into_store(self) -> Arc<dyn ObjectStore> {
        Arc::new(self)
    }

    /// The generic "operation refused" error these hooks hand back.
    pub(crate) fn denied(op: &'static str, path: &ObjPath) -> object_store::Error {
        object_store::Error::Generic {
            store: "HookStore",
            source: format!("{op} denied by test hook: {path}").into(),
        }
    }
}

impl std::fmt::Display for HookStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

impl std::fmt::Debug for HookStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HookStore({})", self.label)
    }
}

#[async_trait]
impl ObjectStore for HookStore {
    async fn put_opts(
        &self,
        location: &ObjPath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        if let Some(err) = self.on_put.as_ref().and_then(|h| h(location)) {
            return Err(err);
        }
        self.inner.put_opts(location, payload, opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &ObjPath,
        opts: PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        if let Some(err) = self.on_put.as_ref().and_then(|h| h(location)) {
            return Err(err);
        }
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &ObjPath,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        if let Some(hook) = self.on_get.as_ref()
            && let Some(err) = hook(location).await
        {
            return Err(err);
        }
        self.inner.get_opts(location, options).await
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, object_store::Result<ObjPath>>,
    ) -> BoxStream<'static, object_store::Result<ObjPath>> {
        self.inner.delete_stream(locations)
    }

    fn list(
        &self,
        prefix: Option<&ObjPath>,
    ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        let inner_list = match self.list_items.as_ref() {
            Some(items) => items(),
            None => self.inner.list(prefix),
        };
        let Some(hook) = self.on_list.as_ref() else {
            return inner_list;
        };
        // `list` is sync but the hook may await, so the hook runs as the stream's first
        // step: the caller gets a stream immediately, and the stall/failure lands when it
        // is polled — which is where the code under test experiences a slow bucket.
        let pending = hook(prefix);
        let inner = inner_list;
        let resolved = async move {
            match pending.await {
                Some(e) => futures::stream::once(async move { Err(e) }).boxed(),
                None => inner,
            }
        };
        Box::pin(futures::stream::once(resolved).flatten())
    }

    async fn list_with_delimiter(
        &self,
        prefix: Option<&ObjPath>,
    ) -> object_store::Result<ListResult> {
        if let Some(hook) = self.on_list.as_ref()
            && let Some(err) = hook(prefix).await
        {
            return Err(err);
        }
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(
        &self,
        from: &ObjPath,
        to: &ObjPath,
        options: CopyOptions,
    ) -> object_store::Result<()> {
        self.inner.copy_opts(from, to, options).await
    }
}
