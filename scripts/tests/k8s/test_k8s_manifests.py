#!/usr/bin/env python3
"""Structural guards for deploy/kubernetes/.

Not a schema validator: `kubectl apply` already rejects malformed YAML, and a schema check
would need another pinned binary to verify what the first apply catches anyway.

What nothing else catches is semantic drift: a dropped NetworkPolicy, `Recreate` flipped
to `RollingUpdate` (which breaks the single-writer ingest invariant), a missing `fsGroup`
(the node then cannot write its PVC), a Secret that acquires a real credential. Each of
those is valid YAML and valid Kubernetes, and each is an incident.

These assertions encode the container contract stated in docs/deployment.md. If you
change the contract, change it there and here together.
"""

import re
import shutil
import subprocess
import tomllib
import unittest

import yaml

from _helpers import REPO_ROOT

#: deploy/kubernetes/: a one-line kustomization aliasing base/, so the documented
#: `kubectl apply -k deploy/kubernetes` keeps working for the plain shape.
ROOT = REPO_ROOT / "deploy" / "kubernetes"
#: The manifests themselves, in their own subdirectory, because kustomize refuses a
#: resource that is an ancestor of the overlay loading it: an overlay inside the base tree
#: can never render.
BASE = ROOT / "base"
OVERLAYS = ROOT / "overlays"
#: The optional shapes, as kustomize components (`kind: Component`) so they compose. Each
#: is layered by a thin overlay under OVERLAYS. Pointing `kubectl kustomize` at a component
#: directory renders nothing and exits 0, which is why the two trees are kept apart and
#: `LayoutTest` pins which kind lives where.
COMPONENTS = ROOT / "components"
#: The node's config, fed to a `configMapGenerator` in base/kustomization.yaml rather than
#: written as a ConfigMap manifest: the generated name carries a content hash, so the
#: Deployment's pod template changes with the config and `kubectl rollout undo` reverts the
#: two together. A ConfigMap edited in place has no history to roll back to.
NODE_TOML = BASE / "node.toml"

#: The non-root uid the image is built around (see the Dockerfile WORKDIR block).
UID = 65532
#: The management plane: /metrics plus the unauthenticated dataset-state oracle.
MANAGEMENT_PORT = 9090
#: The public data plane.
PUBLIC_PORT = 8080


def manifest_paths():
    """Every manifest under deploy/kubernetes/base/, both spellings.

    `.yml` as well as `.yaml`: kubectl and kustomize accept either, so a manifest added
    under the spelling this function missed would be invisible to every assertion here
    while `test_manifests_exist` kept passing on the other files.
    """
    return sorted(
        p for p in BASE.iterdir() if p.is_file() and p.suffix in (".yaml", ".yml")
    )


def load_all():
    """Every YAML document under deploy/kubernetes/base/, in a stable order."""
    docs = []
    for path in manifest_paths():
        with path.open(encoding="utf-8") as fh:
            docs.extend(d for d in yaml.safe_load_all(fh) if d)
    return docs


def by_kind(docs, kind):
    return [d for d in docs if d.get("kind") == kind]


def _kinds_in(path):
    """Every `kind` present in one manifest file, for filename-level assertions."""
    with path.open(encoding="utf-8") as fh:
        return {d.get("kind") for d in yaml.safe_load_all(fh) if d}


def node_toml():
    """The shipped `node.toml`, parsed.

    Every assertion about the shipped config goes through here rather than substring-
    matching the file. A blob search cannot tell a live setting from a comment describing
    one, so a comment mentioning `0.0.0.0:9090` would satisfy the management-bind check
    while the real field said `127.0.0.1`. `tomllib` is stdlib, so this costs no dependency.

    Reads the `configMapGenerator` input (`base/node.toml`) rather than a ConfigMap
    manifest, because the applied ConfigMap is generated and there is no manifest to read.
    Returns `{}` when the file is absent; callers assert presence themselves, so a failure
    names the missing file rather than raising.
    """
    raw = node_toml_raw()
    return tomllib.loads(raw) if raw else {}


def mebibytes(quantity):
    """A Kubernetes memory quantity (`4Gi`, `512Mi`, `2G`, a bare byte count) in MiB.

    Only the suffixes Kubernetes actually defines for memory, and a bare integer, are
    accepted. Anything else raises rather than returning a number an assertion would then
    compare against, since misreading `4Gi` as 4 would invert every memory check.
    """
    text = str(quantity).strip()
    factors = {
        "Ki": 1024,
        "Mi": 1024**2,
        "Gi": 1024**3,
        "Ti": 1024**4,
        "k": 1000,
        "M": 1000**2,
        "G": 1000**3,
        "T": 1000**4,
    }
    for suffix in sorted(factors, key=len, reverse=True):
        if text.endswith(suffix):
            return float(text[: -len(suffix)]) * factors[suffix] / 1024**2
    return float(text) / 1024**2


def node_toml_raw():
    """The shipped `node.toml`, unparsed.

    The counterpart to `node_toml`, for assertions about the comments. Parsing throws them
    away, and the shipped file's comments are operator-facing instructions, so a wrong one
    is a defect the parsed view cannot see. Returns `""` when the file is absent.
    """
    return NODE_TOML.read_text(encoding="utf-8") if NODE_TOML.is_file() else ""


def comment_block_above(raw, key):
    """The contiguous run of `#` comment lines directly above `key = ` in `raw`.

    For fields whose value is not the point: a `<SET ME>` placeholder says an operator must
    fill something in, and nothing about what breaks if they do not, so the comment is what
    is asserted. Returns `""` when the key is absent or carries no comment.
    """
    lines = raw.splitlines()
    for i, line in enumerate(lines):
        if not re.match(rf"\s*{re.escape(key)}\s*=", line):
            continue
        block = []
        j = i - 1
        while j >= 0 and lines[j].strip().startswith("#"):
            block.append(lines[j])
            j -= 1
        return "\n".join(reversed(block))
    return ""


def port_of(addr):
    """The port from a `host:port` bind string, as an int."""
    return int(str(addr).rsplit(":", 1)[1])


class K8sManifestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.docs = load_all()
        cls.toml = node_toml()

    def containers(self):
        """Every container across every Deployment, with its pod spec."""
        for dep in by_kind(self.docs, "Deployment"):
            pod = dep["spec"]["template"]["spec"]
            for c in pod["containers"]:
                yield pod, c

    def node_containers(self):
        """Only the node's containers, with their pod spec, never a sidecar.

        The memory guards read one config value from `node.toml` and compare it against a
        container's `resources`. Over `containers()` they would also compare the node's
        budget against a sidecar's much smaller request, and fail for a reason neither
        guard is about. A non-empty result is asserted, so a rename cannot turn both guards
        into vacuous passes.
        """
        found = [
            (pod, c)
            for pod, c in self.containers()
            if c.get("name") == "gdi-node-standalone"
        ]
        self.assertTrue(
            found,
            "no container named 'gdi-node-standalone' in any Deployment; the memory "
            "guards would have nothing to compare the node's config against",
        )
        return found

    def test_manifests_exist(self):
        self.assertTrue(self.docs, f"no manifests found under {BASE}")

    def test_a_deployment_is_present(self):
        self.assertTrue(by_kind(self.docs, "Deployment"), "no Deployment manifest")

    def test_deployment_uses_recreate_for_the_single_writer_invariant(self):
        for dep in by_kind(self.docs, "Deployment"):
            self.assertEqual(
                dep["spec"].get("strategy", {}).get("type"),
                "Recreate",
                "RollingUpdate would briefly run two writers against one data volume; "
                "the ingest path is single-writer (deployment.md)",
            )

    def test_pod_runs_as_the_nonroot_uid_with_fsgroup(self):
        for dep in by_kind(self.docs, "Deployment"):
            sc = dep["spec"]["template"]["spec"].get("securityContext", {})
            self.assertEqual(sc.get("runAsUser"), UID)
            self.assertTrue(sc.get("runAsNonRoot"))
            self.assertEqual(
                sc.get("fsGroup"),
                UID,
                "fsGroup gives the pod group access to a fresh PVC (chown -1:65532 plus "
                "setgid). It does not make the node the owner, which the ownership init "
                "container does, but without it a volume the init container has not "
                "reached is not even group-readable",
            )

    def test_container_is_locked_down(self):
        for dep in by_kind(self.docs, "Deployment"):
            for c in dep["spec"]["template"]["spec"]["containers"]:
                sc = c.get("securityContext", {})
                self.assertTrue(
                    sc.get("readOnlyRootFilesystem"),
                    "the image needs no writable root; mirrors the compose stack",
                )
                self.assertFalse(sc.get("allowPrivilegeEscalation", True))
                self.assertEqual(
                    sc.get("capabilities", {}).get("drop"),
                    ["ALL"],
                    "the node binds only ports >1024 as a non-root uid, so it needs none",
                )

    def init_containers(self):
        """Every initContainer across every Deployment, with its pod spec."""
        for dep in by_kind(self.docs, "Deployment"):
            pod = dep["spec"]["template"]["spec"]
            for c in pod.get("initContainers") or []:
                yield pod, c

    @staticmethod
    def script_of(container):
        """A container's whole argv as one string, for coverage assertions on a shell."""
        parts = (container.get("command") or []) + (container.get("args") or [])
        return " ".join(str(p) for p in parts)

    def test_an_init_container_takes_ownership_of_every_persistent_mount(self):
        # `fsGroup` does not confer ownership. It applies `chown -1:<gid>` plus setgid, so
        # the owner stays root, and only the owner may `chmod`. The node's own `chmod 0700`
        # of data_dir then fails with EPERM on a fresh volume of any type, refusing with
        # `cannot tighten data dir ... to owner-only`, so the pod cannot reach Running on a
        # fresh cluster without an init container that runs as root and takes ownership.
        #
        # Asserted over the mounts rather than a hard-coded path list: a component may add
        # a fourth volume, and what must hold is that every persistent mount the node
        # writes is covered.
        checked = 0
        for pod, app in self.containers():
            persistent = {
                m["mountPath"].rstrip("/")
                for m in app.get("volumeMounts") or []
                if self.claim_backing(pod, m["mountPath"]) is not None
            }
            self.assertTrue(persistent, "the node container mounts no PVC at all")
            roots = [
                c
                for c in pod.get("initContainers") or []
                if (c.get("securityContext") or {}).get("runAsUser") == 0
            ]
            self.assertEqual(
                len(roots),
                1,
                "exactly one init container may run as root, the ownership fix. Found "
                f"{[c['name'] for c in roots]}",
            )
            fixer = roots[0]
            self.assertIn(
                "@sha256:",
                fixer["image"],
                "the ownership init container is a second image in this pod, because the "
                "node's is distroless with no shell and no chown. Pin it by digest, like "
                "the Dockerfile's own bases",
            )
            self.assertIs(
                (fixer.get("securityContext") or {}).get("runAsNonRoot"),
                False,
                "the pod-level securityContext sets runAsNonRoot: true, which rejects uid "
                "0 at admission; the ownership container must opt out explicitly",
            )
            script = self.script_of(fixer)
            self.assertIn("chown", script, "the ownership container must chown")
            self.assertIn(
                f"{UID}:{UID}", script, "it must chown to the node's run uid:gid"
            )
            mounted = {
                m["mountPath"].rstrip("/") for m in fixer.get("volumeMounts") or []
            }
            for path in sorted(persistent):
                self.assertIn(
                    path,
                    mounted,
                    f"{path} is a persistent mount the node writes, but the ownership init "
                    f"container does not mount it, so it stays root-owned and the node "
                    f"refuses, or for the inbox warns UNSUPPORTED on every boot",
                )
                parent = path.rsplit("/", 1)[0]
                self.assertTrue(
                    path in script or f"{parent}/*" in script,
                    f"the ownership script covers neither {path} nor {parent}/*: {script}",
                )
            checked += 1
        self.assertTrue(
            checked, "no container mounted anything, so nothing was checked"
        )

    def test_an_init_container_materialises_the_override_store(self):
        # Boot does not create the store's loader subdirectories, so a first boot under
        # this base's own `require_override_store = true` refuses with "the
        # operator-override store is not intact". A crash-looping distroless pod cannot be
        # `kubectl exec`'d, so without this init container the example needs an out-of-band
        # Job before it can start at all.
        service = self.toml.get("service", {})
        checked = 0
        for pod, app in self.containers():
            inits = pod.get("initContainers") or []
            named = [c for c in inits if "overrides" in c["name"]]
            self.assertEqual(
                len(named),
                1,
                f"expected one overrides init container, found {[c['name'] for c in inits]}",
            )
            init = named[0]
            self.assertEqual(
                init["image"],
                app["image"],
                "the store is initialised by the NODE binary, so it must be the node image "
                "at the same tag; a second image would drift from the store format",
            )
            argv = [
                str(t) for t in (init.get("command") or []) + (init.get("args") or [])
            ]
            self.assertIn("overrides", argv)
            self.assertIn("init", argv)
            self.assertNotIn(
                "--yes",
                argv,
                "--yes attests an emptied store as intentionally empty, clearing the used "
                "marker. Automating that turns a lost override volume into a silent "
                "re-serve of every withheld dataset. Plain `init` refuses there, which is "
                "the guarantee that makes this safe to run on every boot",
            )
            mounts = {
                m["mountPath"].rstrip("/") for m in init.get("volumeMounts") or []
            }
            for key in ("data_dir", "override_dir"):
                path = str(service.get(key, "")).rstrip("/")
                self.assertIn(
                    path,
                    mounts,
                    f"the overrides init container does not mount [service].{key} "
                    f"({path!r}). The USED marker lives under data_dir, so without that "
                    f"mount `overrides init` cannot see it and would re-initialise a store "
                    f"that had held overrides",
                )
            self.assertTrue(
                any(m.startswith("/etc/") for m in mounts),
                "the overrides init container must mount the config it is passed",
            )
            self.assertNotEqual(
                (init.get("securityContext") or {}).get("runAsUser"),
                0,
                "the store must be created owned by the node's uid, not by root",
            )
            names = [c["name"] for c in inits]
            root_names = [
                c["name"]
                for c in inits
                if (c.get("securityContext") or {}).get("runAsUser") == 0
            ]
            for root_name in root_names:
                self.assertLess(
                    names.index(root_name),
                    names.index(init["name"]),
                    "init containers run in order: ownership must be fixed before the node "
                    "binary tries to create the store, or creation fails with EACCES",
                )
            checked += 1
        self.assertTrue(checked, "no Deployment, so nothing was checked")

    def test_every_init_container_is_locked_down(self):
        # The same posture as the serving container, minus the one capability the ownership
        # fix genuinely needs. An init container is a container: it shares the pod's volumes
        # and network, and a permissive one is the easiest way to hand back everything the
        # main container's securityContext buys.
        allowed_caps = {"CHOWN", "FOWNER"}
        for _pod, c in self.init_containers():
            sc = c.get("securityContext") or {}
            self.assertTrue(
                sc.get("readOnlyRootFilesystem"), f"{c['name']}: writable root"
            )
            self.assertFalse(sc.get("allowPrivilegeEscalation", True), c["name"])
            caps = sc.get("capabilities") or {}
            self.assertEqual(caps.get("drop"), ["ALL"], f"{c['name']}: drops nothing")
            extra = set(caps.get("add") or []) - allowed_caps
            self.assertFalse(
                extra,
                f"{c['name']} adds {sorted(extra)}; only {sorted(allowed_caps)} are "
                "justified here (chown/chmod of a foreign-owned volume)",
            )

    def claim_backing(self, pod, mount_path):
        """The `claimName` backing `mount_path` in `pod`, or None.

        Resolves the mountPath -> volumeMount.name -> volume -> persistentVolumeClaim
        chain, which is the thing that actually decides what storage a directory lands on.
        """
        for container in pod["containers"]:
            for mount in container.get("volumeMounts") or []:
                if mount.get("mountPath") != mount_path:
                    continue
                for vol in pod.get("volumes") or []:
                    if vol.get("name") == mount.get("name"):
                        return (vol.get("persistentVolumeClaim") or {}).get("claimName")
        return None

    def test_data_and_override_store_are_separate_claims(self):
        # Asserts the property rather than a proxy for it. Counting PersistentVolumeClaim
        # manifests says nothing about what the pod mounts: repointing the `overrides`
        # volume at the data claim leaves both manifests on disk while the two directories
        # share one volume.
        #
        # The override store is the only state re-ingest cannot rebuild (operating.md §17),
        # so losing it with the data volume re-serves erased datasets.
        declared = {
            p["metadata"]["name"] for p in by_kind(self.docs, "PersistentVolumeClaim")
        }
        self.assertTrue(declared, "no PersistentVolumeClaim manifests found")

        data_dir = self.toml.get("service", {}).get("data_dir")
        override_dir = self.toml.get("service", {}).get("override_dir")
        self.assertTrue(
            data_dir and override_dir,
            "the ConfigMap must set both [service].data_dir and [service].override_dir; "
            "without an explicit override_dir the store defaults inside data_dir, which is "
            "the shared-volume failure this test forbids",
        )

        checked = 0
        for pod, _container in self.containers():
            data_claim = self.claim_backing(pod, data_dir)
            override_claim = self.claim_backing(pod, override_dir)
            self.assertIsNotNone(
                data_claim, f"{data_dir} is not backed by a persistentVolumeClaim"
            )
            self.assertIsNotNone(
                override_claim,
                f"{override_dir} is not backed by a persistentVolumeClaim; an emptyDir "
                "or a missing mount loses every operator suppression on restart",
            )
            self.assertNotEqual(
                data_claim,
                override_claim,
                "the override store and the data dir resolve to the same claim "
                f"({data_claim!r}); losing that one volume re-serves erased datasets",
            )
            for claim in (data_claim, override_claim):
                self.assertIn(
                    claim, declared, f"claimName {claim!r} has no PVC manifest here"
                )
            checked += 1
        self.assertTrue(
            checked, "no container mounted either directory, so nothing was checked"
        )

    def test_selectors_match_the_pod_labels(self):
        # A one-character typo in the NetworkPolicy podSelector selects no pod, which
        # leaves the unauthenticated management plane with no policy in front of it and
        # nothing else complaining. Kustomize's `includeSelectors: true` rewrites
        # podSelectors and can cause the same thing, so every selector is checked against
        # the pod labels.
        labels = {}
        for dep in by_kind(self.docs, "Deployment"):
            labels.update(dep["spec"]["template"]["metadata"].get("labels") or {})
        self.assertTrue(labels, "no Deployment pod-template labels to match against")

        def subset_of_labels(sel, what):
            self.assertTrue(sel, f"{what} is empty, so it would select every pod")
            for key, value in sel.items():
                self.assertIn(key, labels, f"{what} matches on unknown label {key!r}")
                self.assertEqual(
                    labels[key],
                    value,
                    f"{what} expects {key}={value!r} but the pod template carries "
                    f"{labels[key]!r}, so this selector matches nothing",
                )

        for pol in by_kind(self.docs, "NetworkPolicy"):
            subset_of_labels(
                (pol["spec"].get("podSelector") or {}).get("matchLabels") or {},
                f"NetworkPolicy/{pol['metadata']['name']} podSelector",
            )
        for svc in by_kind(self.docs, "Service"):
            subset_of_labels(
                svc["spec"].get("selector") or {},
                f"Service/{svc['metadata']['name']} selector",
            )
        for dep in by_kind(self.docs, "Deployment"):
            subset_of_labels(
                (dep["spec"].get("selector") or {}).get("matchLabels") or {},
                f"Deployment/{dep['metadata']['name']} selector",
            )

    def test_data_claim_is_rwo_for_the_single_writer_path(self):
        # Every claim must be ReadWriteOnce and must not be ReadWriteMany. The ingest path
        # assumes a single writer: an atomic rename into the data dir, plus the `.incoming`
        # and `.deleting` markers. The `overrides` claim needs no more than ReadOnlyMany,
        # since the serving path does not write the store, so RWX would grant a write
        # nothing asks for. The README's "Scaling beyond one replica" agrees — it says RWX
        # is not required and points at this guard — so this asserts the shipped
        # single-replica shape rather than overriding a doc that asks for something else.
        # ReadOnlyMany there describes the StatefulSet shape that section defers, not this
        # base: these claims are RWO today, and a claim that dropped RWO for RWM-only would
        # fail here too, which is correct while one replica owns the volume.
        #
        # ReadWriteOnce does not by itself prevent a second writer: it is node-scoped, so
        # two pods on one node can both mount the claim read-write. The single-writer
        # guarantee is the node's own `<data_dir>/.lock` plus `strategy: Recreate`, both
        # asserted elsewhere here; banning RWX keeps the claim off a second node, where no
        # lock this node takes would help.
        seen = 0
        for pvc in by_kind(self.docs, "PersistentVolumeClaim"):
            name = pvc["metadata"]["name"]
            modes = pvc["spec"].get("accessModes", [])
            self.assertTrue(modes, f"{name} declares no accessModes")
            self.assertIn(
                "ReadWriteOnce",
                modes,
                f"{name} must be ReadWriteOnce; the ingest and override-store paths are "
                f"single-writer. Got {modes}",
            )
            self.assertNotIn(
                "ReadWriteMany",
                modes,
                f"{name} allows multi-writer mounting, which the single-writer ingest path "
                f"cannot tolerate; got {modes}",
            )
            seen += 1
        self.assertTrue(
            seen, "no PersistentVolumeClaim found, so this guard checks nothing"
        )

    def test_the_burst_and_the_budget_together_fit_the_memory_request(self):
        # node.toml states the memory model as a sum: the decode floor plus the retained
        # burst is what the memory request reserves. The two per-term tests each compare
        # one term against the whole request, so a request can satisfy both while the sum
        # over-commits it. This asserts the sum, from the same two inputs.
        retained_mib_per_request = 220
        toml = node_toml()
        service = toml.get("service") or {}
        admitted = service.get("max_concurrent_requests")
        budget_bytes = service.get("max_total_query_bytes")
        self.assertIsInstance(admitted, int)
        self.assertIsInstance(budget_bytes, int)
        need_mib = admitted * retained_mib_per_request + budget_bytes / 1024**2
        checked = 0
        for _pod, c in self.node_containers():
            request = ((c.get("resources") or {}).get("requests") or {}).get("memory")
            if request is None:
                continue
            checked += 1
            self.assertLessEqual(
                need_mib,
                mebibytes(request),
                f"resources.requests.memory is {request} but the burst "
                f"({admitted} x {retained_mib_per_request} MiB) plus the query budget "
                f"({budget_bytes} B) is {need_mib / 1024:.1f} GiB. The two terms fit "
                "separately but not together",
            )
        self.assertTrue(checked, "no node container with a memory request was checked")

    def test_the_data_volume_fits_the_peak_ingest_scratch(self):
        # The data claim is sized from two caps, and nothing else makes them agree.
        # Scratch peaks at 4x per package (docs/deployment.md, operating.md §7), so a claim
        # sized from a smaller model leaves LowDisk's margin firing far too late.
        #
        # 4 (scratch per package) and 1.25 (headroom) are the figures deployment.md states.
        # `ingest_concurrency` and `max_package_bytes` are read from the shipped node.toml,
        # falling back to the node's built-in defaults when it inherits them. Those
        # defaults are a second copy of core's, the same trade the memory test makes:
        # deriving them would mean parsing Rust for two integers.
        scratch_per_package = 4
        headroom = 1.25
        default_ingest_concurrency = 4
        default_max_package_bytes = 16 * 1024**3
        toml = node_toml()
        self.assertTrue(toml, "no node.toml to read the ingest caps from")
        service = toml.get("service") or {}
        concurrency = service.get("ingest_concurrency", default_ingest_concurrency)
        package_bytes = service.get("max_package_bytes", default_max_package_bytes)
        self.assertIsInstance(concurrency, int)
        self.assertIsInstance(package_bytes, int)
        need_mib = (
            concurrency * scratch_per_package * package_bytes * headroom / 1024**2
        )

        data = [
            p
            for p in by_kind(self.docs, "PersistentVolumeClaim")
            if p["metadata"]["name"] == "gdi-node-standalone-data"
        ]
        self.assertEqual(
            len(data), 1, "expected exactly one data PersistentVolumeClaim"
        )
        storage = data[0]["spec"]["resources"]["requests"]["storage"]
        self.assertGreaterEqual(
            mebibytes(storage),
            need_mib,
            f"the data claim requests {storage} but ingest_concurrency = {concurrency} x "
            f"{scratch_per_package} x max_package_bytes = {package_bytes} B, + 25 %, needs "
            f"{need_mib / 1024:.0f} GiB of scratch at peak. Raise the claim or lower a cap; "
            "see docs/deployment.md 'Resource baseline'",
        )

    def test_a_networkpolicy_guards_the_management_plane(self):
        policies = by_kind(self.docs, "NetworkPolicy")
        self.assertTrue(
            policies,
            "management_addr must be widened to 0.0.0.0:9090 for kubelet probes, which "
            "exposes the unauthenticated dataset-state oracle (GET /datasets/{id}/state, "
            "revealing hidden and errored ids). The NetworkPolicy is what makes that "
            "safe, so it is not optional",
        )
        ports = [
            p.get("port")
            for pol in policies
            for rule in pol["spec"].get("ingress", [])
            for p in rule.get("ports", [])
        ]
        self.assertIn(
            MANAGEMENT_PORT, ports, "no policy rule actually covers the management port"
        )

    def test_the_policy_admits_monitoring_rather_than_only_denying(self):
        saw_rule = False
        for pol in by_kind(self.docs, "NetworkPolicy"):
            for rule in pol["spec"].get("ingress", []):
                if any(p.get("port") == MANAGEMENT_PORT for p in rule.get("ports", [])):
                    saw_rule = True
                    self.assertTrue(
                        rule.get("from"),
                        "a policy that admits nobody gives you the exposure and no "
                        "metrics; it must name the monitoring namespace",
                    )
        self.assertTrue(saw_rule, "no ingress rule covers the management port")

    def test_probes_target_the_health_endpoints(self):
        for dep in by_kind(self.docs, "Deployment"):
            for c in dep["spec"]["template"]["spec"]["containers"]:
                self.assertEqual(
                    c.get("livenessProbe", {}).get("httpGet", {}).get("path"),
                    "/health/live",
                )
                self.assertEqual(
                    c.get("readinessProbe", {}).get("httpGet", {}).get("path"),
                    "/health/ready",
                )

    def test_management_addr_is_widened_in_the_config(self):
        # Reads the parsed field, not the rendered text: a substring search for
        # "0.0.0.0:9090" over the whole blob is satisfied by a comment mentioning the
        # wildcard while the real field says loopback.
        self.assertTrue(self.toml, "no ConfigMap carrying node.toml")
        addr = self.toml.get("service", {}).get("management_addr")
        self.assertEqual(
            addr,
            f"0.0.0.0:{MANAGEMENT_PORT}",
            "kubelet probes cannot reach the default 127.0.0.1:9090, so the shipped "
            f"config must widen management_addr (and the NetworkPolicy must cover it); "
            f"got {addr!r}",
        )

    def test_the_override_store_is_required_not_advisory(self):
        # The directory's disaster-recovery argument (operating.md §17, and the separate
        # PVC guarded above) rests on this one boolean: with it false, a node whose
        # override mount is missing serves every withheld dataset and reports a clean
        # startup.
        self.assertTrue(self.toml, "no ConfigMap carrying node.toml")
        self.assertIs(
            self.toml.get("service", {}).get("require_override_store"),
            True,
            "require_override_store must be true: an absent override store is otherwise "
            "indistinguishable from one that never existed, and the node lifts every "
            "suppression silently",
        )

    def test_the_k_anonymity_floor_is_stated_not_inherited(self):
        # Presence, not value. The floor is the operator's call, and 0 is defensible if
        # the DPIA treats aggregate allele frequencies as non-identifying. Inheriting it by
        # omission is not, because the built-in default is the disclosive one: an omitted
        # key serves exact counts, singletons included, on an unauthenticated plane. No
        # `<SET ME>` sentinel can catch that, since the key is absent and the field is an
        # integer.
        self.assertTrue(self.toml, "no ConfigMap carrying node.toml")
        beacon = self.toml.get("beacon", {})
        self.assertIn(
            "min_allele_count",
            beacon,
            "[beacon].min_allele_count is absent, so the k-anonymity floor is whatever the "
            "binary defaults to, and 0 disables suppression. State it explicitly, at any "
            "value, so the choice is visible in review rather than inherited by silence.",
        )
        self.assertIsInstance(
            beacon["min_allele_count"],
            int,
            "min_allele_count must be an integer; a quoted value fails config parsing at "
            "boot, which in a Recreate single-replica Deployment is a crash-loop",
        )

    def test_the_fair_data_point_is_configured_not_silently_off(self):
        # Without a `[fairdp]` block the example deploys a Beacon-only node: `/fairdp`
        # answers 404, `GET /` lists no `fairdp`, and `check-config` prints
        # `fairdp = not-configured`, while the README promises a FAIR Data Point.
        #
        # The whole required set is asserted, because preflight rejects a partial block,
        # and at one replica under Recreate that rejection is a crash-loop.
        fairdp = self.toml.get("fairdp")
        self.assertTrue(
            fairdp,
            "no [fairdp] block: this example deploys a Beacon-only node while the README "
            "promises a FAIR Data Point. Ship the block with placeholders, or say plainly "
            "that the example is Beacon-only",
        )
        for key in ("title", "description", "issued", "license"):
            self.assertIn("<SET ME", str(fairdp.get(key, "")), f"[fairdp].{key}")
        for key in ("theme", "applicable_legislation"):
            values = fairdp.get(key)
            self.assertTrue(
                isinstance(values, list) and values,
                f"[fairdp].{key} must be a non-empty array; preflight requires one IRI",
            )
            for value in values:
                self.assertIn("<SET ME", str(value), f"[fairdp].{key}")
        for agent in ("publisher", "hdab"):
            block = fairdp.get(agent)
            self.assertTrue(
                block,
                f"[fairdp.{agent}] is required whenever [fairdp] is present; the service "
                f"refuses to start without it",
            )
            self.assertIn("<SET ME", str(block.get("name", "")), f"{agent}.name")
            contact = block.get("contact_point")
            self.assertTrue(
                contact,
                f"[fairdp.{agent}.contact_point] is required; the submission model makes a "
                f"contact point mandatory on this agent",
            )
            for key in ("fn", "has_email"):
                self.assertIn(
                    "<SET ME", str(contact.get(key, "")), f"{agent}.contact_point.{key}"
                )

    def test_the_beacon_network_registry_fields_are_shipped_with_their_warning(self):
        # `[beacon].alternative_url` and `[beacon.organization].logo_url` are optional in
        # the Beacon schema and unset by default, but the GDI allele-frequency network's
        # registry reads both, and a member that omits either has been observed to degrade
        # the shared member listing rather than only its own entry. The node emits them
        # verbatim and never fetches them, so the failure is invisible in its own logs.
        #
        # Asserts the shipped comment still says the blast radius reaches other members,
        # which is why an operator keeps a schema-optional field. It does not pin a status
        # code or a handler name: that behaviour is a third party's and can change.
        beacon = self.toml.get("beacon") or {}
        organization = beacon.get("organization") or {}
        raw = node_toml_raw()
        for key, table, block in (
            ("alternative_url", beacon, "[beacon]"),
            ("logo_url", organization, "[beacon.organization]"),
        ):
            self.assertIn(
                key,
                table,
                f"{block}.{key} is absent. Registering this node in the GDI "
                f"allele-frequency network then degrades the shared member listing, not "
                f"just this node's entry (see docs/deployment.md, 'Registering with a "
                f"Beacon network')",
            )
            self.assertIn("<SET ME", str(table[key]), f"{block}.{key}")
            # Normalised: `comment_block_above` returns raw `#` lines, so a phrase that
            # wraps across two of them would never match a plain substring test.
            comment = " ".join(comment_block_above(raw, key).replace("#", " ").split())
            self.assertTrue(
                "shared member listing" in comment,
                f"{block}.{key} carries no comment saying what its absence breaks. An "
                f"operator who deletes the line because it looks optional degrades the "
                f"network's member listing, and nothing in this node reports it",
            )
            self.assertTrue(
                "rather than only its own" in comment
                or "not just this node" in comment,
                f"{block}.{key}'s comment no longer says the blast radius reaches other "
                f"members. Without that, the warning reads as 'your entry looks worse', "
                f"which is not why an operator keeps a schema-optional field",
            )

    def test_config_dirs_are_actually_mounted(self):
        # Cross-file coherence, which YAML validity cannot express: data_dir and
        # override_dir name paths in the container, and the root filesystem is readOnly. A
        # path no volumeMount covers is neither a config error nor a schema error. It is a
        # pod that starts and then cannot write.
        self.assertTrue(self.toml, "no ConfigMap carrying node.toml")
        service = self.toml.get("service", {})
        for _pod, c in self.containers():
            mounts = {m["mountPath"].rstrip("/") for m in c.get("volumeMounts", [])}
            writable = {
                m["mountPath"].rstrip("/")
                for m in c.get("volumeMounts", [])
                if not m.get("readOnly")
            }
            for key in ("data_dir", "override_dir"):
                path = service.get(key)
                if path is None:
                    continue
                path = str(path).rstrip("/")
                self.assertIn(
                    path,
                    mounts,
                    f"[service].{key} = {path!r} has no volumeMount; with "
                    f"readOnlyRootFilesystem the node cannot create it",
                )
                self.assertIn(
                    path,
                    writable,
                    f"[service].{key} = {path!r} is mounted readOnly. The serving path "
                    f"does not write the override store, but boot materialises its loader "
                    f"subdirectories and the operator CLI writes through this same mount; "
                    f"a read-only store belongs on extra replicas, not here",
                )

    def test_container_ports_match_the_configured_listeners(self):
        # containerPort is documentation for humans and for the Service's targetPort by
        # name, so a desync still applies cleanly. It just stops matching the
        # NetworkPolicy, which selects on the number.
        self.assertTrue(self.toml, "no ConfigMap carrying node.toml")
        service = self.toml.get("service", {})
        declared = {
            port_of(service[k]) for k in ("listen", "management_addr") if k in service
        }
        for _pod, c in self.containers():
            exposed = {p["containerPort"] for p in c.get("ports", [])}
            self.assertEqual(
                exposed,
                declared,
                f"containerPorts {sorted(exposed)} do not match the configured listeners "
                f"{sorted(declared)}; the NetworkPolicy matches on the number",
            )

    def test_termination_grace_covers_the_sequential_drain(self):
        # Shutdown spends three bounded phases back to back (main.rs):
        #   1. the public listener drains       -- shutdown_drain_seconds
        #   2. the management listener stops    -- a hard-coded 2s join
        #   3. in-flight ingest is awaited      -- shutdown_drain_seconds again
        # so the ceiling is 2 x shutdown_drain_seconds + 2s. The second full budget is the
        # ingest quiesce, not a second plane.
        #
        # Kubernetes' default grace period is 30s, which covers one drain's worth and
        # SIGKILLs the pod mid-shutdown.
        self.assertTrue(self.toml, "no ConfigMap carrying node.toml")
        drain = self.toml.get("service", {}).get("shutdown_drain_seconds")
        self.assertIsNotNone(
            drain,
            "state [service].shutdown_drain_seconds explicitly: the grace period below "
            "has to cover it, and nothing else makes the two comparable",
        )
        for pod, container in self.containers():
            grace = pod.get("terminationGracePeriodSeconds")
            self.assertIsNotNone(
                grace,
                "terminationGracePeriodSeconds is unset, so Kubernetes uses 30s, below "
                f"the 2 x {drain}s this node can spend draining",
            )
            # A preStop sleep runs before the drain starts and is charged to the same
            # grace period, so the rule is `preStop + 2 x drain + 2s management stop +
            # slack`. The +2 keeps the hard-coded management-stop join in the pinned
            # relation rather than only in a comment.
            pre_stop = self._pre_stop_sleep_seconds(container)
            self.assertGreaterEqual(
                grace,
                pre_stop + 2 * drain + 2,
                f"terminationGracePeriodSeconds ({grace}s) must cover the preStop sleep "
                f"({pre_stop}s) plus both drain budgets (2 x {drain}s: the public drain "
                f"and the ingest quiesce) plus the hard-coded 2s management-listener stop. "
                f"The pod is otherwise SIGKILLed mid-drain",
            )

    @staticmethod
    def _pre_stop_sleep_seconds(container):
        """Seconds a `preStop` sleep hook holds, or 0 when there is none.

        Two shapes are understood:

        * `preStop: sleep: {seconds: N}`, the native `PodLifecycleSleepAction` and the only
          one this image can run. The runtime performs the sleep itself, so it needs
          nothing inside the container.
        * `preStop: exec: [sleep, N]`, which executes in the container. The runtime image
          is distroless, with no shell and no `sleep` binary, so it fails with
          `exec: "sleep": executable file not found` and the kubelet proceeds straight to
          SIGTERM. It is understood here so the grace-period arithmetic still holds for
          anyone who writes it against a different image.

        Any other hook returns 0, which is the conservative direction: it under-counts the
        grace period needed, so it cannot mask a violation of the 2 x drain floor.
        """
        pre_stop = (container.get("lifecycle") or {}).get("preStop") or {}
        native = (pre_stop.get("sleep") or {}).get("seconds")
        if native is not None:
            try:
                return int(float(native))
            except (TypeError, ValueError):
                return 0
        cmd = (pre_stop.get("exec") or {}).get("command") or []
        parts = [str(c) for c in cmd]
        for i, tok in enumerate(parts):
            if tok.endswith("sleep") and i + 1 < len(parts):
                try:
                    return int(float(parts[i + 1]))
                except ValueError:
                    return 0
        return 0

    def test_a_prestop_sleep_covers_the_endpoint_removal_race(self):
        # Endpoint removal is eventually consistent, so without a pause a rollout can
        # still route a few requests to a pod that has stopped accepting, producing
        # connection-refused blips. operating.md §14 prescribes the hook and counts it in
        # the grace-period formula ("terminationGracePeriodSeconds >= preStop sleep +
        # 2 x shutdown_drain_seconds"), so a manifest without one leaves that formula's
        # first term at zero.
        #
        # The shape is asserted as well as the duration. `_pre_stop_sleep_seconds`
        # understands both hook forms, because the arithmetic must hold for anyone who
        # writes the exec form against an image that has a shell. This image is distroless,
        # so an `exec: ["sleep", "5"]` hook fails with `executable file not found` and the
        # kubelet goes straight to SIGTERM: a hook present in the manifest, counted in the
        # grace period, and doing nothing, which a duration-only assertion would accept.
        for _pod, c in self.containers():
            pre_stop = (c.get("lifecycle") or {}).get("preStop") or {}
            self.assertTrue(
                pre_stop,
                "no preStop hook on the node container. operating.md §14 prescribes one "
                "and counts it in the grace-period formula; the shipped manifest must "
                "carry it or the doc is describing something else",
            )
            self.assertIn(
                "sleep",
                pre_stop,
                "the preStop hook must be the native sleep action "
                "(`preStop: sleep: {seconds: N}`), which the kubelet performs itself. "
                f"Got {sorted(pre_stop)}",
            )
            self.assertNotIn(
                "exec",
                pre_stop,
                "an `exec` preStop hook runs inside the container, and this image is "
                "distroless: no shell and no `sleep` binary, so it fails with "
                "`executable file not found` and the kubelet proceeds straight to SIGTERM. "
                "It looks present and does nothing",
            )
            self.assertGreaterEqual(
                self._pre_stop_sleep_seconds(c),
                1,
                "the preStop sleep must hold for a moment; its job is to outlast the "
                "eventually-consistent endpoint withdrawal",
            )

    def test_readiness_does_not_re_pay_for_cold_start(self):
        # Readiness does not run until the startupProbe has succeeded, which is to say
        # until /health/ready has already answered 200, so an initial delay here buys
        # nothing and is spent on every restart. At one replica under Recreate that delay
        # is the whole outage.
        #
        # `timeoutSeconds` matters for the same reason it does on the startup probe: the
        # kubelet default of 1 s is too tight for this endpoint.
        for _pod, c in self.containers():
            probe = c.get("readinessProbe") or {}
            self.assertTrue(probe, "no readinessProbe")
            self.assertLessEqual(
                probe.get("initialDelaySeconds", 0),
                2,
                "readiness runs only after the startupProbe has passed, so an initial "
                "delay here is added to every restart outage for nothing",
            )
            timeout = probe.get("timeoutSeconds")
            self.assertIsNotNone(
                timeout, "readinessProbe.timeoutSeconds is unset (kubelet default: 1 s)"
            )
            self.assertGreaterEqual(timeout, 2)
            self.assertLessEqual(
                timeout,
                probe.get("periodSeconds", 10),
                "a timeout longer than the period lets probes overlap",
            )

    def test_the_config_is_generated_rather_than_a_manifest(self):
        # `kubectl rollout undo` reverts the pod template and nothing else, so a config in
        # a hand-written ConfigMap has no rollback mechanism: a ConfigMap edited in place
        # has no history. A configMapGenerator gives the object a content-hash name, which
        # lands in the pod template, so the config is part of what `rollout undo` reverts,
        # and a config change rolls the pods rather than waiting for the kubelet's
        # eventually-consistent projection.
        self.assertTrue(
            NODE_TOML.is_file(),
            f"{NODE_TOML.name} is the generator's input and must exist beside the "
            f"kustomization",
        )
        self.assertFalse(
            by_kind(self.docs, "ConfigMap"),
            "a ConfigMap manifest is back in base/. Its name carries no content hash, so "
            "`rollout undo` cannot revert it together with the image",
        )
        kustomizations = [d for d in self.docs if d.get("kind") == "Kustomization"]
        self.assertTrue(kustomizations, "no kustomization.yaml in base/")
        generators = [
            g for k in kustomizations for g in (k.get("configMapGenerator") or [])
        ]
        self.assertTrue(
            generators, "base/kustomization.yaml declares no configMapGenerator"
        )
        for gen in generators:
            self.assertIn(
                NODE_TOML.name,
                [str(f).split("=")[-1] for f in gen.get("files") or []],
                f"the generator does not read {NODE_TOML.name}",
            )
            self.assertIsNot(
                (gen.get("options") or {}).get("disableNameSuffixHash"),
                True,
                "disableNameSuffixHash removes the content hash, which is the whole "
                "mechanism: without it the ConfigMap is mutated in place again",
            )
        for kust in kustomizations:
            self.assertIsNot(
                (kust.get("generatorOptions") or {}).get("disableNameSuffixHash"),
                True,
                "generatorOptions.disableNameSuffixHash disables the hash globally",
            )

    def test_the_pod_declines_the_serviceaccount_token(self):
        # The node never calls the Kubernetes API (Vault auth is AppRole or an agent-written
        # token file, never the kubernetes auth method), so a projected token is pure
        # escalation surface in a pod that otherwise drops ALL capabilities.
        for pod, _c in self.containers():
            self.assertIs(
                pod.get("automountServiceAccountToken"),
                False,
                "set automountServiceAccountToken: false; the node needs no API access",
            )

    def test_a_startup_probe_protects_the_hydrating_node(self):
        # Liveness is the only probe that can kill, and its default budget (initialDelay
        # 10 plus period 10 x threshold 3, about 40s) is inside a single Vault connect and
        # request timeout, and well inside the PME store self-test. The startupProbe holds
        # liveness off until hydration finishes; without it a populated node is killed
        # mid-hydrate, forever.
        for _pod, c in self.containers():
            probe = c.get("startupProbe")
            self.assertTrue(
                probe,
                "a startupProbe is required: it is the only probe that protects a "
                "hydrating node from the liveness killer",
            )
            self.assertEqual(probe.get("httpGet", {}).get("path"), "/health/ready")
            budget = probe.get("periodSeconds", 10) * probe.get("failureThreshold", 3)
            self.assertGreaterEqual(
                budget,
                300,
                f"the startup budget ({budget}s) must exceed the Vault connect+request "
                f"timeouts (10s + 30s) and the PME store self-test; size it above them",
            )

    def test_the_startup_probe_timeout_is_not_the_kubelet_default(self):
        # The default timeoutSeconds is 1 s. A hydrating node answering /health/ready from
        # a loaded store can miss that under contention, and a timed-out probe counts
        # against failureThreshold exactly like a 503, so the generous threshold above is
        # spent 1 s at a time. The timeout must not exceed the period either.
        for _pod, c in self.containers():
            probe = c.get("startupProbe")
            if not probe:
                continue
            timeout = probe.get("timeoutSeconds")
            self.assertIsNotNone(
                timeout, "startupProbe.timeoutSeconds is unset (kubelet default: 1 s)"
            )
            self.assertGreaterEqual(timeout, 5)
            self.assertLessEqual(timeout, probe.get("periodSeconds", 10))

    def test_both_planes_have_their_own_service(self):
        # Two Services are what let an Ingress select the public plane without exposing
        # :9090, the unauthenticated dataset-state oracle plus /metrics. Merging them back
        # into one is valid Kubernetes and a disclosure.
        ports = {
            p.get("port")
            for svc in by_kind(self.docs, "Service")
            for p in svc["spec"].get("ports", [])
        }
        self.assertIn(PUBLIC_PORT, ports, "no Service exposes the public plane")
        self.assertIn(MANAGEMENT_PORT, ports, "no Service exposes the management plane")
        for svc in by_kind(self.docs, "Service"):
            numbers = {p.get("port") for p in svc["spec"].get("ports", [])}
            self.assertNotEqual(
                numbers,
                {PUBLIC_PORT, MANAGEMENT_PORT},
                f"Service {svc['metadata']['name']} carries both planes; keep them split "
                f"so an Ingress cannot select :{MANAGEMENT_PORT}",
            )

    def test_the_pod_is_not_besteffort(self):
        # Without `requests` the pod is BestEffort and the first thing evicted under node
        # pressure, which for a single-replica Recreate deployment with a five-minute
        # startup budget is downtime. `limits` are not required here: a memory limit is
        # only safe alongside a matching `max_total_query_bytes`, so it stays a deployment
        # decision (see the comment in deployment.yaml).
        for _pod, c in self.containers():
            requests = (c.get("resources") or {}).get("requests") or {}
            for key in ("cpu", "memory"):
                self.assertIn(
                    key,
                    requests,
                    f"set resources.requests.{key}: with no requests the pod is "
                    f"BestEffort and evicted before anything else on the node",
                )

    def test_admitted_concurrency_fits_the_memory_request(self):
        # A broad `record` query retains its page, `datasets matched x max_page_limit x
        # populations x ~450 B`, which at the shipped `[beacon].max_page_limit = 1000` and
        # the 512-population cap is about 220 MiB per matched dataset (docs/deployment.md
        # "Resource baseline"). A burst can therefore claim
        # `max_concurrent_requests x 220 MiB`, and raising either that or the memory
        # request without the other fails here.
        #
        # 220 is hard-coded rather than derived: deriving it would replace one constant
        # with three, the page-limit default, the 512-population cap and the ~450 B row.
        # It fails safe, because lowering `max_page_limit` shrinks the real term while this
        # stays at 220. The node's own ceilings are separate: the sibling test below covers
        # `max_total_query_bytes`, which sheds 503s rather than OOMing.
        retained_mib_per_request = 220
        toml = node_toml()
        self.assertTrue(toml, "no node.toml to read the admitted concurrency from")
        admitted = (toml.get("service") or {}).get("max_concurrent_requests")
        self.assertIsInstance(
            admitted,
            int,
            "[service].max_concurrent_requests must be set explicitly in the shipped "
            "node.toml and be integer-typed: an inherited value sizes the query burst "
            "against nothing, least of all this manifest's memory request",
        )
        for _pod, c in self.node_containers():
            request = ((c.get("resources") or {}).get("requests") or {}).get("memory")
            if request is None:
                continue  # test_the_pod_is_not_besteffort owns that failure
            budget_mib = mebibytes(request)
            need_mib = admitted * retained_mib_per_request
            self.assertLessEqual(
                need_mib,
                budget_mib,
                f"resources.requests.memory is {request} ({budget_mib} MiB) but "
                f"[service].max_concurrent_requests = {admitted} admits a burst of "
                f"{need_mib} MiB ({admitted} x {retained_mib_per_request} MiB retained "
                f"page at [beacon].max_page_limit = 1000 and the 512-population cap). "
                f"Lower the concurrency, lower max_page_limit, or raise the request; "
                f"see docs/deployment.md 'Resource baseline'",
            )

    def test_the_query_byte_budget_fits_the_memory_request(self):
        # `max_concurrent_requests` is a fairness knob; the memory protection is the
        # process-wide retained-row budget `[service].max_total_query_bytes`, over which
        # the node sheds 503s instead of growing. A budget the pod's memory cannot honour
        # means the kernel OOM-kills the container before the node ever sheds, so raising
        # the budget without the request fails here.
        #
        # The example sets the value explicitly even though it equals the built-in default,
        # because the budget also has to stay at or above the node's decode floor
        # (`(query_concurrency x 4 + 16) x max_parquet_row_group_bytes`), which the node
        # warns about at boot when the budget is lower. An inherited value shows neither
        # relation at the site an operator edits.
        toml = node_toml()
        self.assertTrue(toml, "no node.toml to read the byte budget from")
        budget = (toml.get("service") or {}).get("max_total_query_bytes")
        self.assertIsInstance(
            budget,
            int,
            "[service].max_total_query_bytes must be set explicitly in the shipped "
            "node.toml and be integer-typed: an inherited budget is one nobody sized "
            "against this pod's memory request, and the pod is OOM-killed before the node "
            "sheds",
        )
        for _pod, c in self.node_containers():
            resources = c.get("resources") or {}
            request = (resources.get("requests") or {}).get("memory")
            if request is None:
                continue  # test_the_pod_is_not_besteffort owns that failure
            ceiling_mib = mebibytes(request)
            limit = (resources.get("limits") or {}).get("memory")
            if limit is not None:
                ceiling_mib = min(ceiling_mib, mebibytes(limit))
            budget_mib = budget // (1024 * 1024)
            self.assertLessEqual(
                budget_mib,
                ceiling_mib,
                f"[service].max_total_query_bytes = {budget} ({budget_mib} MiB) exceeds the "
                f"pod's memory ({request}{' / limit ' + limit if limit else ''} = {ceiling_mib} MiB): "
                f"the node would be OOM-killed before it sheds. Lower the budget or raise the request.",
            )

    def test_kustomize_does_not_rewrite_the_scraper_selector(self):
        # `labels: includeSelectors: true` rewrites every selector it finds, including the
        # `podSelector` inside a NetworkPolicy ingress `from` element, which names the
        # scraper rather than this app's pods. Rewriting that to this app's own label turns
        # the management-plane rule into "admit our own pods" and blocks all monitoring,
        # while the source still reads correctly. Nothing is lost by disabling it: every
        # selector here is written out explicitly.
        app_label = "app.kubernetes.io/name"
        for kust in (d for d in self.docs if d.get("kind") == "Kustomization"):
            for entry in kust.get("labels") or []:
                self.assertIsNot(
                    entry.get("includeSelectors"),
                    True,
                    "includeSelectors rewrites the NetworkPolicy's scraper podSelector to "
                    "this app's own label, which blocks the scrape it is meant to admit",
                )
        # The rule itself must name someone other than this app: a management-plane `from`
        # that selects this app's own pods admits nothing and yields no metrics.
        app_name = None
        for kust in (d for d in self.docs if d.get("kind") == "Kustomization"):
            for entry in kust.get("labels") or []:
                app_name = (entry.get("pairs") or {}).get(app_label, app_name)
        for pol in by_kind(self.docs, "NetworkPolicy"):
            for rule in pol["spec"].get("ingress", []):
                if not any(
                    p.get("port") == MANAGEMENT_PORT for p in rule.get("ports", [])
                ):
                    continue
                for src in rule.get("from") or []:
                    pod = (src.get("podSelector") or {}).get("matchLabels") or {}
                    if app_name and pod.get(app_label) == app_name:
                        self.fail(
                            f"the management-plane rule selects this app's own pods "
                            f"({app_label}={app_name}); it must select the scraper"
                        )

    def test_the_placeholder_secret_is_not_applied_by_kustomize(self):
        # secret.example.yaml holds literal "<SET ME: ...>" values. The credential check
        # below asserts it still carries placeholders; this asserts that
        # `kubectl apply -k .` does not create a Secret out of them. Only the pair is the
        # property that matters.
        kustomizations = [d for d in self.docs if d.get("kind") == "Kustomization"]
        self.assertTrue(kustomizations, "no kustomization.yaml found")
        secret_files = {p.name for p in manifest_paths() if "Secret" in _kinds_in(p)}
        self.assertTrue(
            secret_files, "no Secret manifest found; this exclusion check is vacuous"
        )
        for kust in kustomizations:
            listed = set(kust.get("resources") or [])
            leaked = listed & secret_files
            self.assertFalse(
                leaked,
                f"{sorted(leaked)} is listed in kustomization resources, so `apply -k` "
                f"would create a Secret containing the literal placeholder string",
            )

    def test_no_real_credentials_are_committed(self):
        # Presence guard, as Deployment and PVC already have. Without it, renaming or
        # deleting secret.example.yaml leaves this iterating an empty list, so the
        # credential check passes precisely when there is nothing to check.
        secrets = by_kind(self.docs, "Secret")
        self.assertTrue(
            secrets,
            "no Secret manifest found; this credential check would pass vacuously",
        )
        for sec in secrets:
            for value in (sec.get("stringData") or {}).values():
                self.assertIn(
                    "SET ME",
                    str(value),
                    "shipped Secret manifests must carry placeholders only",
                )
            self.assertFalse(
                sec.get("data"),
                "use stringData placeholders, never base64 `data` that could hide a "
                "real credential",
            )

    def test_no_commented_optin_redeclares_an_active_table(self):
        """A commented-out `[table]` header must not name an already-live table.

        The ConfigMap documents its opt-in surfaces as commented TOML for an operator to
        uncomment. A `# [service]` header below a live `[service]` cannot be enabled the
        way its own comment instructs: uncommenting both yields a duplicate table, which
        TOML rejects (`duplicate key 'service' in document root`), and the node refuses to
        boot. Uncommenting only the key is no better, because it binds to whichever table
        precedes it, and a bool landing in a `BTreeMap<String, String>` fails
        deserialization with an error naming the wrong section entirely. Neither road
        points at the cause.

        No parsed-TOML assertion can catch this: the file as shipped parses fine and the
        defect lives entirely in comments. Hence the raw body.

        Arrays of tables are exempt. `[[s3.buckets]]` may legally repeat, and appending a
        second element is how the shipped examples document adding another provider
        bucket, so a commented `# [[s3.buckets]]` beneath a live one is correct. Without
        that exemption this guard flags node.example.toml's multi-provider example.
        """
        raw = node_toml_raw()
        self.assertTrue(
            raw,
            "no ConfigMap carries a node.toml, so this check would pass vacuously",
        )
        active, commented = set(), {}
        for lineno, line in enumerate(raw.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("[[") or re.match(r"#\s*\[\[", stripped):
                continue  # array of tables: repeating a header is legal TOML
            if m := re.fullmatch(r"\[([^\[\]]+)\]", stripped):
                active.add(m.group(1))
            elif m := re.fullmatch(r"#\s*\[([^\[\]]+)\]", stripped):
                commented.setdefault(m.group(1), []).append(lineno)
        clash = {t: lines for t, lines in commented.items() if t in active}
        self.assertFalse(
            clash,
            f"commented table header(s) re-declare a table that is already live: "
            f"{clash} (table -> node.toml line numbers). Uncommenting one, as the "
            f"surrounding comment invites, produces a duplicate table and the node "
            f"refuses to boot. Comment the KEY in place inside the existing table "
            f"instead of repeating its header.",
        )


#: The two optional shapes, as components: composable, and layered by the thin overlays
#: below. An overlay that hard-codes `resources: [../../base]` cannot be stacked on a base
#: an operator has customised through their own overlay; applying it reverts the ConfigMap
#: and drops their fourth volume.
PUSH_COMPONENT = COMPONENTS / "push-telemetry"
INBOX_COMPONENT = COMPONENTS / "inbox"
#: The applicable roots: `kubectl apply -k <dir>` targets. One per shape plus the pair,
#: because "these two components compose" is a claim only a render can settle.
PUSH_OVERLAY = OVERLAYS / "push-telemetry"
INBOX_OVERLAY = OVERLAYS / "inbox"
INBOX_PUSH_OVERLAY = OVERLAYS / "inbox-push"

PUSH_ENV = {
    "GDI_NODE__SERVICE__OTLP_ENDPOINT",
    "GDI_NODE__SERVICE__OTLP_METRICS_INTERVAL_SECONDS",
    "OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE",
    "OTEL_EXPORTER_OTLP_HEADERS",
}
#: The one variable the inbox component adds. The path lives in one place, the volumeMount,
#: and this env overlay points the node at it. A second copy of `[service].inbox` in a
#: patched node.toml would drift from the mount.
INBOX_ENV = "GDI_NODE__SERVICE__INBOX"


#: Every directory under deploy/kubernetes/ that `kubectl kustomize` can be pointed at.
#: A new overlay must be added here, which is what makes `test_every_kustomization_root_
#: is_rendered_by_this_file` fail until the new directory gets a test class of its own.
KUSTOMIZATION_ROOTS = (
    ROOT,
    BASE,
    PUSH_OVERLAY,
    INBOX_OVERLAY,
    INBOX_PUSH_OVERLAY,
)
#: Component directories, kept out of KUSTOMIZATION_ROOTS: `kubectl kustomize` pointed at a
#: `kind: Component` directory renders nothing and exits 0, with no error to notice, so
#: "apply the component" is a silent no-op and the two must not be confused.
COMPONENT_ROOTS = (PUSH_COMPONENT, INBOX_COMPONENT)


def kustomize(path):
    """The documents `kubectl kustomize <path>` renders, or None when kubectl is absent.

    The only way to know an overlay builds is to build it: asserting on the text of
    `resources` can bless an overlay that has never rendered once. Callers skip loudly on
    None, and the `k8s-manifests` gate leg reports that skip in its summary rather than
    counting the test as run.
    """
    exe = shutil.which("kubectl")
    if exe is None:
        return None
    proc = subprocess.run(
        [exe, "kustomize", str(path)], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"`kubectl kustomize {path.relative_to(REPO_ROOT)}` exited "
            f"{proc.returncode}:\n{proc.stderr.strip()}"
        )
    return [d for d in yaml.safe_load_all(proc.stdout) if d]


class LayoutTest(unittest.TestCase):
    """deploy/kubernetes/ is an alias + base/ + components/ + overlays/, and nothing else."""

    def test_every_kustomization_root_is_rendered_by_this_file(self):
        # Every directory a `kubectl kustomize` can target must be one this file renders.
        # An overlay added beside push-telemetry/ without a test class is otherwise never
        # rendered by anything.
        found = {p.parent for p in ROOT.rglob("kustomization.y*ml")}
        self.assertEqual(
            found,
            set(KUSTOMIZATION_ROOTS) | set(COMPONENT_ROOTS),
            "a kustomization root exists that this file does not render (or one listed "
            "here is gone): add it to KUSTOMIZATION_ROOTS (or COMPONENT_ROOTS) and give "
            "it a test class",
        )
        # ...and every subdirectory is one of the known roots or a container for them: a
        # stray directory of manifests is invisible to every assertion here.
        dirs = {p for p in ROOT.rglob("*") if p.is_dir()}
        self.assertEqual(
            dirs,
            (
                {BASE, OVERLAYS, COMPONENTS}
                | set(KUSTOMIZATION_ROOTS)
                | set(COMPONENT_ROOTS)
            )
            - {ROOT},
            "a directory under deploy/kubernetes/ is covered by no test class",
        )

    def test_components_are_components_and_overlays_are_kustomizations(self):
        # `kubectl kustomize <a Component directory>` prints nothing and exits 0, with no
        # error to notice, so an operator told to "apply the component" applies an empty
        # stream and concludes the manifests are broken. A `kind: Kustomization` under
        # components/ cannot be composed at all, since kustomize refuses a Kustomization in
        # `components:`. Which kind lives where therefore decides whether either works.
        for path in COMPONENT_ROOTS:
            with (path / "kustomization.yaml").open(encoding="utf-8") as fh:
                (kust,) = [d for d in yaml.safe_load_all(fh) if d]
            self.assertEqual(
                kust.get("kind"),
                "Component",
                f"{path.name} lives under components/ but is not a Component, so it cannot "
                f"be listed in another kustomization's `components:`",
            )
            self.assertTrue(
                str(kust.get("apiVersion", "")).endswith("v1alpha1"),
                f"{path.name}: Components are kustomize.config.k8s.io/v1alpha1",
            )
        for path in KUSTOMIZATION_ROOTS:
            with (path / "kustomization.yaml").open(encoding="utf-8") as fh:
                (kust,) = [d for d in yaml.safe_load_all(fh) if d]
            self.assertEqual(
                kust.get("kind"),
                "Kustomization",
                f"{path} is documented as an `apply -k` target, but a Component renders "
                f"empty and exits 0 there",
            )

    def test_every_overlay_is_a_thin_composition_of_base_and_components(self):
        # An overlay under overlays/ exists to be applied; the content belongs in a
        # component so it can be stacked. Kustomize's load restrictor refuses a patch file
        # from a sibling directory, so a patch left in an overlay has to be copied to be
        # reused, and the overlays stop composing one copied file at a time.
        for path in KUSTOMIZATION_ROOTS:
            if path in (ROOT, BASE):
                continue
            with (path / "kustomization.yaml").open(encoding="utf-8") as fh:
                (kust,) = [d for d in yaml.safe_load_all(fh) if d]
            self.assertEqual(
                kust.get("resources"),
                ["../../base"],
                f"{path.name} must build on the base as a sibling path",
            )
            components = kust.get("components") or []
            self.assertTrue(components, f"{path.name} lists no components")
            for ref in components:
                self.assertTrue(
                    (path / ref).resolve() in {p.resolve() for p in COMPONENT_ROOTS},
                    f"{path.name} lists {ref!r}, which is not a known component",
                )
            self.assertEqual(
                set(kust) - {"apiVersion", "kind", "resources", "components"},
                set(),
                f"{path.name} carries more than a composition; put it in a component",
            )
            self.assertEqual(
                [p.name for p in path.iterdir()],
                ["kustomization.yaml"],
                f"{path.name} holds a file besides its kustomization; a patch there "
                f"cannot be reused by any other overlay, which is the defect this layout "
                f"exists to fix",
            )

    def test_the_root_is_a_pure_alias_for_the_base(self):
        # The alias exists so `kubectl apply -k deploy/kubernetes` keeps working. It must
        # hold no resources of its own: kustomize rejects an ancestor as a resource, and a
        # file outside the loading directory, so anything listed here is unreachable from
        # every overlay and the layout regrows the cycle the split removed.
        with (ROOT / "kustomization.yaml").open(encoding="utf-8") as fh:
            (kust,) = [d for d in yaml.safe_load_all(fh) if d]
        self.assertEqual(kust.get("resources"), ["base"])
        self.assertEqual(
            set(kust) - {"apiVersion", "kind", "resources"},
            set(),
            "the root kustomization carries more than the alias; put it in base/",
        )

    def test_the_alias_renders_byte_identically_to_the_base(self):
        rendered = kustomize(ROOT)
        if rendered is None:
            self.skipTest(
                "kubectl not installed; the kustomize render of deploy/kubernetes is not "
                "checked"
            )
        self.assertEqual(rendered, kustomize(BASE))
        self.assertTrue(by_kind(rendered, "Deployment"), "the render has no Deployment")


class PushTelemetryComponentTest(unittest.TestCase):
    """The push-based shape (deploy/kubernetes/components/push-telemetry/) stays a
    component that adds exactly the four export variables, and never the credential
    itself."""

    @classmethod
    def setUpClass(cls):
        cls.files = {p.name: p for p in PUSH_COMPONENT.iterdir() if p.suffix == ".yaml"}
        cls.docs = {}
        for name, path in cls.files.items():
            with path.open(encoding="utf-8") as fh:
                cls.docs[name] = [d for d in yaml.safe_load_all(fh) if d]

    def test_the_component_carries_the_patch_and_no_base_reference(self):
        (kust,) = self.docs["kustomization.yaml"]
        # A component has no `resources: [../../base]`: it is layered onto whatever is
        # being built, which is what makes it stackable. The overlay that applies it names
        # the base; this file must not, or it would pull a second copy in.
        self.assertNotIn("../../base", kust.get("resources") or [])
        patches = [p.get("path") for p in kust.get("patches") or []]
        self.assertEqual(patches, ["deployment-env.patch.yaml"])
        self.assertIn("deployment-env.patch.yaml", self.files)

    def test_the_overlay_builds_on_the_base_and_applies_the_env_patch(self):
        rendered = kustomize(PUSH_OVERLAY)
        if rendered is None:
            self.skipTest(
                "kubectl not installed; the kustomize render of the push-telemetry "
                "overlay is not checked, and the ancestor-cycle build failure this test "
                "exists for is invisible without it"
            )
        base = kustomize(BASE)
        (dep,) = by_kind(rendered, "Deployment")
        (base_dep,) = by_kind(base, "Deployment")
        (container,) = dep["spec"]["template"]["spec"]["containers"]
        env = {e["name"] for e in container.get("env") or []}
        self.assertTrue(
            env >= PUSH_ENV,
            f"the rendered Deployment lacks {sorted(PUSH_ENV - env)}; the patch did "
            "not apply",
        )
        # The overlay changes the container's env and nothing else: strip env from both
        # renders and they must be equal, so a patch that grew a second change is seen.
        for doc in (dep, base_dep):
            for c in doc["spec"]["template"]["spec"]["containers"]:
                c.pop("env", None)
        self.assertEqual(dep, base_dep, "the overlay changed more than the env")
        self.assertEqual(
            [d for d in rendered if d.get("kind") != "Deployment"],
            [d for d in base if d.get("kind") != "Deployment"],
            "the overlay touched a resource other than the Deployment",
        )
        self.assertFalse(
            by_kind(rendered, "Secret"), "the overlay must not render a Secret"
        )

    def test_the_patch_targets_the_base_container_with_the_four_variables(self):
        (patch,) = self.docs["deployment-env.patch.yaml"]
        base_names = {
            c["name"]
            for d in by_kind(load_all(), "Deployment")
            for c in d["spec"]["template"]["spec"]["containers"]
        }
        (container,) = patch["spec"]["template"]["spec"]["containers"]
        self.assertIn(
            container["name"],
            base_names,
            "the patch names a container the base does not have",
        )
        env = {e["name"]: e for e in container["env"]}
        self.assertEqual(set(env), PUSH_ENV)
        self.assertEqual(
            env["OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE"]["value"], "delta"
        )
        self.assertIn("<SET ME", env["GDI_NODE__SERVICE__OTLP_ENDPOINT"]["value"])
        ref = (
            env["OTEL_EXPORTER_OTLP_HEADERS"]
            .get("valueFrom", {})
            .get("secretKeyRef", {})
        )
        self.assertEqual(
            ref.get("name"),
            "gdi-node-standalone-otlp",
            "the credential must come from a Secret",
        )

    def test_the_credential_secret_is_a_placeholder_and_not_applied(self):
        (secret,) = self.docs["secret.example.yaml"]
        self.assertEqual(secret["kind"], "Secret")
        for value in (secret.get("stringData") or {}).values():
            self.assertIn(
                "<SET ME", value, "secret.example.yaml must hold placeholders only"
            )
        for kust in [
            d
            for docs in self.docs.values()
            for d in docs
            if d.get("kind") == "Kustomization"
        ]:
            self.assertNotIn("secret.example.yaml", kust.get("resources") or [])
        for kust in [d for d in load_all() if d.get("kind") == "Kustomization"]:
            self.assertNotIn(
                "push-telemetry",
                " ".join(kust.get("resources") or []),
                "the base must not pull the overlay in",
            )


class InboxComponentTest(unittest.TestCase):
    """The inbox shape (deploy/kubernetes/components/inbox/): a fourth volume, the env
    overlay that points the node at it, and the `ops` sidecar that is the only way to get
    a dataset into it on Kubernetes."""

    @classmethod
    def setUpClass(cls):
        cls.rendered = kustomize(INBOX_OVERLAY)
        cls.base = None if cls.rendered is None else kustomize(BASE)

    def deployment(self):
        if self.rendered is None:
            self.skipTest(
                "kubectl not installed; the kustomize render of the inbox overlay is not "
                "checked"
            )
        (dep,) = by_kind(self.rendered, "Deployment")
        return dep["spec"]["template"]["spec"]

    def test_the_inbox_is_a_fourth_claim_and_not_an_emptydir(self):
        # The inbox holds decrypted staging dirs until ingest moves them, and a drop that
        # vanishes on restart is a silent data-loss path: the tool reports success, the
        # dataset never appears.
        pod = self.deployment()
        (node,) = [c for c in pod["containers"] if c["name"] == "gdi-node-standalone"]
        mount = [m for m in node["volumeMounts"] if m["mountPath"].endswith("/inbox")]
        self.assertEqual(len(mount), 1, "the node container mounts no inbox")
        volume = [v for v in pod["volumes"] if v["name"] == mount[0]["name"]]
        self.assertTrue(
            (volume[0].get("persistentVolumeClaim") or {}).get("claimName"),
            "the inbox must be a PVC: an emptyDir loses every staged drop on restart",
        )
        claims = {
            p["metadata"]["name"]
            for p in by_kind(self.rendered, "PersistentVolumeClaim")
        }
        self.assertEqual(
            len(claims),
            len(
                {
                    p["metadata"]["name"]
                    for p in by_kind(self.base, "PersistentVolumeClaim")
                }
            )
            + 1,
            "the component must add exactly one claim",
        )

    def test_the_node_is_pointed_at_the_inbox_by_the_env_overlay(self):
        # One copy of the path. Patching `[service].inbox` into the ConfigMap's node.toml
        # would be a second copy that drifts from the volumeMount, and the failure that
        # produces, an inbox configured at a path nothing mounts on a read-only root
        # filesystem, is a runtime error rather than an apply-time one.
        pod = self.deployment()
        (node,) = [c for c in pod["containers"] if c["name"] == "gdi-node-standalone"]
        env = {e["name"]: e.get("value") for e in node.get("env") or []}
        self.assertIn(INBOX_ENV, env, "the component sets no inbox env overlay")
        mounts = {m["mountPath"].rstrip("/") for m in node["volumeMounts"]}
        self.assertIn(
            str(env[INBOX_ENV]).rstrip("/"),
            mounts,
            f"{INBOX_ENV} names a path this pod does not mount; with a read-only root "
            f"filesystem the node cannot create it",
        )

    def test_the_ops_sidecar_can_receive_a_drop_and_runs_as_the_node_uid(self):
        # There is no other way in. `kubectl cp` into the node container fails with
        # `exec: "tar": executable file not found`, because the runtime image is
        # distroless, and the dataset tool's inbox verbs know only local directories. The
        # sidecar shares the inbox volume in the same pod, so a drop lands owned by the
        # node's uid with no scale-to-zero dance and no downtime.
        pod = self.deployment()
        ops = [c for c in pod["containers"] if c["name"] == "ops"]
        self.assertEqual(len(ops), 1, "the inbox component ships no `ops` sidecar")
        ops = ops[0]
        mounts = {m["mountPath"].rstrip("/") for m in ops.get("volumeMounts") or []}
        (node,) = [c for c in pod["containers"] if c["name"] == "gdi-node-standalone"]
        node_env = {e["name"]: e.get("value") for e in node.get("env") or []}
        self.assertIn(
            str(node_env[INBOX_ENV]).rstrip("/"),
            mounts,
            "the sidecar must share the inbox volume, or `kubectl cp` into it lands "
            "nowhere the node reads",
        )
        # The scratch space the documented recipe copies into. `kubectl cp` is a streaming
        # tar extract, not an atomic rename, so copying straight into the inbox lets the
        # node's watcher see a half-written staging dir. The recipe lands in /tmp and then
        # has the tool install it atomically. With a read-only root filesystem /tmp is
        # writable only because this volume is here, and without it the README's first step
        # fails with EROFS.
        staging = [
            m
            for m in ops.get("volumeMounts") or []
            if m["mountPath"].rstrip("/") == "/tmp"
        ]
        self.assertEqual(
            len(staging),
            1,
            "the ops sidecar has no writable /tmp; the documented `kubectl cp` landing "
            "area does not exist on a read-only root filesystem",
        )
        volume = [v for v in pod["volumes"] if v["name"] == staging[0]["name"]]
        self.assertEqual(len(volume), 1, "the /tmp mount names no volume")
        self.assertIn(
            "emptyDir",
            volume[0],
            "the staging area must be an emptyDir: it holds one in-flight copy, is "
            "discarded with the pod, and must not compete for the inbox claim",
        )
        sc = ops.get("securityContext") or {}
        self.assertEqual(
            sc.get("runAsUser"),
            UID,
            "a drop must arrive owned by the node's uid, which is why the sidecar is "
            "co-located rather than run as a helper pod",
        )
        self.assertFalse(sc.get("allowPrivilegeEscalation", True))
        self.assertEqual((sc.get("capabilities") or {}).get("drop"), ["ALL"])

    def test_the_ownership_fix_covers_the_inbox_too(self):
        # A fresh inbox PVC trips the node's two UNSUPPORTED posture warnings on every
        # boot: a group- or other-writable inbox is a TOCTOU hijack, and a group- or
        # other-readable one exposes decrypted content. Unlike data_dir, the node does not
        # tighten the inbox, so nothing else fixes this.
        pod = self.deployment()
        (node,) = [c for c in pod["containers"] if c["name"] == "gdi-node-standalone"]
        inbox = next(
            m for m in node["volumeMounts"] if m["mountPath"].endswith("/inbox")
        )
        roots = [
            c
            for c in pod.get("initContainers") or []
            if (c.get("securityContext") or {}).get("runAsUser") == 0
        ]
        self.assertEqual(len(roots), 1)
        covered = {
            m["mountPath"].rstrip("/") for m in roots[0].get("volumeMounts") or []
        }
        self.assertIn(
            inbox["mountPath"].rstrip("/"),
            covered,
            "the ownership init container does not mount the inbox, so the fresh PVC "
            "stays root-owned and world-writable",
        )


class ComposedOverlayTest(unittest.TestCase):
    """The two components stack.

    An overlay that hard-codes `resources: [../../base]` plus a patch in its own directory
    cannot be layered onto a base an operator has customised: applying it reverts the
    ConfigMap and drops the fourth volume.
    """

    def test_both_components_compose_into_one_render(self):
        rendered = kustomize(INBOX_PUSH_OVERLAY)
        if rendered is None:
            self.skipTest(
                "kubectl not installed; the composed render is not checked, and it is "
                "the only assertion that can catch a component that does not stack"
            )
        (dep,) = by_kind(rendered, "Deployment")
        pod = dep["spec"]["template"]["spec"]
        names = {c["name"] for c in pod["containers"]}
        self.assertIn("ops", names, "the inbox component did not apply")
        (node,) = [c for c in pod["containers"] if c["name"] == "gdi-node-standalone"]
        env = {e["name"] for e in node.get("env") or []}
        self.assertTrue(
            env >= PUSH_ENV | {INBOX_ENV},
            f"the composed render lacks {sorted((PUSH_ENV | {INBOX_ENV}) - env)}: the "
            f"two components did not both apply",
        )
        # The composition is exactly the union, one applied render rather than two half
        # renders: the inbox claim survives the push component being layered after it.
        claims = {
            p["metadata"]["name"] for p in by_kind(rendered, "PersistentVolumeClaim")
        }
        self.assertEqual(
            claims,
            {
                p["metadata"]["name"]
                for p in by_kind(kustomize(INBOX_OVERLAY), "PersistentVolumeClaim")
            },
        )


class GeneratedConfigTest(unittest.TestCase):
    """The rendered ConfigMap is hashed, and the pod template points at that name."""

    def test_the_rendered_configmap_name_carries_a_content_hash(self):
        rendered = kustomize(BASE)
        if rendered is None:
            self.skipTest(
                "kubectl not installed; the generated ConfigMap name is not checked"
            )
        (cm,) = by_kind(rendered, "ConfigMap")
        name = cm["metadata"]["name"]
        self.assertRegex(
            name,
            r"-[bcdfghkmnpqrstvwxz2456789]{10}$",
            "the generated ConfigMap has no hash suffix, so a config change does not roll "
            "the Deployment and `rollout undo` cannot revert it with the image",
        )
        self.assertIn(
            "node.toml",
            cm.get("data") or {},
            "the generated ConfigMap does not carry node.toml under that key; the "
            "container is started with --config .../node.toml",
        )
        (dep,) = by_kind(rendered, "Deployment")
        referenced = {
            (v.get("configMap") or {}).get("name")
            for v in dep["spec"]["template"]["spec"]["volumes"]
        }
        self.assertIn(
            name,
            referenced,
            "the pod template does not reference the generated name; kustomize's name "
            "reference transformer did not rewrite it, so the pod mounts a ConfigMap "
            "that does not exist",
        )


DOCKERFILE = REPO_ROOT / "Dockerfile"


class DockerfileVolumeContractTest(unittest.TestCase):
    """The image pre-creates its mount points, and the manifests mount where it did."""

    @classmethod
    def setUpClass(cls):
        cls.lines = [
            ln.strip()
            for ln in DOCKERFILE.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        cls.toml = node_toml()

    def test_every_workdir_precedes_the_volume_declaration(self):
        # Docker discards writes made to a path after its `VOLUME` line, and `WORKDIR` is
        # the only tool the distroless runtime has to pre-create a directory owned by the
        # non-root user. A `WORKDIR` moved below `VOLUME` is valid Dockerfile and a
        # root-owned, unwritable mount at runtime.
        volume_idx = [i for i, ln in enumerate(self.lines) if ln.startswith("VOLUME ")]
        self.assertTrue(volume_idx, "no VOLUME line in the Dockerfile")
        first_volume = volume_idx[0]
        late = [
            ln
            for i, ln in enumerate(self.lines)
            if ln.startswith("WORKDIR /var/lib/") and i > first_volume
        ]
        self.assertEqual(
            late, [], f"WORKDIR after VOLUME, so its directory is discarded: {late}"
        )
        pre_created = {
            ln.split(None, 1)[1]
            for ln in self.lines[:first_volume]
            if ln.startswith("WORKDIR /var/lib/")
        }
        self.assertTrue(pre_created, "no /var/lib/ WORKDIR precedes the VOLUME line")
        for declared in self._volume_paths(self.lines[first_volume]):
            self.assertIn(
                declared,
                pre_created,
                f"{declared} is declared as a VOLUME but never pre-created by a WORKDIR",
            )

    @staticmethod
    def _volume_paths(volume_line):
        body = volume_line[len("VOLUME") :].strip()
        return re.findall(r'"([^"]+)"', body) if body.startswith("[") else body.split()

    def test_the_pre_created_override_path_is_the_configmaps_override_dir(self):
        # The override store is not a VOLUME, because its default is inside the datasets
        # volume, but it is pre-created, because deploy/kubernetes puts it on its own
        # PVC at exactly that path. Two copies of one path: bound here so the ConfigMap
        # cannot point the store at a directory the image never created (root-owned mount,
        # `overrides init` fails with EACCES, boot refuses under require_override_store).
        override_dir = self.toml.get("service", {}).get("override_dir")
        self.assertTrue(override_dir, "the ConfigMap's node.toml sets no override_dir")
        pre_created = {
            ln.split(None, 1)[1] for ln in self.lines if ln.startswith("WORKDIR ")
        }
        self.assertIn(
            override_dir,
            pre_created,
            f"configmap override_dir {override_dir!r} is not a path the Dockerfile "
            f"pre-creates with WORKDIR: {sorted(pre_created)}",
        )


if __name__ == "__main__":
    unittest.main()
