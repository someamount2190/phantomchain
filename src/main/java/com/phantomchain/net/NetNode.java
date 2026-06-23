package com.phantomchain.net;

import com.phantomchain.debug.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import fi.iki.elonen.NanoHTTPD;
import org.json.JSONArray;
import org.json.JSONObject;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * Networked validator with Byzantine accountability:
 *   - VIEW-CHANGE: proposer for (h,view) = (h+v) mod N; dead/slashed proposer slots time out and advance.
 *   - DISCOVERY: only a seed is configured; membership learned via /announce + /peers.
 *   - PERSISTENT VOTES: each per-height vote is written to disk, so a crash-restart can't equivocate.
 *   - DOUBLE-SIGN SLASHING: votes are gossiped; two conflicting signatures from one validator at one
 *     height = equivocation evidence -> a SLASH tx -> on commit every node burns that validator's
 *     stake and ejects it (excluded from quorum + proposing). Crash- AND equivocation-accountable.
 * Commit = 2-of-3 quorum certificate of standard ML-DSA signatures (multisig, not a true threshold sig).
 */
public class NetNode extends NanoHTTPD {

    int N;                         // validator count (per-node view; grows as this node processes joins)
    static final long VIEW_TIMEOUT = 3000L;
    static final long TICK = 700L;

    String[] VAL_IDS;              // validator ids by position (per-node view, tracks N)
    static final Map<String, MLDSAPublicKeyParameters> PUB_BY_ID = new HashMap<>();
    static Genesis GEN;            // the chain definition (validator set), loaded once per process
    static final Map<String, String> GEN_VALPUBS = new HashMap<>();   // genesis id -> pubkey hex (seeds ledger.valPubs)

    volatile int index;            // -1 = observer until it joins via VALJOIN
    final int certIndex;           // TLS cert slot
    final String selfAddr;
    final List<String> seeds;
    final MLDSAPrivateKeyParameters key;
    final String id;
    final File dataFile;
    final File votesFile;
    final Ledger ledger = new Ledger();

    final Map<Integer, String> peers = new ConcurrentHashMap<>();
    final Set<String> seenTx = Collections.synchronizedSet(new HashSet<String>());
    final Set<String> seenBlock = Collections.synchronizedSet(new HashSet<String>());
    final Map<Integer, JSONObject> votedAt = new ConcurrentHashMap<>();                 // PERSISTED: height -> our {hash,sig}
    final Map<String, Map<Integer, JSONObject>> seenVotes = new ConcurrentHashMap<>();  // valId -> height -> {hash,sig}
    final Set<String> processedVotes = Collections.synchronizedSet(new HashSet<String>());
    volatile boolean running = true;
    volatile boolean byzantine = false;
    volatile long beaconCtr = 0;       // index of our current outstanding reveal (persisted with votes)
    static final String OP_TOKEN = System.getenv("PC_OP_TOKEN") == null ? "" : System.getenv("PC_OP_TOKEN");  // operator RPC token
    static final boolean DEBUG_ENDPOINTS = "1".equals(System.getenv("PC_DEBUG"));                              // gate /byz/equivocate
    static final Set<String> OP_ENDPOINTS = new HashSet<>(java.util.Arrays.asList(
            "/submit", "/bond", "/unbond", "/unjail", "/vouch", "/gov/propose", "/gov/vote", "/valjoin", "/bridge/out"));
    /** Endpoints served on the OPEN read port (server-auth TLS, no client cert) — read-only, no state
     *  mutation. Everything else (writes, consensus, gossip) lives on the mTLS peer port (rpcPort). */
    static final Set<String> READ_ENDPOINTS = new HashSet<>(java.util.Arrays.asList(
            "/status", "/econ", "/identity", "/head", "/account", "/stateproof", "/shard", "/extaddr", "/bridge/outs",
            "/oracle", "/identity-info", "/body", "/rsshard", "/block", "/peers", "/genesis", "/gov"));
    int readPort;                          // open read port (rpcPort + 1 by default)
    fi.iki.elonen.NanoHTTPD readServer;   // the open-read server (server-auth TLS, NO client cert)
    javax.net.ssl.SSLContext tls;

    static synchronized void initFromGenesis(Genesis gen) {
        if (GEN != null) return;
        GEN = gen;
        for (Genesis.Validator v : gen.validators) {   // process-global identity material (append-only, same for every node)
            PUB_BY_ID.put(v.id, PhantomCrypto.pubKey(v.pubkeyHex));
            GEN_VALPUBS.put(v.id, v.pubkeyHex);
        }
    }

    NetNode(Genesis gen, NodeConfig cfg, MLDSAPrivateKeyParameters key) throws Exception {
        super(cfg.rpcPort);
        initFromGenesis(gen);
        this.N = gen.validators.size();                // per-node validator view (so in-process nodes don't share one)
        this.VAL_IDS = new String[N];
        for (int i = 0; i < N; i++) this.VAL_IDS[i] = gen.validators.get(i).id;
        this.key = key;
        this.id = Keys.idOf(key);
        this.index = gen.indexOfId(this.id);   // -1 if not a genesis validator -> runs as observer until it joins
        this.certIndex = cfg.certIndex >= 0 ? cfg.certIndex : index;
        this.selfAddr = cfg.selfAddr;
        this.seeds = cfg.seeds;
        this.readPort = cfg.readPort > 0 ? cfg.readPort : cfg.rpcPort + 1;
        File dataDir = new File(cfg.dataDir); dataDir.mkdirs();
        this.dataFile = new File(dataDir, "chain.json");
        this.votesFile = new File(dataDir, "votes.json");
        if (index >= 0) peers.put(index, selfAddr);
    }

    /** Rebuild the local validator view from committed ledger state (append-only set + joined pubkeys),
     *  and promote ourselves from observer to validator once our VALJOIN has committed. */
    synchronized void syncValidatorSet() {
        int vn = ledger.validatorCount();
        if (vn != N) {
            N = vn;
            VAL_IDS = ledger.validatorIds();
            for (Map.Entry<String, String> e : ledger.valPubs().entrySet())
                if (!"CLUSTER".equals(e.getValue()))   // a cluster has no single key; its consensus sig is an M-of-N member bundle (verifyClusterVote)
                    PUB_BY_ID.computeIfAbsent(e.getKey(), kk -> PhantomCrypto.pubKey(e.getValue()));
        }
        if (index < 0) {
            int myIdx = ledger.validatorIndex(id);
            if (myIdx >= 0) { index = myIdx; peers.put(index, selfAddr);
                System.out.println("node " + id.substring(0, 8) + "... JOINED validator set at index " + myIdx); }
        }
    }

    void boot() throws Exception {
        if (dataFile.exists()) {
            ledger.fromJson(new String(Files.readAllBytes(dataFile.toPath()), StandardCharsets.UTF_8));
            System.out.println("node" + index + " loaded chain height=" + ledger.height() + " slashed=" + ledger.slashedCount());
        } else {
            java.util.List<String> vals = new java.util.ArrayList<>();
            LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
            Map<String, Long> stk = new HashMap<>(); Map<String, Long> idn = new HashMap<>();
            java.util.Set<String> seedVerified = new HashSet<>();
            for (Genesis.Validator v : GEN.validators) {
                vals.add(v.id);
                if (v.alloc > 0) alloc.put(v.id, v.alloc);
                stk.put(v.id, v.stake); idn.put(v.id, v.identity);
                if (v.verified) seedVerified.add(v.id);   // founders bootstrap the web-of-trust
            }
            if (GEN.reserve > 0) alloc.put(Ledger.BRIDGE_RESERVE, GEN.reserve);   // genesis bridge reserve
            Map<String, String> beaconCommits = new HashMap<>();
            for (Genesis.Validator v : GEN.validators) if (!v.beaconCommit0.isEmpty()) beaconCommits.put(v.id, v.beaconCommit0);
            ledger.genesisEcon(GEN.chainId, alloc, vals, stk, idn, seedVerified, GEN_VALPUBS, beaconCommits, GEN.genesisTime);
            Map<String, String> regions = new HashMap<>(), tiers = new HashMap<>(), custodians = new HashMap<>();
            for (Genesis.Validator v : GEN.validators) {
                if (!v.region.isEmpty()) regions.put(v.id, v.region);   // opt-in geo regions
                if (!v.tier.isEmpty()) tiers.put(v.id, v.tier);         // heavy/light storage tier
            }
            for (String cp : GEN.custodianPubs) custodians.put(Ledger.idOf(cp), cp);   // bridge custodians (M-of-N)
            ledger.applyGenesisProfile(regions, tiers, custodians, GEN.bridgeThreshold);
            save();
            System.out.println("node" + index + " genesis chainId=" + GEN.chainId + " validators=" + N);
        }
        loadVotes();
        syncValidatorSet();   // pick up any validators joined since genesis (and our own index if we joined)
        // commit-reveal beacon: secret seed is DERIVED from our ML-DSA key (so commit0 is publishable at
        // keygen and bound at genesis/VALJOIN — no unconstrained first reveal), then resync our counter.
        String onchainCommit = ledger.commitOf(id);
        if (onchainCommit != null) for (long c = Math.max(0, beaconCtr - 3); c <= beaconCtr + 3; c++)
            if (PhantomCrypto.hex(PhantomCrypto.sha3_256(beaconSecret(c))).equals(onchainCommit)) { beaconCtr = c; break; }
        // TLS 1.3 transport: the per-cluster CA + node certs are minted by the genesis ceremony and
        // distributed with the chain as dataDir/certs/{truststore.p12, node-<index>.p12}.
        java.io.File certDir = new java.io.File(dataFile.getParentFile(), "certs");
        if (certIndex < 0 || !new java.io.File(certDir, "node-" + certIndex + ".p12").exists()
                || !new java.io.File(certDir, "truststore.p12").exists())
            throw new IllegalStateException("TLS cert (node-" + certIndex + ".p12) missing in " + certDir
                    + " (run the genesis ceremony / mintcert and place this node's cert there)");
        tls = TlsSetup.context(certDir, certIndex);
        // mTLS: the server socket (with a REQUIRED peer client cert) is supplied by getServerSocketFactory()
        // below — we bypass makeSecure(), whose SecureServerSocketFactory.create() hard-resets
        // setNeedClientAuth(false) (verified in the 2.3.1 bytecode), which would silently defeat client auth.
        start();
        // open READ port (server-auth TLS, NO client cert): the documented open read endpoints stay
        // queryable by curl, while the peer port (rpcPort) requires a client cert (mTLS) for everything.
        readServer = new fi.iki.elonen.NanoHTTPD(readPort) {
            @Override public Response serve(IHTTPSession s) { return NetNode.this.serveRead(s); }
        };
        readServer.makeSecure(tls.getServerSocketFactory(), new String[]{"TLSv1.3", "TLSv1.2"});
        readServer.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
        System.out.println("node" + index + " (" + GEN.chainId + ") up at " + selfAddr + " TLS=on("
                + (TlsSetup.hybrid ? "BCJSSE, PQ-hybrid X25519MLKEM768 offered" : "JDK TLSv1.3")
                + ") seeds=" + seeds + " persistedVotes=" + votedAt.size());
        new Thread(this::discoveryLoop, "disc-" + index).start();
        new Thread(consensus::loop, "cons-" + index).start();
    }

    /** mTLS server socket: a peer MUST present a node cert signed by the cluster CA. We override the
     *  factory NanoHTTPD's start() uses (getServerSocketFactory().create()) rather than makeSecure(),
     *  because NanoHTTPD 2.3.1's SecureServerSocketFactory.create() hard-resets setNeedClientAuth(false)
     *  after our factory returns — silently defeating client auth. The genesis node cert carries no
     *  extendedKeyUsage restriction, so it doubles as the client credential each peer already presents
     *  via its SSLContext KeyManager (ARCHITECTURE §6). */
    @Override
    public fi.iki.elonen.NanoHTTPD.ServerSocketFactory getServerSocketFactory() {
        final javax.net.ssl.SSLContext ctx = tls;
        return () -> {
            javax.net.ssl.SSLServerSocket ss = (javax.net.ssl.SSLServerSocket) ctx.getServerSocketFactory().createServerSocket();
            ss.setNeedClientAuth(true);
            ss.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
            return ss;
        };
    }

    /** Crash-safe write: stage to a temp file, then atomically rename over the target. */
    static void atomicWrite(File f, byte[] data) throws Exception {
        File tmp = new File(f.getParentFile(), f.getName() + ".tmp");
        Files.write(tmp.toPath(), data);
        try { Files.move(tmp.toPath(), f.toPath(),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE); }
        catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(tmp.toPath(), f.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    void save() { try { atomicWrite(dataFile, ledger.toJson().getBytes(StandardCharsets.UTF_8)); } catch (Exception e) { System.err.println("save failed: " + e); } }

    synchronized void saveVotes() {
        try {
            JSONObject o = new JSONObject();
            for (Map.Entry<Integer, JSONObject> e : votedAt.entrySet()) o.put(String.valueOf(e.getKey()), e.getValue());
            o.put("_beaconCtr", beaconCtr);
            atomicWrite(votesFile, o.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) { System.err.println("saveVotes failed: " + e); }
    }
    void loadVotes() {
        try {
            if (!votesFile.exists()) return;
            JSONObject o = new JSONObject(new String(Files.readAllBytes(votesFile.toPath()), StandardCharsets.UTF_8));
            for (String k : o.keySet()) { if (k.startsWith("_")) continue; votedAt.put(Integer.parseInt(k), o.getJSONObject(k)); }
            beaconCtr = o.optLong("_beaconCtr", 0);
        } catch (Exception e) { System.err.println("loadVotes: corrupt vote history, starting empty (double-vote protection reset for prior heights): " + e); }
    }

    boolean isSlashed(int idx) { return ledger.excluded(VAL_IDS[idx]); }   // excluded = permanent tombstone OR active jail

    /** BFT quorum over the ACTIVE (non-excluded) validator set, recomputed each block so that
     *  tombstoned/jailed validators don't count in the denominator (chain stays live as members drop).
     *  Deterministic across nodes because exclusion is committed state (state-root-bound). */
    int quorumNow() {
        int active = 0;
        for (int i = 0; i < N; i++) if (!isSlashed(i)) active++;
        return Math.max(1, active - (active - 1) / 3);
    }

    // ---- ledger-history sharding: each node keeps only its assigned archived block bodies ----
    static final int RS_K = 2, RS_N = 4;   // erasure code: any RS_K of RS_N shards reconstruct a body
    static final ReedSolomon RS = new ReedSolomon(RS_K, RS_N);
    boolean isLight() { return "light".equals(ledger.tierOf(id)); }
    int myShardIdx() { return (index < 0 ? 0 : index) % RS_N; }
    /** Drop full archived bodies, retaining only THIS node's RS shard (~1/k size). Light tier keeps nothing. */
    void pruneArchived() throws Exception {
        int upTo = ledger.chainSize() - Ledger.RETAIN_RECENT;
        boolean changed = false;
        synchronized (ledger) {
            for (int h = 1; h < upTo; h++) {
                if (!ledger.hasBody(h)) continue;
                if (isLight()) { ledger.pruneBlock(h); changed = true; continue; }
                try {
                    byte[] body = ledger.blockAt(h).getJSONArray("txs").toString().getBytes(StandardCharsets.UTF_8);
                    byte[][] shards = RS.encode(ReedSolomon.split(body, RS_K));
                    int mine = myShardIdx();
                    ledger.pruneBlockRS(h, mine, shards[mine]);
                    changed = true;
                } catch (Exception e) { System.err.println("pruneArchived: RS-encode failed for h=" + h + ", retaining full body: " + e); }
            }
        }
        if (changed) save();
    }

    final NodeRpc rpc = new NodeRpc(this);   // HTTP API surface — routing + endpoint handlers (NodeRpc)
    String announceSig() { return PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8("announce|" + GEN.chainId + "|" + index + "|" + selfAddr))); }
    byte[] voteSig(String hash) { return PhantomCrypto.sign(key, PhantomCrypto.utf8(hash)); }
    byte[] beaconSecret(long c) { return Ledger.beaconSecretFor(key.getEncoded(), c); }   // single source: BeaconLogic
    String beaconReveal() { return PhantomCrypto.hex(beaconSecret(beaconCtr)); }
    String beaconCommit() { return PhantomCrypto.hex(PhantomCrypto.sha3_256(beaconSecret(beaconCtr + 1))); }

    boolean verifyQC(JSONObject b) throws Exception {
        JSONArray qc = b.optJSONArray("qc");
        if (qc == null) return false;
        String hash = b.getString("hash");
        // proposer legitimacy: the block must come from the scheduled proposer for its (height,view),
        // and that proposer must not be jailed — prevents off-schedule / view-relabelled blocks committing.
        int height = b.getInt("height");
        int legitProposer = ledger.proposerFor(b.getString("prevHash"), height, b.optInt("view", 0));
        if (b.optInt("proposer", -1) != legitProposer || isSlashed(legitProposer)) return false;
        // only signatures from the beacon-sortitioned committee for this height count (full set when committeeSize=0)
        Set<Integer> committee = new HashSet<>(ledger.committeeFor(height));
        Set<Integer> ok = new HashSet<>();
        for (int i = 0; i < qc.length(); i++) {
            JSONObject v = qc.getJSONObject(i);
            int idx = v.getInt("i");
            if (idx < 0 || idx >= N || isSlashed(idx) || !committee.contains(idx)) continue;   // off-committee or slashed votes don't count
            String valId = VAL_IDS[idx];
            if (ledger.isCluster(valId)) {                                                     // cluster validator: vote is an M-of-N member-sig bundle
                if (ledger.verifyClusterVote(valId, hash, v.optJSONArray("bundle"))) ok.add(idx);
            } else {
                MLDSAPublicKeyParameters pub = PUB_BY_ID.get(valId);
                if (pub != null && PhantomCrypto.verify(pub, PhantomCrypto.utf8(hash), PhantomCrypto.unhex(v.getString("sig")))) ok.add(idx);
            }
        }
        return ok.size() >= ledger.committeeQuorum(height);
    }

    void mergePeers(String json) { try { JSONObject o = new JSONObject(json); for (String k : o.keySet()) peers.putIfAbsent(Integer.parseInt(k), o.getString(k)); } catch (Exception e) { System.err.println("mergePeers: dropping malformed peer map: " + e); } }

    /** Open-read-port handler — delegates to the RPC layer's read-allowlist gate. */
    Response serveRead(IHTTPSession s) { return rpc.serveRead(s); }

    @Override
    public void stop() {
        try { if (readServer != null) readServer.stop(); } catch (Exception e) { }
        super.stop();
    }

    @Override public Response serve(IHTTPSession s) { return rpc.serve(s); }

    // ---- equivocation detection ----
    void handleIncomingVote(JSONObject v) {
        try {
            String valId = v.getString("valId"); int h = v.getInt("height"); String hash = v.getString("hash");
            String k = valId + "|" + h + "|" + hash;
            if (!processedVotes.add(k)) return;                        // already saw this exact vote
            MLDSAPublicKeyParameters pub = PUB_BY_ID.get(valId);
            if (pub == null || !PhantomCrypto.verify(pub, PhantomCrypto.utf8(hash), PhantomCrypto.unhex(v.getString("sig")))) return;
            recordVote(v);
            gossipVote(v);                                              // flood (dedup above stops loops)
        } catch (Exception e) { /* untrusted gossip: a malformed/garbage vote must not crash the handler — drop it silently */ }
    }

    void recordVote(JSONObject v) {
        try {
            String valId = v.getString("valId"); int h = v.getInt("height");
            Map<Integer, JSONObject> byH = seenVotes.computeIfAbsent(valId, x -> new ConcurrentHashMap<>());
            JSONObject prev = byH.putIfAbsent(h, v);
            if (prev != null && !prev.getString("hash").equals(v.getString("hash"))) {
                JSONObject slash = new JSONObject().put("from", "SLASH").put("valId", valId)
                        .put("ha", prev.getString("hash")).put("sa", prev.getString("sig"))
                        .put("hb", v.getString("hash")).put("sb", v.getString("sig"));
                System.out.println("node" + index + " DETECTED equivocation by " + valId.substring(0, 8) + "... at height " + h + " -> SLASH");
                queueSlash(slash);
                for (int j = 0; j < N; j++) { if (j == index) continue; String a = peers.get(j); if (a != null) httpPost(a, "/gossip/slash", slash.toString()); }
            }
        } catch (Exception e) { System.err.println("recordVote: failed to record vote / build equivocation evidence (equivocation may go unslashed): " + e); }
    }

    void queueSlash(JSONObject slash) {
        try {
            synchronized (ledger) { ledger.enqueueSlash(slash, PUB_BY_ID); }   // engine dedups vs slashed/pending + verifies before admitting
        } catch (Exception e) { System.err.println("queueSlash: failed to enqueue slash evidence: " + e); }
    }

    // ---- discovery ----
    void discoveryLoop() {
        while (running) {
            try {
                for (String seed : seeds) { if (seed.equals(selfAddr)) continue; String r = httpGet(seed, "/announce?index=" + index + "&addr=" + selfAddr + "&sig=" + announceSig()); if (r != null) mergePeers(r); }
                for (String addr : new java.util.ArrayList<>(peers.values())) { if (addr.equals(selfAddr)) continue; String r = httpGet(addr, "/peers"); if (r != null) mergePeers(r); }
                syncFromPeers();
                pruneArchived();   // drop bodies this node isn't assigned (keeps recent + assigned)
            } catch (Exception e) { }
            try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
        }
    }

    // consensus algorithm (proposer loop + round) — impl in Consensus.
    final Consensus consensus = new Consensus(this);

    void syncFromPeers() {
        for (int j = 0; j < N; j++) {
            if (j == index) continue; String addr = peers.get(j); if (addr == null) continue;
            try {
                String head = httpGet(addr, "/head"); if (head == null) continue;
                int peerSize = Integer.parseInt(head.trim().split("\\|")[0]);
                while (true) {
                    int want; synchronized (ledger) { want = ledger.chainSize(); }
                    if (want >= peerSize) break;
                    String bj = httpGet(addr, "/block?h=" + want); if (bj == null) break;
                    JSONObject blk = new JSONObject(bj.trim());
                    if (blk.has("error") || !verifyQC(blk)) break;
                    synchronized (ledger) {
                        String cr = ledger.commitBlock(blk, PUB_BY_ID);
                        if (!"appended".equals(cr)) { System.out.println("sync h=" + want + " rejected by ledger: " + cr); break; }   // surface the reason (was silently swallowed)
                        save();
                    }
                    seenBlock.add(blk.getString("hash"));
                }
            } catch (Exception e) { /* per-peer sync is best-effort: a down/slow/garbage peer must not stall the loop — try the next one (ledger-reject reasons are logged above) */ }
        }
    }

    void gossipTx(String body) { for (int j = 0; j < N; j++) { if (j == index) continue; String a = peers.get(j); if (a != null) httpPost(a, "/gossip/tx", body); } }
    void gossipVote(JSONObject v) { for (int j = 0; j < N; j++) { if (j == index) continue; String a = peers.get(j); if (a != null) httpPost(a, "/gossip/vote", v.toString()); } }

    // peer HTTP client — impl in NetHttp; thin delegators keep the consensus/gossip/sync call sites unchanged.
    String httpPost(String addr, String path, String body) { return NetHttp.post(tls, addr, path, body); }
    String httpGet(String addr, String path) { return NetHttp.get(tls, addr, path); }
}
