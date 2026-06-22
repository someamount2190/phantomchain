package com.phantomchain.debug;

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

    static int N;                  // validator count, from genesis
    static int QUORUM;             // N/2 + 1
    static final long VIEW_TIMEOUT = 3000L;
    static final long TICK = 700L;

    static String[] VAL_IDS;       // validator ids, by genesis position
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
    byte[] beaconSeed;                 // per-node RANDAO secret seed (derived deterministically from the node key)
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
        N = gen.validators.size();
        QUORUM = N - (N - 1) / 3;   // BFT: tolerate f=floor((N-1)/3) Byzantine; two quorums overlap in >=f+1 (>=1 honest)
        VAL_IDS = new String[N];
        for (int i = 0; i < N; i++) {
            Genesis.Validator v = gen.validators.get(i);
            VAL_IDS[i] = v.id;
            PUB_BY_ID.put(v.id, new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, PhantomCrypto.unhex(v.pubkeyHex)));
            GEN_VALPUBS.put(v.id, v.pubkeyHex);
        }
    }

    NetNode(Genesis gen, NodeConfig cfg, MLDSAPrivateKeyParameters key) throws Exception {
        super(cfg.rpcPort);
        initFromGenesis(gen);
        this.key = key;
        this.id = PhantomCrypto.hex(PhantomCrypto.sha3_256(key.getPublicKeyParameters().getEncoded()));
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
        int vn = ledger.validators.size();
        if (vn != N) {
            N = vn;
            VAL_IDS = ledger.validators.toArray(new String[0]);
            for (Map.Entry<String, String> e : ledger.valPubs.entrySet())
                if (!"CLUSTER".equals(e.getValue()))   // a cluster has no single key; its consensus sig is an M-of-N member bundle (verifyClusterVote)
                    PUB_BY_ID.computeIfAbsent(e.getKey(), kk -> new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, PhantomCrypto.unhex(e.getValue())));
        }
        if (index < 0) {
            int myIdx = ledger.validators.indexOf(id);
            if (myIdx >= 0) { index = myIdx; peers.put(index, selfAddr);
                System.out.println("node " + id.substring(0, 8) + "... JOINED validator set at index " + myIdx); }
        }
    }

    void boot() throws Exception {
        if (dataFile.exists()) {
            ledger.fromJson(new String(Files.readAllBytes(dataFile.toPath()), StandardCharsets.UTF_8));
            System.out.println("node" + index + " loaded chain height=" + ledger.height() + " slashed=" + ledger.slashed.size());
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
            for (Genesis.Validator v : GEN.validators) {
                if (!v.region.isEmpty()) ledger.regions.put(v.id, v.region);   // opt-in geo regions
                if (!v.tier.isEmpty()) ledger.tiers.put(v.id, v.tier);         // heavy/light storage tier
            }
            for (String cp : GEN.custodianPubs) ledger.custodians.put(Ledger.idOf(cp), cp);   // bridge custodians (M-of-N)
            ledger.bridgeThreshold = GEN.bridgeThreshold;
            save();
            System.out.println("node" + index + " genesis chainId=" + GEN.chainId + " validators=" + N);
        }
        loadVotes();
        syncValidatorSet();   // pick up any validators joined since genesis (and our own index if we joined)
        // commit-reveal beacon: secret seed is DERIVED from our ML-DSA key (so commit0 is publishable at
        // keygen and bound at genesis/VALJOIN — no unconstrained first reveal), then resync our counter.
        beaconSeed = Ledger.beaconSeedFor(key.getEncoded());
        String onchainCommit = ledger.commits.get(id);
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
        new Thread(this::consensusLoop, "cons-" + index).start();
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
        } catch (Exception e) { }
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
    boolean isLight() { return "light".equals(ledger.tiers.get(id)); }
    int myShardIdx() { return (index < 0 ? 0 : index) % RS_N; }
    /** Drop full archived bodies, retaining only THIS node's RS shard (~1/k size). Light tier keeps nothing. */
    void pruneArchived() throws Exception {
        int upTo = ledger.chain.size() - Ledger.RETAIN_RECENT;
        boolean changed = false;
        synchronized (ledger) {
            for (int h = 1; h < upTo; h++) {
                if (!ledger.hasBody(h)) continue;
                if (isLight()) { ledger.pruneBlock(h); changed = true; continue; }
                try {
                    byte[] body = ledger.chain.get(h).getJSONArray("txs").toString().getBytes(StandardCharsets.UTF_8);
                    byte[][] shards = RS.encode(ReedSolomon.split(body, RS_K));
                    int mine = myShardIdx();
                    ledger.pruneBlockRS(h, mine, shards[mine]);
                    changed = true;
                } catch (Exception e) { }
            }
        }
        if (changed) save();
    }

    Response resp(String b) { return newFixedLengthResponse(b + "\n"); }

    String status() throws Exception {
        StringBuilder bal = new StringBuilder();
        for (int i = 0; i < N; i++) bal.append(" bal").append(i).append("=").append(ledger.balanceOf(VAL_IDS[i]));
        StringBuilder sl = new StringBuilder();
        for (int i = 0; i < N; i++) if (isSlashed(i)) { if (sl.length() > 0) sl.append(","); sl.append(i); }
        return "node=" + index + " height=" + ledger.height()
                + " last=" + ledger.lastHash().substring(0, 12) + " mempool=" + ledger.mempool.size()
                + " peers=" + peers.size() + " slashed=[" + sl + "]" + bal;
    }

    String param(IHTTPSession s, String k) { List<String> v = s.getParameters().get(k); return (v == null || v.isEmpty()) ? null : v.get(0); }
    String body(IHTTPSession s) { Map<String, String> f = new HashMap<>(); try { s.parseBody(f); } catch (Exception e) { return null; } String b = f.get("postData"); return (b != null && b.length() > 1_048_576) ? null : b; }
    boolean opAuth(IHTTPSession s) { return OP_TOKEN.isEmpty() || OP_TOKEN.equals(param(s, "token")); }   // open if no token configured
    String announceSig() { return PhantomCrypto.hex(PhantomCrypto.sign(key, PhantomCrypto.utf8("announce|" + GEN.chainId + "|" + index + "|" + selfAddr))); }
    byte[] voteSig(String hash) { return PhantomCrypto.sign(key, PhantomCrypto.utf8(hash)); }
    byte[] beaconSecret(long c) { return PhantomCrypto.hkdf(beaconSeed, null, PhantomCrypto.utf8("pcbeacon" + c), 32); }
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

    String peersJson() { JSONObject o = new JSONObject(); for (Map.Entry<Integer, String> e : peers.entrySet()) o.put(String.valueOf(e.getKey()), e.getValue()); return o.toString(); }
    void mergePeers(String json) { try { JSONObject o = new JSONObject(json); for (String k : o.keySet()) peers.putIfAbsent(Integer.parseInt(k), o.getString(k)); } catch (Exception e) { } }

    /** Open-read-port handler: serve the read-only allowlist, reject everything else (writes / consensus
     *  / gossip stay on the mTLS peer port). */
    Response serveRead(IHTTPSession s) {
        if (!READ_ENDPOINTS.contains(s.getUri()))
            return newFixedLengthResponse(Response.Status.FORBIDDEN, MIME_PLAINTEXT, "not exposed on the open read port (use the mTLS peer port)\n");
        return serve(s);
    }

    @Override
    public void stop() {
        try { if (readServer != null) readServer.stop(); } catch (Exception e) { }
        super.stop();
    }

    @Override
    public Response serve(IHTTPSession s) {
        String uri = s.getUri();
        try {
            if (OP_ENDPOINTS.contains(uri) && !opAuth(s))
                return newFixedLengthResponse(Response.Status.UNAUTHORIZED, MIME_PLAINTEXT, "operator token required\n");
            switch (uri) {
                case "/status": synchronized (ledger) { return resp(status()); }
                case "/econ": synchronized (ledger) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < N; i++) sb.append("node" + i
                            + ": stake=" + ledger.stake.getOrDefault(VAL_IDS[i], 0L)
                            + " identity=" + ledger.identity.getOrDefault(VAL_IDS[i], 0L)
                            + " weight=" + String.format("%.1f%%", 100 * ledger.weight(i))
                            + " balance=" + ledger.balanceOf(VAL_IDS[i])
                            + (isSlashed(i) ? " [SLASHED]" : "") + "\n");
                    sb.append("total_minted=" + ledger.totalMinted + " burned=" + ledger.burned
                            + " circulating=" + ledger.circulatingSupply() + " height=" + ledger.height());
                    return resp(sb.toString());
                }
                case "/identity": synchronized (ledger) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < N; i++) sb.append("node" + i
                            + ": verified=" + ledger.verified.contains(VAL_IDS[i])
                            + " vouches=" + ledger.vouches.getOrDefault(VAL_IDS[i], java.util.Collections.<String>emptySet()).size() + "/" + Ledger.VOUCH_THRESHOLD
                            + " weight=" + String.format("%.1f%%", 100 * ledger.weight(i)) + "\n");
                    return resp(sb.toString());
                }
                case "/vouch": {
                    String ci = param(s, "i");
                    if (ci == null) return resp("need i=<candidate index>");
                    String cand = VAL_IDS[Integer.parseInt(ci)];
                    JSONObject tx; String res;
                    synchronized (ledger) {
                        if (!ledger.verified.contains(id)) return resp("reject: this node is not personhood-verified, cannot vouch");
                        tx = ledger.buildVouchTx(id, cand, key);
                        res = ledger.addToMempool(tx, PUB_BY_ID);
                    }
                    if ("accepted".equals(res)) { seenTx.add(tx.getString("sig")); gossipTx(tx.toString()); }
                    return resp("vouch=" + res + " by node" + index + " for node" + ci);
                }
                case "/bond": case "/unbond": {
                    boolean unbond = uri.equals("/unbond");
                    long amt = Long.parseLong(param(s, "amount") == null ? "0" : param(s, "amount"));
                    JSONObject tx; String res;
                    synchronized (ledger) { tx = ledger.buildBondTx(id, amt, ledger.projectedNonce(id), unbond, key); res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) { seenTx.add(tx.getString("sig")); gossipTx(tx.toString()); }
                    return resp((unbond ? "unbond=" : "bond=") + res + " amount=" + amt);
                }
                case "/unjail": {
                    JSONObject tx; String res;
                    synchronized (ledger) { tx = ledger.buildUnjailTx(id, ledger.projectedNonce(id), key); res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) { seenTx.add(tx.getString("sig")); gossipTx(tx.toString()); }
                    return resp("unjail=" + res + " by node" + index);
                }
                case "/valjoin": {   // this node bonds-in and requests to join the validator set
                    JSONObject tx; String res;
                    synchronized (ledger) { tx = ledger.buildValJoinTx(key); res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) { seenTx.add(Ledger.txId(tx)); gossipTx(tx.toString()); }
                    return resp("valjoin=" + res + " id=" + id.substring(0, 12));
                }
                case "/gov/propose": {
                    String pp = param(s, "param"), pid = param(s, "pid");
                    long val = Long.parseLong(param(s, "value") == null ? "0" : param(s, "value"));
                    if (pp == null || pid == null) return resp("need pid=&param=&value=");
                    JSONObject tx; String res;
                    synchronized (ledger) { tx = ledger.buildProposeTx(id, pid, pp, val, ledger.projectedNonce(id), key); res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) { seenTx.add(tx.getString("sig")); gossipTx(tx.toString()); }
                    return resp("propose=" + res + " " + pid + " " + pp + "=" + val);
                }
                case "/gov/vote": {
                    String pid = param(s, "pid"); boolean yes = "true".equals(param(s, "yes"));
                    if (pid == null) return resp("need pid=&yes=true|false");
                    JSONObject tx; String res;
                    synchronized (ledger) { tx = ledger.buildVoteTx(id, pid, yes, ledger.projectedNonce(id), key); res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) { seenTx.add(tx.getString("sig")); gossipTx(tx.toString()); }
                    return resp("govvote=" + res + " " + pid + " yes=" + yes);
                }
                case "/gov": synchronized (ledger) {
                    StringBuilder sb = new StringBuilder();
                    for (String pid : ledger.proposals.keySet()) {
                        JSONObject p = ledger.proposals.get(pid);
                        sb.append(pid + ": " + p.getString("param") + "=" + p.getLong("value")
                                + " deadline=" + p.getLong("deadline") + " executed=" + p.getBoolean("executed")
                                + " votes=" + p.getJSONObject("votes").length() + "\n");
                    }
                    sb.append("params: blockReward=" + ledger.blockReward + " halvingBlocks=" + ledger.halvingBlocks
                            + " maxSupply=" + ledger.maxSupply + " feeBurnBps=" + ledger.feeBurnBps + " slashBps=" + ledger.slashBps
                            + " jailBlocks=" + ledger.jailBlocks + " unbondingBlocks=" + ledger.unbondingBlocks);
                    return resp(sb.toString());
                }
                case "/head": synchronized (ledger) { return resp(ledger.chain.size() + "|" + ledger.lastHash()); }
                case "/account": synchronized (ledger) {
                    String aid = param(s, "id"); if (aid == null) return resp("need id=");
                    return resp(new JSONObject().put("id", aid).put("balance", ledger.balanceOf(aid))
                            .put("nonce", ledger.projectedNonce(aid)).put("cid", ledger.chainId).toString());
                }
                case "/stateproof": synchronized (ledger) {   // authenticated account inclusion proof (Merkle) — verifiable by a light client
                    String aid = param(s, "id"); if (aid == null) return resp("need id=");
                    JSONObject pr = ledger.accountProof(aid);
                    pr.put("accountsRoot", ledger.accountsMerkleRoot());   // == pr.root; light clients trust it via stateRoot when srVersion=m1
                    pr.put("verified", Ledger.verifyAccountProof(pr));     // self-check the served proof
                    return resp(pr.toString());
                }
                case "/shard": synchronized (ledger) {
                    String ss = param(s, "s"); if (ss == null) return resp("need s=<shard 0.." + (Ledger.SHARDS - 1) + ">");
                    int sh = Integer.parseInt(ss); if (sh < 0 || sh >= Ledger.SHARDS) return resp("bad shard");
                    JSONArray roots = new JSONArray();
                    for (int i = 0; i < Ledger.SHARDS; i++) roots.put(ledger.shardRoot(i));
                    return resp(new JSONObject().put("shard", sh).put("shards", Ledger.SHARDS)
                            .put("data", ledger.shardData(sh)).put("roots", roots)
                            .put("shardsRoot", ledger.shardsRoot()).toString());
                }
                case "/extaddr": {   // derive this node's deterministic external-chain address
                    String chain = param(s, "chain"); if (chain == null) return resp("need chain=");
                    return resp(Ledger.extAddr(chain, PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded())));
                }
                case "/bridge/out": {   // lock PHNT to the reserve for external release
                    String chain = param(s, "chain"); long amount = Long.parseLong(param(s, "amount") == null ? "0" : param(s, "amount"));
                    long fee = Long.parseLong(param(s, "fee") == null ? "1" : param(s, "fee"));
                    String ext = Ledger.extAddr(chain == null ? "ETH" : chain, PhantomCrypto.hex(key.getPublicKeyParameters().getEncoded()));
                    JSONObject tx; String res;
                    synchronized (ledger) { tx = ledger.buildBridgeOutTx(id, chain == null ? "ETH" : chain, ext, amount, fee, ledger.projectedNonce(id), key); res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) { seenTx.add(Ledger.txId(tx)); gossipTx(tx.toString()); }
                    return resp("bridge_out=" + res + " amount=" + amount + " -> " + (chain == null ? "ETH" : chain) + ":" + ext);
                }
                case "/bridge/outs": synchronized (ledger) {   // outbound locks awaiting external release (for custodians)
                    JSONArray a = new JSONArray(); for (JSONObject o : ledger.bridgeOuts) a.put(o); return resp(a.toString());
                }
                case "/oracle": synchronized (ledger) {
                    String pair = param(s, "pair"); if (pair == null) return resp("need pair=");
                    return resp(new JSONObject().put("pair", pair).put("median", ledger.oracleMedian(pair))
                            .put("sources", ledger.oracleRates.getOrDefault(pair, java.util.Collections.<String, Long>emptyMap()).size()).toString());
                }
                case "/identity-info": synchronized (ledger) {
                    String aid = param(s, "id"); if (aid == null) return resp("need id=");
                    JSONObject idn = ledger.identities.get(aid);
                    return resp(idn == null ? new JSONObject().put("registered", false).toString() : idn.toString());
                }
                case "/body": {   // leaf: full body if we still hold it, else pruned
                    int h = Integer.parseInt(param(s, "h"));
                    synchronized (ledger) { return resp(ledger.hasBody(h) ? ledger.chain.get(h).toString() : "pruned"); }
                }
                case "/rsshard": synchronized (ledger) {   // this node's RS shard of block h (stored, or computed if we hold the body)
                    int h = Integer.parseInt(param(s, "h"));
                    if (h < 0 || h >= ledger.chain.size()) return resp("{}");
                    JSONObject b = ledger.chain.get(h);
                    if (b.has("rsShard")) return resp(new JSONObject().put("idx", b.getInt("rsIdx")).put("shard", b.getString("rsShard")).toString());
                    if (ledger.hasBody(h)) {
                        byte[] body = b.getJSONArray("txs").toString().getBytes(StandardCharsets.UTF_8);
                        byte[][] shards = RS.encode(ReedSolomon.split(body, RS_K));
                        return resp(new JSONObject().put("idx", myShardIdx()).put("shard", PhantomCrypto.hex(shards[myShardIdx()])).toString());
                    }
                    return resp("{}");
                }
                case "/block": {   // full block; if pruned, RS-reconstruct from k shards and verify vs the committed hash
                    int h = Integer.parseInt(param(s, "h"));
                    JSONObject header;
                    synchronized (ledger) {
                        if (h < 0 || h >= ledger.chain.size()) return resp(new JSONObject().put("error", "no height").toString());
                        if (ledger.hasBody(h)) return resp(ledger.chain.get(h).toString());
                        header = ledger.chain.get(h);
                    }
                    byte[][] shards = new byte[RS_N][]; boolean[] present = new boolean[RS_N]; int got = 0, slen = 0;
                    if (header.has("rsShard")) { int idx = header.getInt("rsIdx"); byte[] sh = PhantomCrypto.unhex(header.getString("rsShard")); shards[idx] = sh; present[idx] = true; got++; slen = sh.length; }
                    for (int p = 0; p < N && got < RS_K; p++) {
                        if (p == index) continue; String addr = peers.get(p); if (addr == null) continue;
                        String r = httpGet(addr, "/rsshard?h=" + h); if (r == null) continue;
                        try { JSONObject o = new JSONObject(r.trim()); if (!o.has("shard")) continue;
                            int idx = o.getInt("idx"); if (idx < 0 || idx >= RS_N || present[idx]) continue;
                            byte[] sh = PhantomCrypto.unhex(o.getString("shard")); shards[idx] = sh; present[idx] = true; got++; slen = sh.length;
                        } catch (Exception e) { }
                    }
                    if (got >= RS_K) try {
                        byte[] body = ReedSolomon.join(RS.decode(shards, present, slen));
                        JSONArray txs = new JSONArray(new String(body, StandardCharsets.UTF_8));
                        JSONObject full = new JSONObject(header.toString()).put("txs", txs);
                        full.remove("pruned"); full.remove("rsShard"); full.remove("rsIdx");
                        synchronized (ledger) { if (header.getString("hash").equals(ledger.blockHash(full))) return resp(full.toString()); }   // trustless
                    } catch (Exception e) { }
                    return resp(header.toString());   // fallback
                }
                case "/peers": return resp(peersJson());
                case "/genesis": return resp(GEN.toJson().toString());
                case "/announce": {   // only the validator that owns this index (proven by signature) can set its address
                    int aidx = Integer.parseInt(param(s, "index")); String addr = param(s, "addr"); String sig = param(s, "sig");
                    if (aidx >= 0 && aidx < N && addr != null && sig != null && addr.indexOf('|') < 0) {   // no delimiter injection into the signed announce

                        MLDSAPublicKeyParameters pub = PUB_BY_ID.get(VAL_IDS[aidx]);
                        if (pub != null && PhantomCrypto.verify(pub, PhantomCrypto.utf8("announce|" + GEN.chainId + "|" + aidx + "|" + addr), PhantomCrypto.unhex(sig)))
                            peers.put(aidx, addr);
                    }
                    return resp(peersJson());
                }
                case "/sync": { int before; synchronized (ledger) { before = ledger.height(); } syncFromPeers(); synchronized (ledger) { return resp("synced from=" + before + " to=" + ledger.height()); } }

                case "/submit": {
                    String to = param(s, "to"); if (to == null) to = VAL_IDS[(index + 1) % N];
                    long amount = Long.parseLong(param(s, "amount") == null ? "10" : param(s, "amount"));
                    long fee = Long.parseLong(param(s, "fee") == null ? "1" : param(s, "fee"));
                    JSONObject tx; String res;
                    synchronized (ledger) { tx = ledger.buildTxProjected(id, to, amount, fee, key); res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) { seenTx.add(tx.getString("sig")); gossipTx(tx.toString()); }
                    return resp("submit=" + res + " amount=" + amount + " fee=" + fee);
                }
                case "/gossip/tx": {
                    String b = body(s); if (b == null) return resp("no body");
                    JSONObject tx = new JSONObject(b);
                    if (!seenTx.add(Ledger.txId(tx))) return resp("dup");
                    String res; synchronized (ledger) { res = ledger.addToMempool(tx, PUB_BY_ID); }
                    if ("accepted".equals(res)) gossipTx(b);
                    return resp("tx=" + res);
                }

                case "/vote": {
                    String b = body(s); if (b == null) return resp("no body");
                    JSONObject blk = new JSONObject(b);
                    int h = blk.getInt("height"); int view = blk.getInt("view");
                    String hash = blk.getString("hash");
                    synchronized (ledger) {
                        int proposer = ledger.proposerFor(blk.getString("prevHash"), h, view);
                        if (blk.getInt("proposer") != proposer) { System.out.println("VOTE-REJECT wrong proposer h=" + h + " v=" + view + " got=" + blk.getInt("proposer") + " want=" + proposer); return resp("reject: wrong proposer for view"); }
                        if (isSlashed(proposer)) return resp("reject: proposer is slashed");
                        if (!ledger.proposalLinks(blk)) { System.out.println("VOTE-REJECT bad links h=" + h + " stateRootMatch=" + ledger.stateRoot().equals(blk.optString("prevStateRoot")) + " shardsMatch=" + ledger.shardsRoot().equals(blk.optString("prevShardsRoot")) + " beaconValid=" + ledger.beaconRevealValid(blk)); return resp("reject: bad links/hash"); }
                        if (!ledger.txsValid(blk, PUB_BY_ID)) { System.out.println("VOTE-REJECT bad txs h=" + h); return resp("reject: bad txs"); }
                        JSONObject prev = votedAt.get(h);
                        if (prev != null && !prev.getString("hash").equals(hash)) return resp("reject: already voted at height " + h);
                        JSONObject myVote = new JSONObject().put("valId", id).put("height", h).put("hash", hash).put("sig", PhantomCrypto.hex(voteSig(hash)));
                        votedAt.put(h, myVote); saveVotes();   // PERSIST before returning the vote
                        recordVote(myVote); gossipVote(myVote);
                        return resp(new JSONObject().put("i", index).put("sig", myVote.getString("sig")).toString());
                    }
                }
                case "/commit": {
                    String b = body(s); if (b == null) return resp("no body");
                    JSONObject blk = new JSONObject(b);
                    if (!verifyQC(blk)) return resp("reject: insufficient quorum");
                    if (!seenBlock.add(blk.getString("hash"))) return resp("dup");
                    String res; synchronized (ledger) { res = ledger.commitBlock(blk, PUB_BY_ID); if ("appended".equals(res)) save(); }
                    return resp("commit=" + res);
                }

                case "/gossip/vote": { String b = body(s); if (b == null) return resp("no body"); handleIncomingVote(new JSONObject(b)); return resp("ok"); }
                case "/gossip/slash": {
                    String b = body(s); if (b == null) return resp("no body");
                    JSONObject slash = new JSONObject(b);
                    if (Ledger.verifySlash(slash, PUB_BY_ID)) queueSlash(slash);
                    return resp("ok");
                }
                case "/byz/equivocate": {   // DEBUG-only adversary hook; disabled unless PC_DEBUG=1
                    if (!DEBUG_ENDPOINTS) return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "no route\n");
                    int h; synchronized (ledger) { h = ledger.chain.size(); }
                    String ha = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("equivA|" + h)));
                    String hb = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("equivB|" + h)));
                    JSONObject vA = new JSONObject().put("valId", id).put("height", h).put("hash", ha).put("sig", PhantomCrypto.hex(voteSig(ha)));
                    JSONObject vB = new JSONObject().put("valId", id).put("height", h).put("hash", hb).put("sig", PhantomCrypto.hex(voteSig(hb)));
                    gossipVote(vA); gossipVote(vB);
                    return resp("equivocated at height " + h + " (two conflicting signed votes broadcast)");
                }
                default: return newFixedLengthResponse(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "no route\n");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return newFixedLengthResponse(Response.Status.INTERNAL_ERROR, MIME_PLAINTEXT, "ERR " + e.getClass().getSimpleName() + ": " + e.getMessage() + "\n");
        }
    }

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
        } catch (Exception e) { }
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
        } catch (Exception e) { }
    }

    void queueSlash(JSONObject slash) {
        try {
            String valId = slash.getString("valId");
            synchronized (ledger) {
                if (ledger.slashed.contains(valId)) return;
                for (JSONObject t : ledger.mempool) if ("SLASH".equals(t.optString("from")) && valId.equals(t.optString("valId"))) return;
                if (Ledger.verifySlash(slash, PUB_BY_ID)) ledger.mempool.add(slash);
            }
        } catch (Exception e) { }
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

    // ---- consensus with view-change (skips slashed proposers) ----
    void consensusLoop() {
        long workStart = 0; int workHeight = -1; String lastKey = null;
        while (running) {
            try { Thread.sleep(TICK); } catch (InterruptedException e) { return; }
            syncValidatorSet();   // refresh validator set / promote self after a VALJOIN commits
            int h; boolean hasWork;
            synchronized (ledger) { h = ledger.chain.size(); hasWork = !ledger.mempool.isEmpty(); }
            if (!hasWork) { workHeight = -1; lastKey = null; continue; }
            long now = System.currentTimeMillis();
            if (workHeight != h) { workHeight = h; workStart = now; lastKey = null; }
            int view = (int) ((now - workStart) / VIEW_TIMEOUT);
            int proposer;
            try { synchronized (ledger) { proposer = ledger.proposerFor(ledger.lastHash(), h, view); } }
            catch (Exception e) { continue; }
            if (index >= 0 && proposer == index && !isSlashed(index)) {
                String k = h + ":" + view;
                if (!k.equals(lastKey)) { lastKey = k; try { doRound(h, view); } catch (Exception e) { } }
            }
        }
    }

    void doRound(int h, int view) throws Exception {
        JSONObject blk; String hash;
        synchronized (ledger) {
            if (ledger.chain.size() != h || ledger.mempool.isEmpty()) return;
            blk = ledger.buildProposal(index, System.currentTimeMillis());
            blk.put("view", view);
            blk.put("reveal", beaconReveal()).put("commit", beaconCommit());   // RANDAO: reveal prior secret, commit next
            hash = blk.getString("hash");
            JSONObject prevVote = votedAt.get(h);
            if (prevVote != null && !prevVote.getString("hash").equals(hash)) return;   // already voted a different block at this height: never self-equivocate (was causing false slashing on view-change)
            JSONObject myVote = new JSONObject().put("valId", id).put("height", h).put("hash", hash).put("sig", PhantomCrypto.hex(voteSig(hash)));
            votedAt.put(h, myVote); saveVotes();
            recordVote(myVote); gossipVote(myVote);
        }
        if (view > 0) System.out.println("node" + index + " VIEW-CHANGE proposing height=" + h + " view=" + view);
        // only the beacon-sortitioned committee signs (full set when committeeSize=0) -> QC carries committee sigs only
        java.util.Set<Integer> committee; int needed;
        synchronized (ledger) { committee = new HashSet<>(ledger.committeeFor(h)); needed = ledger.committeeQuorum(h); }
        JSONArray qc = new JSONArray();
        if (committee.contains(index)) qc.put(new JSONObject().put("i", index).put("sig", PhantomCrypto.hex(voteSig(hash))));
        for (int j = 0; j < N && qc.length() < needed; j++) {
            if (j == index || !committee.contains(j)) continue; String addr = peers.get(j); if (addr == null) continue;
            String r = httpPost(addr, "/vote", blk.toString());
            if (r != null) { try { JSONObject v = new JSONObject(r.trim()); if (v.has("sig")) qc.put(v); } catch (Exception e) { } }
        }
        blk.put("qc", qc);
        boolean committed = false;
        synchronized (ledger) {
            if (ledger.chain.size() != h) return;
            if (!verifyQC(blk)) return;
            seenBlock.add(hash);
            if ("appended".equals(ledger.commitBlock(blk, PUB_BY_ID))) { save(); committed = true; beaconCtr++; saveVotes(); }
        }
        if (committed) {
            StringBuilder sg = new StringBuilder();
            for (int i = 0; i < qc.length(); i++) { sg.append(qc.getJSONObject(i).getInt("i")); if (i < qc.length() - 1) sg.append(","); }
            System.out.println("node" + index + " committed height=" + h + " view=" + view + " signers=[" + sg + "]");
            for (int j = 0; j < N; j++) { if (j == index) continue; String a = peers.get(j); if (a != null) httpPost(a, "/commit", blk.toString()); }
        }
    }

    void syncFromPeers() {
        for (int j = 0; j < N; j++) {
            if (j == index) continue; String addr = peers.get(j); if (addr == null) continue;
            try {
                String head = httpGet(addr, "/head"); if (head == null) continue;
                int peerSize = Integer.parseInt(head.trim().split("\\|")[0]);
                while (true) {
                    int want; synchronized (ledger) { want = ledger.chain.size(); }
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
            } catch (Exception e) { }
        }
    }

    void gossipTx(String body) { for (int j = 0; j < N; j++) { if (j == index) continue; String a = peers.get(j); if (a != null) httpPost(a, "/gossip/tx", body); } }
    void gossipVote(JSONObject v) { for (int j = 0; j < N; j++) { if (j == index) continue; String a = peers.get(j); if (a != null) httpPost(a, "/gossip/vote", v.toString()); } }

    javax.net.ssl.HttpsURLConnection https(String addr, String path) throws Exception {
        javax.net.ssl.HttpsURLConnection c = (javax.net.ssl.HttpsURLConnection) new java.net.URL("https://" + addr + path).openConnection();
        c.setSSLSocketFactory(tls.getSocketFactory());
        c.setHostnameVerifier((h, s) -> true);   // trust is via the cluster CA, not hostname
        c.setConnectTimeout(3000); c.setReadTimeout(3000);
        return c;
    }
    String httpPost(String addr, String path, String body) {
        javax.net.ssl.HttpsURLConnection c = null;
        try {
            c = https(addr, path);
            c.setRequestMethod("POST"); c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            c.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8)); c.getOutputStream().flush();
            return readAll(c.getInputStream());
        } catch (Exception e) { return null; } finally { if (c != null) c.disconnect(); }
    }
    String httpGet(String addr, String path) {
        javax.net.ssl.HttpsURLConnection c = null;
        try {
            c = https(addr, path);
            return readAll(c.getInputStream());
        } catch (Exception e) { return null; } finally { if (c != null) c.disconnect(); }
    }
    static String readAll(InputStream is) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream(); byte[] buf = new byte[4096]; int n;
        while ((n = is.read(buf)) > 0) bo.write(buf, 0, n); is.close();
        return new String(bo.toByteArray(), StandardCharsets.UTF_8);
    }
}
