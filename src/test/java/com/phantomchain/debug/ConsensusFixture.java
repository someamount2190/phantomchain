package com.phantomchain.debug;

import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Shared genesis + QC scaffolding for the engine-level consensus tests. The {@code genesis(int)} builder and
 * the {@code verifyQC} rule were copy-pasted across ~9 suites (PartitionTest, LivenessTest, AdvAdversaryTest,
 * FuzzTest, MempoolDosTest, TimestampTest, EstateAttackTest, RecoveryAttackTest, VoteLockWedgeTest); each now
 * delegates here. Tests keep their own {@code keys/ids/pub/N/ctr} fields (populated from the returned
 * fixture) so their bodies and forge/sync helpers are unchanged.
 */
public final class ConsensusFixture {
    public final Ledger L;
    public final MLDSAPrivateKeyParameters[] keys;
    public final String[] ids;
    public final Map<String, MLDSAPublicKeyParameters> pub;

    private ConsensusFixture(Ledger l, MLDSAPrivateKeyParameters[] keys, String[] ids, Map<String, MLDSAPublicKeyParameters> pub) {
        this.L = l; this.keys = keys; this.ids = ids; this.pub = pub;
    }

    public static ConsensusFixture genesis(int n, String chainId) throws Exception {
        return genesis(n, chainId, 1_000_000L, null);
    }

    /** n verified validators, each with {@code allocPer} balance + 1M stake + identity 1; full-set committee. */
    public static ConsensusFixture genesis(int n, String chainId, long allocPer, LinkedHashMap<String, Long> extraAlloc) throws Exception {
        MLDSAPrivateKeyParameters[] keys = new MLDSAPrivateKeyParameters[n];
        String[] ids = new String[n];
        Map<String, MLDSAPublicKeyParameters> pub = new HashMap<>();
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>();
        List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>();
        Set<String> ver = new HashSet<>();
        Map<String, String> vp = new HashMap<>(), bc = new HashMap<>();
        for (int i = 0; i < n; i++) {
            keys[i] = PhantomCrypto.randomDeviceKey();
            ids[i] = PhantomCrypto.hex(PhantomCrypto.sha3_256(keys[i].getPublicKeyParameters().getEncoded()));
            pub.put(ids[i], new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_65, keys[i].getPublicKeyParameters().getEncoded()));
            alloc.put(ids[i], allocPer); vals.add(ids[i]); stk.put(ids[i], 1_000_000L); idn.put(ids[i], 1L);
            ver.add(ids[i]); vp.put(ids[i], PhantomCrypto.hex(keys[i].getPublicKeyParameters().getEncoded()));
            bc.put(ids[i], Ledger.beaconCommit0For(keys[i].getEncoded()));
        }
        if (extraAlloc != null) alloc.putAll(extraAlloc);
        Ledger L = new Ledger();
        L.genesisEcon(chainId, alloc, vals, stk, idn, ver, vp, bc, 1700000000000L);
        L.committeeSize = 0;   // full live set signs (default; set explicitly for clarity)
        return new ConsensusFixture(L, keys, ids, pub);
    }

    /** The exact QC rule NetNode.verifyQC enforces: scheduled proposer + a committee quorum of valid sigs. */
    public static boolean verifyQC(Ledger L, Map<String, MLDSAPublicKeyParameters> pubById, JSONObject b) throws Exception {
        JSONArray qc = b.optJSONArray("qc"); if (qc == null) return false;
        String hash = b.getString("hash"); int h = b.getInt("height");
        int legit = L.proposerFor(b.getString("prevHash"), h, b.optInt("view", 0));
        if (b.optInt("proposer", -1) != legit || L.excluded(L.validators.get(legit))) return false;
        Set<Integer> committee = new HashSet<>(L.committeeFor(h)), ok = new HashSet<>();
        for (int i = 0; i < qc.length(); i++) {
            JSONObject v = qc.getJSONObject(i); int idx = v.getInt("i");
            if (idx < 0 || idx >= L.validatorCount() || L.excluded(L.validators.get(idx)) || !committee.contains(idx)) continue;
            MLDSAPublicKeyParameters p = pubById.get(L.validators.get(idx));
            if (p != null && PhantomCrypto.verify(p, PhantomCrypto.utf8(hash), PhantomCrypto.unhex(v.getString("sig")))) ok.add(idx);
        }
        return ok.size() >= L.committeeQuorum(h);
    }
}
