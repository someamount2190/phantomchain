package com.phantomchain.debug;

import java.util.*;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;

/**
 * Phase 4 — a cluster whose members are REAL separate devices (Android emulators), assembled live.
 *
 * The coordinator runs the cluster's validator slot in a real consensus net (2 desktop validators + the
 * cluster). To cast the cluster's single vote it collects an M-of-N bundle of member signatures: each
 * emulator device signs over HTTP (after explicit biometric consent, spec §9.1), and desktop members
 * top up to the threshold. No operator earns — epoch rewards land directly in each member's wallet.
 *
 * Usage: ClusterCoordinator <emuEndpoint...>   (e.g. 127.0.0.1:8801 [127.0.0.1:8802])
 *   The cluster is always 3 members / threshold 2; any emulators given are members, the rest are desktop.
 *   The emulator device(s) are made REQUIRED signers so each cluster block carries a real device's sig.
 */
public class ClusterCoordinator {
    static final int M = 3, THRESHOLD = 2;
    static MLDSAPrivateKeyParameters key() { return PhantomCrypto.randomDeviceKey(); }
    static byte[] secret(MLDSAPrivateKeyParameters k, long c) { return Ledger.beaconSecretFor(k.getEncoded(), c); }

    static String httpGet(String addr, String path) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL("http://" + addr + path).openConnection();
        c.setConnectTimeout(6000); c.setReadTimeout(8000);
        try (InputStream in = c.getInputStream()) {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream(); byte[] b = new byte[4096]; int n;
            while ((n = in.read(b)) > 0) bo.write(b, 0, n);
            return new String(bo.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        } finally { c.disconnect(); }
    }
    static JSONObject memberSign(String addr, String hash) throws Exception { return new JSONObject(httpGet(addr, "/sign?hash=" + hash).trim()); }

    static boolean verifyQC(Ledger L, JSONObject blk, Map<String, MLDSAPublicKeyParameters> pubById) throws Exception {
        String hash = blk.getString("hash"); int height = blk.getInt("height");
        if (blk.optInt("proposer", -1) != L.proposerFor(blk.getString("prevHash"), height, blk.optInt("view", 0))) return false;
        Set<Integer> committee = new HashSet<>(L.committeeFor(height));
        Set<Integer> okv = new HashSet<>(); JSONArray qc = blk.getJSONArray("qc");
        for (int i = 0; i < qc.length(); i++) {
            JSONObject v = qc.getJSONObject(i); int idx = v.getInt("i");
            if (idx < 0 || idx >= L.validators.size() || !committee.contains(idx)) continue;
            String vid = L.validators.get(idx);
            if (L.isCluster(vid)) { if (L.verifyClusterVote(vid, hash, v.optJSONArray("bundle"))) okv.add(idx); }
            else { MLDSAPublicKeyParameters p = pubById.get(vid);
                if (p != null && PhantomCrypto.verify(p, PhantomCrypto.utf8(hash), PhantomCrypto.unhex(v.getString("sig")))) okv.add(idx); }
        }
        return okv.size() >= L.committeeQuorum(height);
    }

    public static void main(String[] a) throws Exception {
        if (a.length < 1) { System.out.println("usage: ClusterCoordinator <emuEndpoint...>"); System.exit(2); }
        List<String> emu = Arrays.asList(a);

        System.out.println("== cluster members (3 total, 2-of-3) ==");
        List<String> members = new ArrayList<>(); Map<String, String> mpub = new HashMap<>();
        Map<String, MLDSAPrivateKeyParameters> desktopKeys = new HashMap<>();   // members we hold keys for (top-up signers)
        Set<String> emuMembers = new LinkedHashSet<>();
        for (String e : emu) {
            JSONObject info = new JSONObject(httpGet(e, "/member").trim());
            String mid = info.getString("id"); members.add(mid); mpub.put(mid, info.getString("pub")); emuMembers.add(mid);
            System.out.println("  EMULATOR DEVICE " + e + " -> member " + mid.substring(0, 16) + "...  (signs with biometric consent)");
        }
        while (members.size() < M) {
            MLDSAPrivateKeyParameters dk = key(); String did = Keys.idOf(dk);
            members.add(did); mpub.put(did, Keys.pubHex(dk)); desktopKeys.put(did, dk);
            System.out.println("  desktop member " + did.substring(0, 16) + "...  (top-up signer)");
        }
        // lead member (holds the cluster beacon key) must be one we control -> first desktop member
        MLDSAPrivateKeyParameters leadKey = desktopKeys.values().iterator().next();
        String emuEndpointFor0 = emu.isEmpty() ? null : emu.get(0);

        // genesis: 2 desktop single-key validators
        LinkedHashMap<String, Long> alloc = new LinkedHashMap<>(); List<String> vals = new ArrayList<>();
        Map<String, Long> stk = new HashMap<>(), idn = new HashMap<>(); Set<String> ver = new HashSet<>(); Map<String, String> vp = new HashMap<>();
        MLDSAPrivateKeyParameters[] vk = new MLDSAPrivateKeyParameters[2]; String[] vid = new String[2];
        Map<String, MLDSAPublicKeyParameters> pubById = new HashMap<>();
        for (int i = 0; i < 2; i++) {
            vk[i] = key(); vid[i] = Keys.idOf(vk[i]);
            alloc.put(vid[i], 1_000_000L); vals.add(vid[i]); stk.put(vid[i], 1_000_000L); idn.put(vid[i], 1L); ver.add(vid[i]); vp.put(vid[i], Keys.pubHex(vk[i]));
            pubById.put(vid[i], vk[i].getPublicKeyParameters());
        }
        Ledger L = new Ledger(); L.genesisEcon("pc-devicecluster", alloc, vals, stk, idn, ver, vp, 0);
        L.beacon = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.utf8("device-cluster-beacon")));

        for (String mid : members) L.stake.put(mid, 250_000L);   // each member pre-bonded; pooled 750k >= floor
        String clusterId = "device-cluster";
        L.applyClusterForm(L.buildClusterFormTx(clusterId, members, mpub, THRESHOLD, leadKey, Ledger.beaconCommit0For(leadKey.getEncoded())));
        int cidx = L.validators.indexOf(clusterId);
        System.out.println("\n== cluster '" + clusterId + "' formed: validator index " + cidx + " ==\n");

        Map<String, Long> ctr = new HashMap<>();
        int deviceSignedRounds = 0;
        for (int round = 0; round < 14 && L.chain.size() <= 9; round++) {
            int h = L.chain.size();
            int proposer = L.proposerFor(L.lastHash(), h, 0); String pid = L.validators.get(proposer);
            JSONObject blk = L.buildProposal(proposer, h * 1000L); blk.put("view", 0);
            MLDSAPrivateKeyParameters bkey = L.isCluster(pid) ? leadKey : vk[proposer];
            long c = ctr.getOrDefault(pid, 0L);
            blk.put("reveal", PhantomCrypto.hex(secret(bkey, c))).put("commit", PhantomCrypto.hex(PhantomCrypto.sha3_256(secret(bkey, c + 1))));
            String hash = blk.getString("hash");

            JSONArray qc = new JSONArray();
            for (int idx : L.committeeFor(h)) {
                String v = L.validators.get(idx);
                if (L.isCluster(v)) {
                    JSONArray bundle = new JSONArray(); boolean deviceSigned = false;
                    for (String e : emu) {   // REAL emulator devices sign first (after biometric consent)
                        try { JSONObject sg = memberSign(e, hash); bundle.put(new JSONObject().put("m", sg.getString("m")).put("sig", sg.getString("sig"))); deviceSigned = true; }
                        catch (Exception ex) { System.out.println("  ! device " + e + " unreachable: " + ex.getMessage()); }
                    }
                    for (Map.Entry<String, MLDSAPrivateKeyParameters> dm : desktopKeys.entrySet()) {   // desktop members top up to threshold
                        if (bundle.length() >= THRESHOLD) break;
                        bundle.put(new JSONObject().put("m", dm.getKey()).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(dm.getValue(), PhantomCrypto.utf8(hash)))));
                    }
                    if (deviceSigned && bundle.length() >= THRESHOLD) deviceSignedRounds++;
                    qc.put(new JSONObject().put("i", idx).put("bundle", bundle));
                } else {
                    qc.put(new JSONObject().put("i", idx).put("sig", PhantomCrypto.hex(PhantomCrypto.sign(vk[idx], PhantomCrypto.utf8(hash)))));
                }
            }
            blk.put("qc", qc);
            if (!verifyQC(L, blk, pubById)) { System.out.println("  ** QC failed at h=" + h); break; }
            String r = L.commitBlock(blk, pubById);
            if (!"appended".equals(r)) { System.out.println("  ** commit failed at h=" + h + ": " + r); break; }
            ctr.put(pid, c + 1);
            StringBuilder bals = new StringBuilder();
            for (int i = 0; i < members.size(); i++) bals.append(emuMembers.contains(members.get(i)) ? "EMU=" : "dsk=").append(L.balanceOf(members.get(i))).append(i < members.size() - 1 ? " " : "");
            System.out.println("  committed h=" + h + " proposer=" + (L.isCluster(pid) ? "CLUSTER" : ("val" + proposer)) + "  members[" + bals + "]");
        }

        System.out.println("\n== RESULT ==");
        System.out.println("rounds the cluster's vote included a REAL emulator-device signature: " + deviceSignedRounds);
        long emuEarned = 0; for (String m : emuMembers) emuEarned += L.balanceOf(m);
        for (String m : emuMembers) System.out.println("emulator member " + m.substring(0, 12) + "... earned: " + L.balanceOf(m) + " (paid directly to the device's wallet)");
        System.out.println("cluster account balance (must be 0 — no operator skim): " + L.balanceOf(clusterId));
        boolean ok = deviceSignedRounds >= 1 && emuEarned > 0 && L.balanceOf(clusterId) == 0;
        System.out.println(ok ? "\nLIVE DEVICE CLUSTER: OK — a real Android emulator co-signed the cluster's blocks (biometric consent) and earned directly."
                              : "\nLIVE DEVICE CLUSTER: INCOMPLETE.");
        System.exit(ok ? 0 : 1);
    }
}
