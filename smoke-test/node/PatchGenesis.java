package com.phantomchain.debug;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.json.JSONArray;
import org.json.JSONObject;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;

/**
 * One-off migration: inject beaconCommit0 (binds the first RANDAO reveal) into an existing genesis.json,
 * computing each validator's commitment from its node key. Keys/certs are untouched.
 * Usage: PatchGenesis <genesis.json> <key0> <key1> ...   (writes genesis.json in place)
 */
public class PatchGenesis {
    public static void main(String[] a) throws Exception {
        File gf = new File(a[0]);
        JSONObject g = new JSONObject(new String(Files.readAllBytes(gf.toPath()), StandardCharsets.UTF_8));
        java.util.Map<String, String> commitById = new java.util.HashMap<>();
        for (int i = 1; i < a.length; i++) {
            MLDSAPrivateKeyParameters key = Keys.loadOrCreate(new File(a[i]));
            commitById.put(Keys.idOf(key), Ledger.beaconCommit0For(key.getEncoded()));
        }
        JSONArray vs = g.getJSONArray("validators");
        int patched = 0;
        for (int i = 0; i < vs.length(); i++) {
            JSONObject v = vs.getJSONObject(i);
            String id = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(v.getString("pubkey"))));
            String c0 = commitById.get(id);
            if (c0 != null) { v.put("beaconCommit0", c0); patched++; }
            else System.out.println("  WARN: no key for validator id=" + id.substring(0, 12) + " (left unbound)");
        }
        Files.write(gf.toPath(), g.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("patched " + patched + "/" + vs.length() + " validators with beaconCommit0 -> " + gf);
    }
}
