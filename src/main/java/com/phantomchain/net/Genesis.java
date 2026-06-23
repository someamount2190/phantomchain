package com.phantomchain.net;

import com.phantomchain.debug.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The chain's genesis: chainId, genesis time, and the validator set.
 * This file is PUBLIC and identical on every node — it is what makes a set of nodes "the same chain".
 * It contains only public keys (no secrets); each operator keeps their own private key locally.
 */
public class Genesis {

    public static class Validator {
        public final String pubkeyHex;   // ML-DSA-65 public key (hex of getEncoded())
        public final String id;          // sha3-256(pubkey) hex -> the on-chain validator identity
        public final long stake;         // genesis stake (PoS weight, sqrt-damped)
        public final long identity;      // enrolled-human / personhood weight
        public final boolean verified;   // personhood-verified at genesis (founding humans bootstrap the web-of-trust)
        public final long alloc;         // genesis token balance
        public final String region;      // opt-in geo coverage region_id ("" = standard cluster)
        public final String tier;        // "light" = no archived storage; "" / "heavy" = full storage
        public final String beaconCommit0; // commitment to this validator's first RANDAO reveal ("" = legacy/unbound)

        public Validator(String pubkeyHex, long stake, long identity, boolean verified, long alloc, String region, String tier, String beaconCommit0) {
            this.pubkeyHex = pubkeyHex;
            this.id = PhantomCrypto.hex(PhantomCrypto.sha3_256(PhantomCrypto.unhex(pubkeyHex)));
            this.stake = stake; this.identity = identity; this.verified = verified; this.alloc = alloc; this.region = region; this.tier = tier;
            this.beaconCommit0 = beaconCommit0;
        }
    }

    public final String chainId;
    public final long genesisTime;
    public final List<Validator> validators;
    public final List<String> custodianPubs;   // bridge custodian pubkeys (M-of-N)
    public final int bridgeThreshold;           // M
    public final long reserve;                  // genesis allocation to BRIDGE_RESERVE

    Genesis(String chainId, long genesisTime, List<Validator> validators, List<String> custodianPubs, int bridgeThreshold, long reserve) {
        this.chainId = chainId; this.genesisTime = genesisTime; this.validators = validators;
        this.custodianPubs = custodianPubs; this.bridgeThreshold = bridgeThreshold; this.reserve = reserve;
    }

    public static Genesis fromJson(String s) {
        JSONObject o = new JSONObject(s);
        List<Validator> vs = new ArrayList<>();
        JSONArray arr = o.getJSONArray("validators");
        for (int i = 0; i < arr.length(); i++) {
            JSONObject v = arr.getJSONObject(i);
            vs.add(new Validator(v.getString("pubkey"), v.getLong("stake"),
                    v.optLong("identity", 1L), v.optBoolean("verified", false), v.optLong("alloc", 0L), v.optString("region", ""), v.optString("tier", ""), v.optString("beaconCommit0", "")));
        }
        List<String> cust = new ArrayList<>();
        JSONArray cu = o.optJSONArray("custodians");
        if (cu != null) for (int i = 0; i < cu.length(); i++) cust.add(cu.getString(i));
        return new Genesis(o.getString("chainId"), o.optLong("genesisTime", 0L), vs, cust, o.optInt("bridgeThreshold", 1), o.optLong("reserve", 0L));
    }

    public static Genesis load(File f) throws Exception {
        return fromJson(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
    }

    public JSONObject toJson() {
        JSONArray arr = new JSONArray();
        for (Validator v : validators) arr.put(new JSONObject()
                .put("pubkey", v.pubkeyHex).put("stake", v.stake).put("identity", v.identity)
                .put("verified", v.verified).put("alloc", v.alloc).put("region", v.region).put("tier", v.tier).put("beaconCommit0", v.beaconCommit0));
        JSONArray cu = new JSONArray(); for (String p : custodianPubs) cu.put(p);
        return new JSONObject().put("chainId", chainId).put("genesisTime", genesisTime).put("validators", arr)
                .put("custodians", cu).put("bridgeThreshold", bridgeThreshold).put("reserve", reserve);
    }

    /** Position of a validator id in the set, or -1 if this id is not a genesis validator. */
    public int indexOfId(String id) {
        for (int i = 0; i < validators.size(); i++) if (validators.get(i).id.equals(id)) return i;
        return -1;
    }
}
