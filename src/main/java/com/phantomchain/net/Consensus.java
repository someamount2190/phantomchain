package com.phantomchain.net;

import java.util.HashSet;

import org.json.JSONArray;
import org.json.JSONObject;

import com.phantomchain.debug.*;

/**
 * The BFT-lite consensus algorithm — proposer loop + single round — extracted from {@link NetNode}.
 *
 * Separates the consensus ALGORITHM (am I the scheduled proposer for this height/view? build a proposal,
 * reveal the beacon, collect a committee quorum certificate, commit + broadcast) from the node's server /
 * gossip / persistence plumbing, which stays in {@link NetNode}. Holds a back-reference to its node for the
 * shared state (ledger, peers, beacon counter, vote book) and infrastructure (verifyQC, gossip, persist).
 * Guarded by the live integration suites + PartitionTest / LivenessTest / AdversaryTest.
 */
final class Consensus {
    final NetNode n;
    Consensus(NetNode n) { this.n = n; }

    /** Proposer loop: when this node is the scheduled proposer for (height, current view) and there is work,
     *  run a round. View advances on a stalled height so a dead proposer is taken over. */
    void loop() {
        long workStart = 0; int workHeight = -1; String lastKey = null;
        while (n.running) {
            try { Thread.sleep(NetNode.TICK); } catch (InterruptedException e) { return; }
            n.syncValidatorSet();   // refresh validator set / promote self after a VALJOIN commits
            int h; boolean hasWork;
            synchronized (n.ledger) { h = n.ledger.chain.size(); hasWork = !n.ledger.mempool.isEmpty(); }
            if (!hasWork) { workHeight = -1; lastKey = null; continue; }
            long now = System.currentTimeMillis();
            if (workHeight != h) { workHeight = h; workStart = now; lastKey = null; }
            int view = (int) ((now - workStart) / NetNode.VIEW_TIMEOUT);
            int proposer;
            try { synchronized (n.ledger) { proposer = n.ledger.proposerFor(n.ledger.lastHash(), h, view); } }
            catch (Exception e) { continue; }
            if (n.index >= 0 && proposer == n.index && !n.isSlashed(n.index)) {
                String k = h + ":" + view;
                if (!k.equals(lastKey)) { lastKey = k; try { round(h, view); } catch (Exception e) { } }
            }
        }
    }

    void round(int h, int view) throws Exception {
        JSONObject blk; String hash;
        synchronized (n.ledger) {
            if (n.ledger.chain.size() != h || n.ledger.mempool.isEmpty()) return;
            blk = n.ledger.buildProposal(n.index, System.currentTimeMillis());
            blk.put("view", view);
            blk.put("reveal", n.beaconReveal()).put("commit", n.beaconCommit());   // RANDAO: reveal prior secret, commit next
            hash = blk.getString("hash");
            JSONObject prevVote = n.votedAt.get(h);
            if (prevVote != null && !prevVote.getString("hash").equals(hash)) return;   // already voted a different block at this height: never self-equivocate
            JSONObject myVote = new JSONObject().put("valId", n.id).put("height", h).put("hash", hash).put("sig", PhantomCrypto.hex(n.voteSig(hash)));
            n.votedAt.put(h, myVote); n.saveVotes();
            n.recordVote(myVote); n.gossipVote(myVote);
        }
        if (view > 0) System.out.println("node" + n.index + " VIEW-CHANGE proposing height=" + h + " view=" + view);
        // only the beacon-sortitioned committee signs (full set when committeeSize=0) -> QC carries committee sigs only
        java.util.Set<Integer> committee; int needed;
        synchronized (n.ledger) { committee = new HashSet<>(n.ledger.committeeFor(h)); needed = n.ledger.committeeQuorum(h); }
        JSONArray qc = new JSONArray();
        if (committee.contains(n.index)) qc.put(new JSONObject().put("i", n.index).put("sig", PhantomCrypto.hex(n.voteSig(hash))));
        for (int j = 0; j < n.N && qc.length() < needed; j++) {
            if (j == n.index || !committee.contains(j)) continue; String addr = n.peers.get(j); if (addr == null) continue;
            String r = n.httpPost(addr, "/vote", blk.toString());
            if (r != null) { try { JSONObject v = new JSONObject(r.trim()); if (v.has("sig")) qc.put(v); } catch (Exception e) { } }
        }
        blk.put("qc", qc);
        boolean committed = false;
        synchronized (n.ledger) {
            if (n.ledger.chain.size() != h) return;
            if (!n.verifyQC(blk)) return;
            n.seenBlock.add(hash);
            if ("appended".equals(n.ledger.commitBlock(blk, n.PUB_BY_ID))) { n.save(); committed = true; n.beaconCtr++; n.saveVotes(); }
        }
        if (committed) {
            StringBuilder sg = new StringBuilder();
            for (int i = 0; i < qc.length(); i++) { sg.append(qc.getJSONObject(i).getInt("i")); if (i < qc.length() - 1) sg.append(","); }
            System.out.println("node" + n.index + " committed height=" + h + " view=" + view + " signers=[" + sg + "]");
            for (int j = 0; j < n.N; j++) { if (j == n.index) continue; String a = n.peers.get(j); if (a != null) n.httpPost(a, "/commit", blk.toString()); }
        }
    }
}
