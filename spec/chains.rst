Chains and Sync State
=====================

Accept only contiguous history. Halt on a fork.

Chain rules
===========

Each record is a link to the hash of the record before it. You find the store code in ``src/bonnet/core/firehose.py``.

1. Start each origin log at origin_seq 1.
2. Link each record to the last hash that you hold.
3. Reject a record that links to a hash you miss.
4. Accept a repeat of a record that you hold.
5. Count a repeat as idempotent, not as new.

Divergence
==========

A fork is final. Run no retry for it.

1. If the next record misses your tip hash, stop the sync cycle.
2. Keep the batches that you already stored.
3. Fetch your own tip sequence from the peer.
4. If the peer tip matches yours, blame the range and not the peer.
5. Else store the peer record as proof of the fork.
6. Mark the origin as diverged. Halt all sync for it.
7. Resume only through an operator order.

Key trouble
===========

Read a bad signature as one of two states. State one: your own rotate records are past your table. State two: the peer sent keys with no proof.

1. If your own rotate records are past your table, repair it.
2. Retry the cycle after a repair.
3. Else mark the origin as diverged. Halt all sync for it.
4. Treat an unproven key change as a takeover.

Batch conduct
=============

Store each batch before you fetch more. You find the sync code in ``src/bonnet/net/firehose_sync.py``.

1. Fetch at most 100 records in one range call.
2. Store each batch before you fetch the next one.
3. Send the head only with the batch that reaches the tip.
4. Anchor other batches by chain links alone.
5. Drop the cycle past a wrong start sequence from the peer.
6. On a conflict in a batch, keep stored batches. Then stop.
7. Cap one cycle at 10000 records past a gap of 100000.
