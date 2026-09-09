Federation Sync
===============

Fetch the head first. Commit each batch before you fetch more. You SHOULD hold batch sizes near 100. Peers with other sizes still conform.

One cycle
=========

1. Refuse origins past the peer allow list.
2. Stop at once past a diverged mark.
3. Fetch the signed head for the origin.
4. Read your top stored sequence for the origin.
5. Stop when the head sequence is at or below your top sequence.
6. Cap one cycle at 10000 records past a gap of 100000.
7. Pin a fresh peer key through first trust only.
8. Check epoch hints against rotation records before you use them.
9. Fetch at most 100 records per range call.
10. Store each batch before you fetch the next one.
11. Send the head only with the batch that reaches the tip.
12. Drop the cycle past a wrong start sequence from the peer.
13. Keep stored batches past a conflict or a reject. Then stop.
14. Treat a reused event or article ID from the peer as divergence: store the
    served bytes as evidence, mark the origin diverged, and halt for an
    operator. It can never resolve by retrying.
15. Dispatch stored records to local views at the end of the cycle.

Batch checks
============

1. Check the origin signature with the epoch key of each sequence.
2. Check the actor signature against the rebuilt intent.
3. Check chain links from the first sequence of the batch.
4. Write your own witness with the peer that you spoke to.
5. Keep upstream witnesses that name the same origin plus ID plus hash.
6. Skip your own key in the kept set.

Backoff and loops
=================

1. Run one loop per origin with a 300 second gap plus jitter.
2. Run on-demand sync through one shared queue.
3. Wait 30 seconds after a fault. Double the wait to a cap of 3600 seconds.
4. Clear backoff past a clean cycle.
