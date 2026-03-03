Create `ume.pyx` (User Management Engine) in `/src/`.

Simple:
- A fixed-record-width KV datastore for user IDs
- username : A username (255 bytes; ASCII)
- registrar: (255 bytes; ASCII)
- publickey: An Ed25519 pubkey (32 bytes)
- password : A password hash (28 bytes; SHA-224) 
- seq_numbr: (8 bytes; Integer; Increasing, not necessarily contiguous all the time)
- Any one of these values can be updated EXCEPT for the sequence number

Since records and values are fixed-width, you shouldn't really have trouble with this. And it should remain small enough that you can just do a linear scan to find matches for any one field and return the matching records. However, UPD requires an actual fixed index be it the username or the sequence number. For deletes, don't bother correcting the sequence number since it's not the actual key. We only use the sequence number when we don't want to remember their changing username

The ume exposes the following semantics:
- PUT
- GET
- UPD
- DEL

The Ume's database file should just be `./userfile`. If it doesn't exist, create it. The Ume should also have a special function to export the entire database as plaintext in a format of: `<{username}@{registrar}>:{publickey}`, newline, repeat. Then dumped into a file `./users`. This operation should be non-blocking.
