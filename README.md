# Server
- the server has just one instance, listens on port xyzt
- everything is stored in-memory

# Client
- can have *n* amount of instances
- when connecting to the server, gets asked for a username, different from the ones already online

# MLS
- using TreeKEM (a group key management protocol which uses a binary tree to facilitate secure key agreement among multiple members of a group)
- max group limit as of right now, making it dynamic is a bit too much considering the scope of this project

# E2EE
- the chats are end-to-end encrypted, the server never sees plaintext