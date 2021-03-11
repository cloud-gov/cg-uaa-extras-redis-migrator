# cg-uaa-extras-redis-migrator
A quick little migration app for upgrading Redis services and ensuring smooth continuity of service.

This intended to be a one-time use app for doing the following in a Cloud Foundry environment:
- Migrating all existing keys in a source Redis instance to a destination Redis instance
- Listen for any new SET or SETEX commands that write data to the source Redis instance so they can be copied to the destination Redis instance.
