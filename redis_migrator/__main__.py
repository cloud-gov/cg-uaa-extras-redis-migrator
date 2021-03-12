import json
import logging
import os
import sys

import redis

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

if __name__ == '__main__':
    # Check for the VCAP_SERVICES environment variable, which will contain the
    # service bindings we need to connect to the Redis instances.
    if 'VCAP_SERVICES' in os.environ:
        services = json.loads(os.getenv('VCAP_SERVICES'))
        source_redis_info = services['redis32'][0]['credentials']
        destination_redis_info = services['aws-elasticache-redis'][0]['credentials']

        # Get the source Redis credentials.
        source_redis_env = {
            'host': source_redis_info['hostname'],
            'port': int(source_redis_info['port']),
            'password': source_redis_info['password'],
            'socket_timeout': 0.5,
            'socket_connect_timeout': 0.5,
        }

        # Get the destination Redis credentials.
        destination_redis_info = {
            'host': destination_redis_info['hostname'],
            'port': int(destination_redis_info['port']),
            'password': destination_redis_info['password'],
            'socket_timeout': 0.5,
            'socket_connect_timeout': 0.5,
            'ssl': True,
            'ssl_cert_reqs': None,
        }

        # Connect to each Redis instance.
        r_source = redis.Redis(**source_redis_env)
        r_destination = redis.Redis(**destination_redis_info)

        # Go through all of the keys in the source Redis instance and copy them
        # to the destination Redis instance.

        # Using the SCAN method here as opposed to KEYS (*) due to this being
        # run in a production system - Python Redis provides an iterable version
        # to keep track of the cursor for you.
        # Redis SCAN: https://redis.io/commands/scan
        # Python Redis scan_iter(): https://github.com/andymccurdy/redis-py/blob/master/redis/client.py#L2220
        logging.info(
            'Checking for any existing keys within the source Redis instance.'
        )

        for key in r_source.scan_iter():
            logging.info('Processing key {key}'.format(key=key))

            try:
                # Dump the key from the source instance, ensuring that we've
                # retrieved everything associated with it correctly.
                # DUMP will return nothing if the key is not found.
                data = r_source.dump(key)

                if data:
                    # Retrieve the TTL (expiration) of the key so we
                    # maintain that information - returned in seconds:
                    # https://redis.io/commands/ttl
                    ttl = r_source.ttl(key)

                    # TTL can be -2 in the case of a key not existing, or -1
                    # for no expiration; in either case, set it to 0, which
                    # will mean no expiration when the key is restored in
                    # the new instance.
                    if ttl < 0:
                        ttl = 0

                    # RESTORE the serialized key with its current TTL, which
                    # is specified in milliseconds:
                    # https://redis.io/commands/restore
                    r_destination.restore(key, ttl * 1000, data)

                    logging.info(
                        'Successfully migrated key {key}!'.format(key=key)
                    )
                else:
                    logging.info(
                        'No data was found for key {key}'.format(key=key)
                    )
            except:
                logging.error(
                    'Could not migrate key {key}!'.format(key=key)
                )
                logging.error(sys.exc_info()[0])

        logging.info('Finished migration to destination Redis instance.')

        # Now monitor the source instance for new writes and copy them over to
        # the destination instance while this app runs.
        # Redis MONITOR: https://redis.io/commands/monitor
        # Python Redis: https://github.com/andymccurdy/redis-py#monitor

        # TODO:  Finish this and watch for SET or SETEX commands to mirror them
        # on the destination instance.
        #with r_source.monitor() as m_source:
        #    for command in m_source.listen():
        #        logging.info(
        #            'Redis command run in the source instance: {command}'.format(
        #                command=command
        #            )
        #        )
    else:
        logging.error(
            'Unable to retrieve Redis connection information; please check that the services are bound.'
        )
