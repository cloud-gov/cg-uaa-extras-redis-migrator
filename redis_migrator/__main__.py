import json
import logging
import os
import re
import sys

import redis

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Redis connection info and objects.
source_redis_env = {}
destination_redis_info = {}

r_source = None
r_destination = None

def migrate_existing_redis_keys():
    """
    Go through all of the keys in the source Redis instance and copy them to the
    destination Redis instance.
    """

    logging.info(
        'Checking for any existing keys within the source Redis instance.'
    )

    # Using the SCAN method here as opposed to KEYS (*) due to this being
    # run in a production system - Python Redis provides an iterable version
    # to keep track of the cursor for you.
    # Redis SCAN: https://redis.io/commands/scan
    # Python Redis scan_iter(): https://github.com/andymccurdy/redis-py/blob/master/redis/client.py#L2220
    for key in r_source.scan_iter():
        logging.info('Processing key {key}'.format(key=key))

        try:
            # Dump the key from the source instance, ensuring that we've
            # retrieved everything associated with it correctly.  DUMP will
            # return nothing if the key is not found.
            data = r_source.dump(key)

            if data:
                # Retrieve the TTL (expiration) of the key so we maintain that
                # information - returned in seconds:
                # https://redis.io/commands/ttl
                ttl = r_source.ttl(key)

                # TTL can be -2 in the case of a key not existing, or -1 for no
                # expiration; in either case, set it to 0, which will mean no
                # expiration when the key is restored in the new instance.
                if ttl < 0:
                    ttl = 0

                # RESTORE the serialized key with its current TTL, which is
                # specified in milliseconds:
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

if __name__ == '__main__':
    # Check for the VCAP_SERVICES environment variable, which will contain the
    # service bindings we need to connect to the Redis instances.
    if 'VCAP_SERVICES' in os.environ:
        services = json.loads(os.getenv('VCAP_SERVICES'))
        source_redis_info = services['redis32'][0]['credentials']
        destination_redis_info = services['aws-elasticache-redis'][0]['credentials']

        # Get the source Redis credentials.
        # We need to stay connected to this instance for listening to commands,
        # so set socket_keepalive to True in this case.
        source_redis_env = {
            'host': source_redis_info['hostname'],
            'port': int(source_redis_info['port']),
            'password': source_redis_info['password'],
            'socket_connect_timeout': 0.5,
            'socket_keepalive': True,
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

        # Migrate the keys from the source Redis instance to the destination
        # Redis instance.
        migrate_existing_redis_keys()

        # Now monitor the source instance for new writes or deletes and copy
        # them over to the destination instance while this app runs.  The
        # listen() method returns a dictionary, which includes a "command" key
        # that contains a string of the full command send to the Redis instance
        # being monitored.
        # Redis MONITOR: https://redis.io/commands/monitor
        # Python Redis: https://github.com/andymccurdy/redis-py#monitor
        allowed_commands = re.compile(
            '(del|get|keys|scan|set|ttl)',
            re.IGNORECASE
        )

        with r_source.monitor() as m_source:
            for command in m_source.listen():
                # Check that the command is one that we expect before executing
                # it in the destination instance.  In addition to SET(EX) and
                # DEL, we also allow for a few others in case we need to debug
                # something.
                if allowed_commands.match(command['command']) is not None:
                    try:
                        r_destination.execute_command(command['command'])
                        logging.info(
                            'Redis command run in the destination instance: {command}'.format(
                                command=command
                            )
                        )
                    except redis.exceptions.RedisError:
                        logging.error(
                            'Could not execute command: {command}'.format(
                                command=command['command']
                            )
                        )
                        logging.error(sys.exc_info()[0])

    else:
        logging.error(
            'Unable to retrieve Redis connection information; please check that the services are bound.'
        )
