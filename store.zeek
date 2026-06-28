##! Redis-backed shared store for Netbase.
##!
##! Netbase is frequently deployed as several independent Zeek worker processes
##! load-balanced over the same traffic (AF_PACKET fanout) WITHOUT a cluster.
##! In that topology there is no Broker/proxy tier to aggregate state, and each
##! worker only sees a slice of any given host's traffic. Anything that needs a
##! single, consistent view across workers -- rolling baselines (Phase 3) and
##! beaconing series -- must live outside the worker process.
##!
##! This module wraps Zeek's Storage framework (added in Zeek 7.2) with the Redis
##! backend so every worker opens its own connection to the one local Redis
##! instance on the sensor, sharing a single dataset.
##!
##! Requirements:
##!   * Zeek >= 7.2 built with the Redis storage backend (hiredis >= 1.1.0)
##!   * a reachable Redis server (>= 6.2.0), by default the sensor's localhost
##!
##! This module is OPT-IN: it is not pulled in by __load__.zeek. Enable it with
##!   @load netbase/store
##! and configure the connection via the redefs below in local.zeek.

@load base/frameworks/storage
@load policy/frameworks/storage/backend/redis

module Netbase;

export {
    ## Redis host. Defaults to the sensor's local instance.
    const redis_server_host = "127.0.0.1" &redef;
    ## Redis TCP port.
    const redis_server_port = 6379/tcp &redef;
    ## Optional Redis unix socket. When set, takes precedence over host/port.
    const redis_server_unix_socket = "" &redef;
    ## Prefix applied to every key Netbase writes, to namespace the dataset.
    const redis_key_prefix = "netbase:" &redef;
    ## Optional Redis ACL username.
    const redis_username = "" &redef;
    ## Optional Redis password.
    const redis_password = "" &redef;
    ## Backend tag for the Redis storage backend. Exposed as a redef purely as an
    ## escape hatch in case a future Zeek renames the enum value.
    const redis_backend_tag: Storage::Backend = Storage::STORAGE_BACKEND_REDIS &redef;
    ## Per-operation timeout for asynchronous store operations.
    const redis_op_timeout = 5 secs &redef;

    ## True once the backend has been opened successfully on this node.
    global store_ready: bool = F;

    ## Handle to the shared Redis backend. Only valid while store_ready is T.
    global store: opaque of Storage::BackendHandle;

    ## Asynchronously write key=value with an optional expiry (0 secs = no expiry).
    ## Fire-and-forget: failures are reported but not surfaced to the caller.
    global store_put: function(key: string, value: string, expire: interval);
}

function store_put(key: string, value: string, expire: interval)
    {
    if ( ! store_ready )
        return;

    when [key, value, expire] ( local r = Storage::Async::put(store,
            [$key=key, $value=value, $overwrite=T, $expire_time=expire]) )
        {
        if ( r$code != Storage::SUCCESS )
            Reporter::warning(fmt("netbase: redis put failed for key %s: %s",
                                  key, r$error_str));
        }
    timeout redis_op_timeout
        {
        Reporter::warning(fmt("netbase: redis put timed out for key %s", key));
        }
    }

event zeek_init() &priority=10
    {
    local redis_opts: Storage::Backend::Redis::Options = [
        $server_host = redis_server_host,
        $server_port = redis_server_port,
        $key_prefix  = redis_key_prefix,
    ];

    if ( redis_server_unix_socket != "" )
        redis_opts$server_unix_socket = redis_server_unix_socket;
    if ( redis_username != "" )
        redis_opts$username = redis_username;
    if ( redis_password != "" )
        redis_opts$password = redis_password;

    local opts: Storage::BackendOptions = [ $redis = redis_opts ];

    # String keys and string values; callers serialize their own structure.
    local res = Storage::Sync::open_backend(redis_backend_tag, opts, string, string);

    if ( res$code == Storage::SUCCESS )
        {
        store = res$value;
        store_ready = T;
        }
    else
        {
        Reporter::warning(fmt("netbase: failed to open Redis store (%s:%s): %s",
                              redis_server_host, redis_server_port, res$error_str));
        }
    }
