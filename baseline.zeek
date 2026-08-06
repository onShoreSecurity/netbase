##! Redis-backed baseline state for Netbase.
##!
##! Implements "first seen" tracking for categorical observables: has this host ever
##! been seen talking to this ASN / country / port, or running this software?
##!
##! Why this shape, given the deployment: Netbase runs as several independent Zeek
##! workers over AF_PACKET fanout with no cluster, so no worker sees all of a host's
##! traffic. First-seen is well suited to that topology because the test is a single
##! atomic operation against shared state rather than an aggregate over a full series:
##! Storage::put with $overwrite=F is an atomic test-and-set (Redis SETNX). Whichever
##! worker gets there first receives SUCCESS (and reports the new value); every other
##! worker receives KEY_EXISTS. There is no read-modify-write window, so parallel
##! workers cannot corrupt the state or double-report.
##!
##! Requires store.zeek (opt-in). See ROADMAP.md for why numeric z-scores and
##! beaconing need a different mechanism under split traffic.

@load ./main
@load ./store

module Netbase;

export {
    ## Master switch. While T, baseline state is populated but nothing is reported.
    ## This is the safe default: let the store fill with normal activity first.
    const learning_mode: bool = T &redef;

    ## Additional warm-up. Even with learning_mode=F, nothing is reported until the
    ## node has been running this long, so a restart does not alert on the world.
    const learning_window: interval = 24 hrs &redef;

    ## How long a learned value stays "known" with no further sightings. Values not
    ## seen again within this window age out and will be reported as new next time.
    const baseline_ttl: interval = 30 days &redef;

    ## Refresh a key's TTL when it is seen again, so continuously-normal activity
    ## does not age out and re-report. Costs one extra Redis write per sighting.
    const refresh_ttl_on_hit: bool = T &redef;

    ## Suppression allowlist -- the analyst tuning artifact. Entries take either form:
    ##   "<dimension>=<value>"          suppress everywhere, e.g. "ext_asn=15169"
    ##   "<ip>|<dimension>=<value>"     suppress for one host, e.g. "10.1.2.3|ext_asn=15169"
    global suppressions: set[string] = set() &redef;

    ## Optional TSV file of suppressions, re-read live. Format (Zeek logging header):
    ##   #fields	entry
    ##   ext_asn=15169
    ##   10.1.2.3|ext_country=RU
    const suppressions_file = "" &redef;

    ## Input record for one suppression row.
    type SuppressionLine: record {
        entry: string;
    };

    ## Raised when a host exhibits a categorical value never seen before for it.
    ## detect.zeek turns this into a Notice; other scripts may also hook it.
    global first_seen: event(ip: addr, dimension: string, value: string);

    ## Test-and-record: is (ip, dimension, value) new for this host?
    global check_first_seen: function(ip: addr, dimension: string, value: string);

    ## True when reporting is currently enabled (past learning mode and warm-up).
    global reporting_active: function(): bool;

    ## Input event for reading the suppressions file.
    global read_suppression: event(desc: Input::EventDescription, t: Input::Event, r: Netbase::SuppressionLine);
}

# Wall-clock moment this node started, used for the warm-up window.
global baseline_start: time = double_to_time(0);

function reporting_active(): bool
    {
    if ( learning_mode )
        return F;

    if ( baseline_start == double_to_time(0) )
        return F;

    return ( network_time() - baseline_start ) >= learning_window;
    }

function is_suppressed(ip: addr, dimension: string, value: string): bool
    {
    if ( fmt("%s=%s", dimension, value) in suppressions )
        return T;

    if ( fmt("%s|%s=%s", ip, dimension, value) in suppressions )
        return T;

    return F;
    }

function check_first_seen(ip: addr, dimension: string, value: string)
    {
    if ( ! store_ready || value == "" )
        return;

    if ( is_suppressed(ip, dimension, value) )
        return;

    local key = fmt("seen:%s:%s:%s", dimension, ip, value);

    # $overwrite=F makes this an atomic test-and-set: exactly one worker can win the
    # race for a given key, so a value is reported at most once across the fleet.
    when [ip, dimension, value, key] ( local r = Storage::Async::put(store,
            [$key=key, $value="1", $overwrite=F, $expire_time=baseline_ttl]) )
        {
        if ( r$code == Storage::SUCCESS )
            {
            # We are the first to record this value for this host.
            if ( reporting_active() )
                event Netbase::first_seen(ip, dimension, value);
            }
        else if ( r$code == Storage::KEY_EXISTS )
            {
            # Already known. Optionally slide the TTL forward so activity that stays
            # normal does not expire and re-report.
            if ( refresh_ttl_on_hit )
                Netbase::store_put(key, "1", baseline_ttl);
            }
        else
            {
            Reporter::warning(fmt("netbase: baseline put failed for %s: %s",
                                  key, r$error_str));
            }
        }
    timeout redis_op_timeout
        {
        Reporter::warning(fmt("netbase: baseline put timed out for %s", key));
        }
    }

event Netbase::read_suppression(desc: Input::EventDescription, t: Input::Event, r: SuppressionLine)
    {
    if ( r$entry != "" )
        add suppressions[r$entry];
    }

event zeek_init() &priority=5
    {
    baseline_start = network_time();

    if ( suppressions_file != "" )
        {
        Input::add_event([$source=suppressions_file,
                          $reader=Input::READER_ASCII,
                          $mode=Input::REREAD,
                          $name="netbase_suppressions",
                          $fields=SuppressionLine,
                          $ev=Netbase::read_suppression]);
        }
    }
