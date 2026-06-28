@load ./main
@load base/utils/directions-and-hosts

module Netbase;

export {
    redef record Netbase::observation += {
        ## Unique countries (ISO codes) of external peers this host communicated with
        ext_countries: set[string] &optional;
        ## Cardinality of ext_countries
        ext_country_cnt: count &default=0 &log;
        ## Unique autonomous systems (ASNs) of external peers this host communicated with
        ext_asns: set[string] &optional;
        ## Cardinality of ext_asns
        ext_asn_cnt: count &default=0 &log;
    };
}

# Initialize the cardinality sets when an observation record is created.
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
    {
    obs[ip]$ext_countries = set();
    obs[ip]$ext_asns = set();
    }

# For outbound flows, record the GeoIP country and ASN of the external peer.
# Requires Zeek's GeoIP support (libmaxminddb) and configured MMDB databases;
# when unavailable these lookups simply return empty results and nothing is added.
event connection_state_remove(c: connection) &priority=2
    {
    if ( ! c?$id )
        return;

    local orig = c$id$orig_h;
    local resp = c$id$resp_h;

    if ( ! id_matches_direction(c$id, OUTBOUND) || ! Netbase::is_monitored(orig) )
        return;

    local pkg = observables();
    pkg[orig] = set();

    local loc = lookup_location(resp);
    if ( loc?$country_code && loc$country_code != "" )
        add pkg[orig][[$name="ext_country", $val=loc$country_code]];

    local as_info = lookup_autonomous_system(resp);
    if ( as_info$number != 0 )
        add pkg[orig][[$name="ext_asn", $val=cat(as_info$number)]];

    if ( |pkg[orig]| > 0 )
        Netbase::SEND(orig, pkg[orig]);
    }

# Convert the unique-value sets to counts before logging.
event Netbase::log_observation(obs: observation)
    {
    if ( obs?$ext_countries )
        obs$ext_country_cnt = |obs$ext_countries|;
    if ( obs?$ext_asns )
        obs$ext_asn_cnt = |obs$ext_asns|;
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "ext_country":
                add observations[ip]$ext_countries[o$val];
                break;
            case "ext_asn":
                add observations[ip]$ext_asns[o$val];
                break;
            }
        }
    }
@endif
