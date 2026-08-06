@load ./main
@load base/protocols/ssl
# Loaded so SSL::Info carries the $validation_status field below.
@load protocols/ssl/validate-certs

module Netbase;

export {
    redef record Netbase::observation += {
        ## Unique TLS server names (SNI) this host connected to as a client
        tls_sni: set[string] &optional;
        ## Cardinality of tls_sni
        tls_sni_cnt: count &default=0 &log;
        ## Count of TLS sessions this host initiated using a deprecated protocol version
        tls_old_version_conns: count &default=0 &log;
        ## Count of TLS sessions this host initiated where certificate validation failed
        tls_validation_failures: count &default=0 &log;
    };

    ## TLS/SSL protocol versions considered deprecated/weak.
    const tls_old_versions: set[string] = { "SSLv2", "SSLv3", "TLSv10", "TLSv11" } &redef;
}

# Initialize the cardinality set when an observation record is created.
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
    {
    obs[ip]$tls_sni = set();
    }

# Summarize each completed TLS session from the client's perspective.
event SSL::log_ssl(rec: SSL::Info)
    {
    if ( ! rec?$id )
        return;

    local orig = rec$id$orig_h;     # TLS client
    if ( ! Netbase::is_monitored(orig) )
        return;

    local pkg = observables();
    pkg[orig] = set();

    if ( rec?$server_name && rec$server_name != "" )
        add pkg[orig][[$name="tls_sni", $val=rec$server_name]];

    if ( rec?$version && rec$version in tls_old_versions )
        add pkg[orig][[$name="tls_old_version_conns"]];

    if ( rec?$validation_status && rec$validation_status != "ok" )
        add pkg[orig][[$name="tls_validation_failures"]];

    if ( |pkg[orig]| > 0 )
        Netbase::SEND(orig, pkg[orig]);
    }

# Convert the unique-value set to a count before logging.
event Netbase::log_observation(obs: observation)
    {
    if ( obs?$tls_sni )
        obs$tls_sni_cnt = |obs$tls_sni|;
    }

@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "tls_sni":
                add observations[ip]$tls_sni[o$val];
                break;
            case "tls_old_version_conns":
                ++observations[ip]$tls_old_version_conns;
                break;
            case "tls_validation_failures":
                ++observations[ip]$tls_validation_failures;
                break;
            }
        }
    }
@endif
