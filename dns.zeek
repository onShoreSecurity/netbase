@load ./main
@load base/utils/directions-and-hosts
@load base/protocols/dns

module Netbase;

export {
    redef record Netbase::observation += {
        # DNS observables
        ## Count of DNS transactions where this host was the querier (client)
        dns_as_client: count &default=0 &log;
        ## Count of DNS transactions where this host was the resolver (server)
        dns_as_server: count &default=0 &log;
        ## Count of authoritative (AA) NOERROR answers this host returned as a server
        dns_auth_answers: count &default=0 &log;
        ## Count of recursive (non-AA) NOERROR answers this host returned as a server
        dns_recur_answers: count &default=0 &log;
        ## Unique query names this host looked up via an EXTERNAL resolver
        dns_ext_rrs: set[string] &optional;
        ## Cardinality of dns_ext_rrs
        dns_ext_rr_cnt: count &default=0 &log;
        ## Unique query names this host looked up via an INTERNAL resolver
        dns_int_rrs: set[string] &optional;
        ## Cardinality of dns_int_rrs
        dns_int_rr_cnt: count &default=0 &log;
        ## Count of NXDOMAIN responses this host received as a client
        dns_nxdomain_rcvd: count &default=0 &log;
        ## Count of NXDOMAIN responses this host returned as a server
        dns_nxdomain_sent: count &default=0 &log;
        ## Count of rejected queries this host returned as a server
        dns_rej_sent: count &default=0 &log;
        ## Count of rejected queries this host received as a client
        dns_rej_rcvd: count &default=0 &log;
        ## Container for query-name length stats (chars) for names this host looked up
        dns_qname_len: Netbase::numstats &default=Netbase::numstats();
        ## Avg/max/min query-name length (chars)
        dns_qname_len_avg: double &optional &log;
        dns_qname_len_max: double &optional &log;
        dns_qname_len_min: double &optional &log;
        ## Count of TXT-record queries this host made (tunneling signal)
        dns_txt_queries: count &default=0 &log;
    };

    # rcode 0 = NOERROR, 3 = NXDOMAIN
    const dns_noerror: count = 0 &redef;
    const dns_nxdomain: count = 3 &redef;
}

# Handle the final, summarized DNS transaction log event.
event DNS::log_dns(rec: DNS::Info)
    {
    if ( ! rec?$id )
        return;

    local orig = rec$id$orig_h;     # querier / client
    local resp = rec$id$resp_h;     # resolver / server

    local do_orig = Netbase::is_monitored(orig);
    local do_resp = Netbase::is_monitored(resp);

    if ( ! do_orig && ! do_resp )
        return;

    local pkg = observables();

    # --- Client (originator) perspective ---
    if ( do_orig )
        {
        pkg[orig] = set([$name="dns_as_client"]);

        # Track the unique query name, bucketed by whether the resolver is local.
        if ( rec?$query && rec$query != "" )
            {
            if ( addr_matches_host(resp, LOCAL_HOSTS) )
                add pkg[orig][[$name="dns_int_rrs", $val=rec$query]];
            else
                add pkg[orig][[$name="dns_ext_rrs", $val=rec$query]];

            add pkg[orig][[$name="dns_qname_len", $val=cat(|rec$query|)]];
            }

        # qtype 16 = TXT
        if ( rec?$qtype && rec$qtype == 16 )
            add pkg[orig][[$name="dns_txt_queries"]];

        if ( rec?$rcode && rec$rcode == dns_nxdomain )
            add pkg[orig][[$name="dns_nxdomain_rcvd"]];

        if ( rec$rejected )
            add pkg[orig][[$name="dns_rej_rcvd"]];
        }

    # --- Server (responder) perspective ---
    if ( do_resp )
        {
        pkg[resp] = set([$name="dns_as_server"]);

        if ( rec?$rcode && rec$rcode == dns_noerror )
            {
            if ( rec?$AA && rec$AA )
                add pkg[resp][[$name="dns_auth_answers"]];
            else
                add pkg[resp][[$name="dns_recur_answers"]];
            }

        if ( rec?$rcode && rec$rcode == dns_nxdomain )
            add pkg[resp][[$name="dns_nxdomain_sent"]];

        if ( rec$rejected )
            add pkg[resp][[$name="dns_rej_sent"]];
        }

    # Deliver
    if ( do_orig )
        Netbase::SEND(orig, pkg[orig]);

    if ( do_resp )
        Netbase::SEND(resp, pkg[resp]);
    }

# Initialize the cardinality sets when an observation record is created.
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
    {
    obs[ip]$dns_ext_rrs = set();
    obs[ip]$dns_int_rrs = set();
    }

# Convert the unique-value sets to counts before logging.
event Netbase::log_observation(obs: observation)
    {
    if ( obs?$dns_ext_rrs )
        obs$dns_ext_rr_cnt = |obs$dns_ext_rrs|;
    if ( obs?$dns_int_rrs )
        obs$dns_int_rr_cnt = |obs$dns_int_rrs|;

    if ( obs$dns_qname_len$cnt > 0 )
        {
        obs$dns_qname_len_avg = obs$dns_qname_len$avg;
        obs$dns_qname_len_max = obs$dns_qname_len$max;
        obs$dns_qname_len_min = obs$dns_qname_len$min;
        }
    }

# Handler to load DNS observables into the observations table.
# This event is executed every time a node calls the SEND() function.
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "dns_as_client":
                ++observations[ip]$dns_as_client;
                break;
            case "dns_as_server":
                ++observations[ip]$dns_as_server;
                break;
            case "dns_auth_answers":
                ++observations[ip]$dns_auth_answers;
                break;
            case "dns_recur_answers":
                ++observations[ip]$dns_recur_answers;
                break;
            case "dns_ext_rrs":
                add observations[ip]$dns_ext_rrs[o$val];
                break;
            case "dns_int_rrs":
                add observations[ip]$dns_int_rrs[o$val];
                break;
            case "dns_nxdomain_rcvd":
                ++observations[ip]$dns_nxdomain_rcvd;
                break;
            case "dns_nxdomain_sent":
                ++observations[ip]$dns_nxdomain_sent;
                break;
            case "dns_rej_sent":
                ++observations[ip]$dns_rej_sent;
                break;
            case "dns_rej_rcvd":
                ++observations[ip]$dns_rej_rcvd;
                break;
            case "dns_qname_len":
                observations[ip]$dns_qname_len = Netbase::update_numstats(observations[ip]$dns_qname_len, to_double(o$val));
                break;
            case "dns_txt_queries":
                ++observations[ip]$dns_txt_queries;
                break;
            }
        }
    }
@endif
