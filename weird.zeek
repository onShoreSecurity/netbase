@load ./main
@load base/utils/directions-and-hosts

module Netbase;

export {       
	redef record Netbase::observation += {
        weirds_sent: count &default=0 &log;
        weirds_recvd: count &default=0 &log;
    };
}

event Weird::log_weird(rec: Weird::Info)
    {
    local orig = 0.0.0.0;
    local resp = 0.0.0.0;
    local pkg = observables();

    if ( rec?$conn ) 
		{
        orig = rec$conn$id$orig_h;
        resp = rec$conn$id$resp_h;
		}
	else if ( rec?$id )
		{
		orig = rec$id$orig_h;
        resp = rec$id$resp_h;
		}
	else 
		{
		return;
		}

    local do_orig = Netbase::is_monitored(orig);
    local do_resp = Netbase::is_monitored(resp);

    if ( do_orig )
        pkg[orig] = set([$name="weirds_sent"]);

    if ( do_resp )
        pkg[resp] = set([$name="weirds_recvd"]);

    # Deliver the observables (this was missing entirely before).
    if ( do_orig )
        Netbase::SEND(orig, pkg[orig]);

    if ( do_resp )
        Netbase::SEND(resp, pkg[resp]);
    }

# Handler to load observables into the observations table
# This event is executed every time a node calls the SEND()
# function.  Proxies only in cluster mode.  
@if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::PROXY )
event Netbase::add_observables(ip: addr, obs: set[observable])
    {
    for ( o in obs )
        {
        switch o$name
            {
            case "weirds_sent":
                ++observations[ip]$weirds_sent;
                break;
            case "weirds_recvd":
                ++observations[ip]$weirds_recvd;
                break;
            }       
        }
    }
@endif