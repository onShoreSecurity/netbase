@load ./main
@load base/frameworks/cluster
@load base/frameworks/input

module Netbase;

export {
    # Input framework record describing one CIDR label row.
    type CidrLabelLine: record {
        cidr: subnet;
        ## Comma-separated list of labels to apply to the subnet.
        labels: string;
    };

    redef record Netbase::observation += {
        ## Static/dynamic labels associated with the device (e.g. role:dc, site:hq, os:win)
        ip_labels: set[string] &optional &log;
        ## Labels associated with the connections the device participated in.
        ## Reserved as an extension point for dynamic, per-connection labeling.
        flow_labels: set[string] &optional &log;
    };

    ## Static label assignments by subnet. Configure inline via redef, e.g.:
    ##   redef Netbase::cidr_labels += {
    ##       [10.1.0.0/16] = set("site:hq", "role:workstation"),
    ##   };
    global cidr_labels: table[subnet] of set[string] = table() &redef;

    ## Optional path to a TSV file of CIDR label assignments. When set, the file is
    ## (re)read live via the Input framework on each node that loads this script.
    ## Format (tab-separated, with a Zeek logging header line):
    ##   #fields	cidr	labels
    ##   10.1.0.0/16	site:hq,role:workstation
    const cidr_labels_file = "" &redef;

    ## Returns the union of all static labels that apply to the given IP.
    global labels_for: function(ip: addr): set[string];

    ## Input-framework event used to (re)load CIDR label rows.
    global read_cidr_label: event(desc: Input::EventDescription, t: Input::Event, r: Netbase::CidrLabelLine);
}

function labels_for(ip: addr): set[string]
    {
    local out: set[string] = set();
    for ( net in cidr_labels )
        {
        if ( ip in net )
            {
            for ( l in cidr_labels[net] )
                add out[l];
            }
        }
    return out;
    }

# Apply static labels at observation creation time so every logged row carries
# the device's role/site/etc. This is what enables peer-group comparison later.
hook Netbase::customize_obs(ip: addr, obs: table[addr] of observation)
    {
    obs[ip]$ip_labels = labels_for(ip);
    obs[ip]$flow_labels = set();
    }

# Merge a CIDR label row from the input file into the cidr_labels table.
event Netbase::read_cidr_label(desc: Input::EventDescription, t: Input::Event, r: CidrLabelLine)
    {
    if ( r$cidr !in cidr_labels )
        cidr_labels[r$cidr] = set();

    local parts = split_string(r$labels, /,/);
    for ( i in parts )
        {
        if ( parts[i] != "" )
            add cidr_labels[r$cidr][parts[i]];
        }
    }

event zeek_init()
    {
    if ( cidr_labels_file != "" )
        {
        Input::add_event([$source=cidr_labels_file,
                          $reader=Input::READER_ASCII,
                          $mode=Input::REREAD,
                          $name="netbase_cidr_labels",
                          $fields=CidrLabelLine,
                          $ev=Netbase::read_cidr_label]);
        }
    }
