##! First-seen detection for Netbase.
##!
##! Turns the categorical observables Netbase already collects into Notices the first
##! time a monitored host exhibits them: a new external ASN or country, a new
##! destination port, a newly observed software version.
##!
##! Ships SUPPRESSED. Netbase::learning_mode defaults to T, so deploying this module
##! populates the baseline without generating a single Notice. Turn reporting on only
##! after the store has seen a representative stretch of normal activity:
##!
##!   redef Netbase::learning_mode = F;
##!
##! Tune by adding entries to Netbase::suppressions (or the suppressions file) rather
##! than by disabling dimensions wholesale -- see baseline.zeek.
##!
##! This module is OPT-IN (it needs Redis via store.zeek) and is not pulled in by
##! __load__.zeek. Enable with: @load netbase/detect

@load base/frameworks/notice
@load ./main
@load ./baseline
@load ./flow
@load ./geo
@load ./software

module Netbase;

export {
    redef enum Notice::Type += {
        ## A monitored host contacted an autonomous system it has never used before.
        New_External_ASN,
        ## A monitored host contacted a country it has never communicated with before.
        New_External_Country,
        ## A monitored host used an external destination port it has never used before.
        New_External_Port,
        ## A monitored host used an internal destination port it has never used before.
        New_Internal_Port,
        ## New or changed software was observed on a monitored host.
        New_Software,
    };

    ## Which dimensions to evaluate. Drop entries here to reduce Redis load; prefer
    ## Netbase::suppressions for tuning out specific known-good values.
    const detect_dimensions: set[string] = {
        "ext_asn",
        "ext_country",
        "ext_port",
        "int_port",
        "software",
    } &redef;

    ## Upper bound on first-seen checks per dimension per observation. Bounds the
    ## Redis operations a single noisy host can trigger in one interval. When a
    ## dimension is truncated the fact is logged via Reporter so the cap is never
    ## silent.
    const max_checks_per_dimension: count = 100 &redef;
}

# Run the configured checks for one dimension over one set of values.
function check_set(ip: addr, dimension: string, values: set[string])
    {
    if ( dimension !in detect_dimensions )
        return;

    local n = 0;
    for ( v in values )
        {
        if ( n >= max_checks_per_dimension )
            {
            Reporter::info(fmt("netbase: %s first-seen checks for %s capped at %d (had %d values)",
                               dimension, ip, max_checks_per_dimension, |values|));
            break;
            }

        Netbase::check_first_seen(ip, dimension, v);
        ++n;
        }
    }

# Evaluate an observation as it closes. Negative priority so modules that finalize
# fields (cardinality counts etc.) have already run.
event Netbase::log_observation(obs: observation) &priority=-20
    {
    if ( ! obs?$address )
        return;

    local ip = obs$address;

    if ( obs?$ext_asns )
        check_set(ip, "ext_asn", obs$ext_asns);

    if ( obs?$ext_countries )
        check_set(ip, "ext_country", obs$ext_countries);

    if ( obs?$ext_ports )
        check_set(ip, "ext_port", obs$ext_ports);

    if ( obs?$int_ports )
        check_set(ip, "int_port", obs$int_ports);

    if ( obs?$software )
        check_set(ip, "software", obs$software);
    }

# Map a first-seen dimension onto its Notice type and raise it.
event Netbase::first_seen(ip: addr, dimension: string, value: string)
    {
    local nt = New_External_ASN;
    local msg = "";

    switch dimension
        {
        case "ext_asn":
            nt = New_External_ASN;
            msg = fmt("%s contacted a new external ASN: AS%s", ip, value);
            break;
        case "ext_country":
            nt = New_External_Country;
            msg = fmt("%s communicated with a new country: %s", ip, value);
            break;
        case "ext_port":
            nt = New_External_Port;
            msg = fmt("%s used a new external destination port: %s", ip, value);
            break;
        case "int_port":
            nt = New_Internal_Port;
            msg = fmt("%s used a new internal destination port: %s", ip, value);
            break;
        case "software":
            nt = New_Software;
            msg = fmt("New software observed on %s: %s", ip, value);
            break;
        default:
            return;
        }

    NOTICE([$note=nt,
            $msg=msg,
            $src=ip,
            # Identifier drives Zeek's native suppression, in addition to the
            # baseline store already making this a once-ever event per host.
            $identifier=fmt("%s|%s=%s", ip, dimension, value)]);
    }
