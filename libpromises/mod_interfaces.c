/*
  Copyright (C) CFEngine AS

  This file is part of CFEngine 3 - written and maintained by CFEngine AS.

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; version 3.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA

  To the extent this program is licensed as part of the Enterprise
  versions of CFEngine, the applicable Commerical Open Source License
  (COSL) may apply to this file if you as a licensee so wish it. See
  included file COSL.txt.
*/

#include <mod_interfaces.h>
#include <syntax.h>

/**********************************************************************************************/

static const ConstraintSyntax linkstate_constraints[] =
{
    ConstraintSyntaxNewBool("bonding", "If true, the Link Aggregation Control Protocol is enabled to bond interfaces", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewOption("state", "up,down", "Status of interface", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewOption("duplex", "half,full", "Duplex wiring configuration", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewOption("spanning_tree", "on,off", "Status of local spanning tree protocol", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewInt("mtu", CF_INTRANGE, "MTU setting", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewInt("speed", CF_INTRANGE, "Link speed in MB/s", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewInt("minimum_allowed_aggregation", CF_INTRANGE, "Smallest number of links up to allow bonding", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

static const BodySyntax linkstate_body = BodySyntaxNew("link_state", linkstate_constraints, NULL, SYNTAX_STATUS_NORMAL);

/**********************************************************************************************/

static const ConstraintSyntax proxy_constraints[] =
{
    ConstraintSyntaxNewString("generate_file", CF_PATHRANGE, "Filename of output", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

static const BodySyntax proxy_body = BodySyntaxNew("proxy", proxy_constraints, NULL, SYNTAX_STATUS_NORMAL);

/**********************************************************************************************/

static const ConstraintSyntax interface_constraints[] =
{
    ConstraintSyntaxNewStringList("aggregate", CF_ANYSTRING, "List of interfaces to bond with LACP", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewStringList("tagged_vlans", CF_IDRANGE, "List of labelled (trunk) vlan identifers for this interface", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("untagged_vlan", CF_IDRANGE, "Unlabelled (access) vlan", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("ipv4_address", CF_IPRANGE, "A static IPV4 address", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewString("ipv6_address", CF_IPRANGE, "A static IPV6 address", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewBody("link_state", &linkstate_body, "The desired state of the interface link", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewBody("proxy", &proxy_body, "For treating a remote device as a peripheral", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

/**********************************************************************************************/

static const ConstraintSyntax sharingpolicy_constraints[] =
{
    ConstraintSyntaxNewOption("balance_policy", "LeastRecentlyUsed,RoundRobin", "Load balancing policy", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

static const BodySyntax sharingpolicy_body = BodySyntaxNew("sharing_policy", sharingpolicy_constraints, NULL, SYNTAX_STATUS_NORMAL);

/**********************************************************************************************/

static const ConstraintSyntax balancer_constraints[] =
{
    ConstraintSyntaxNewStringList("share_hosts", CF_ANYSTRING, "List of hosts connected to balancer", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewBody("sharing_policy", &sharingpolicy_body, "The balancer policy settings", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

/**********************************************************************************************/

static const ConstraintSyntax overlay_constraints[] =
{
    ConstraintSyntaxNewStringList("id", CF_IDRANGE, "Identifier for the overlay", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

/**********************************************************************************************/

static const ConstraintSyntax relay_constraints[] =
{
    ConstraintSyntaxNewStringList("rip_networks", CF_ANYSTRING, "List of local networks", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewInt("rip_metric", CF_INTRANGE, "RIP route metric", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewInt("rip_timeout", CF_INTRANGE, "RIP timeout on updates", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewOption("rip_horizon", "split-horizon-poison-reverse", "RIP Horizon control", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewBool("rip_passive", "Passive mode", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

static const BodySyntax relay_body = BodySyntaxNew("relay", relay_constraints, NULL, SYNTAX_STATUS_NORMAL);

/**********************************************************************************************/

static const ConstraintSyntax route_constraints[] =
{
    ConstraintSyntaxNewBody("relay", &relay_body, "A body assigning a forwarding agent", SYNTAX_STATUS_NORMAL),
    ConstraintSyntaxNewNull()
};

/**********************************************************************************************/

const PromiseTypeSyntax CF_INTERFACES_PROMISE_TYPES[] =
{
    PromiseTypeSyntaxNew("agent", "interfaces", interface_constraints, NULL, SYNTAX_STATUS_NORMAL),

    PromiseTypeSyntaxNew("agent", "overlays", overlay_constraints, NULL, SYNTAX_STATUS_NORMAL),
    PromiseTypeSyntaxNew("agent", "routes", route_constraints, NULL, SYNTAX_STATUS_NORMAL),
    PromiseTypeSyntaxNew("agent", "balancers", balancer_constraints, NULL, SYNTAX_STATUS_NORMAL),
    PromiseTypeSyntaxNewNull()
};

