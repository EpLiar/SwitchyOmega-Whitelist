#!/usr/bin/env python3
import argparse
import datetime as dt
import os
import re
import sys
import ipaddress


RULE_TYPE_DOMAIN = "domain"
RULE_TYPE_FULL = "full"
RULE_TYPE_KEYWORD = "keyword"
RULE_TYPE_REGEXP = "regexp"
RULE_TYPE_INCLUDE = "include"
RULE_TYPE_IPCIDR = "ipcidr"

TYPE_CHECKER = re.compile(r"^(domain|full|keyword|regexp|include|ipcidr)$")
DOMAIN_CHECKER = re.compile(r"^[a-z0-9\.-]+$")
ATTR_CHECKER = re.compile(r"^[a-z0-9!-]+$")
SITE_CHECKER = re.compile(r"^[A-Z0-9!-]+$")

EXTRA_PRIVATE_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
    "::ffff:0:0/96",
]

def ipv4_network_to_wildcards(network):
    if network.prefixlen <= 8:
        target_prefix = 8
    elif network.prefixlen <= 16:
        target_prefix = 16
    elif network.prefixlen <= 24:
        target_prefix = 24
    else:
        return [str(network.network_address)]

    if network.prefixlen == target_prefix:
        subnets = [network]
    else:
        subnets = network.subnets(new_prefix=target_prefix)

    patterns = []
    for subnet in subnets:
        octets = str(subnet.network_address).split(".")
        if target_prefix == 8:
            patterns.append(f"{octets[0]}.*")
        elif target_prefix == 16:
            patterns.append(f"{octets[0]}.{octets[1]}.*")
        else:
            patterns.append(f"{octets[0]}.{octets[1]}.{octets[2]}.*")
    return patterns


def ipv6_network_to_regexps(network):
    normalized = str(network)
    if normalized == "fc00::/7":
        return [r"/^\[?(fc|fd)[0-9a-fA-F:]*\]?$/"]
    if normalized == "fe80::/10":
        return [r"/^\[?fe[89abAB][0-9a-fA-F:]*\]?$/"]
    if normalized == "::1/128":
        return [r"/^\[?::1\]?$/"]
    if normalized == "::ffff:0:0/96":
        return [r"/^\[?::ffff:[0-9a-fA-F:.]+\]?$/"]
    if network.prefixlen == 128:
        addr = network.network_address.compressed
        return [f"/^\\[?{addr}\\]?$/"]
    return []


def ipcidr_to_patterns(value):
    network = ipaddress.ip_network(value, strict=False)
    if isinstance(network, ipaddress.IPv4Network):
        return ipv4_network_to_wildcards(network)
    return ipv6_network_to_regexps(network)


class Entry:
    def __init__(self, rule_type, value, attrs, affs, plain, source):
        self.type = rule_type
        self.value = value
        self.attrs = attrs
        self.affs = affs
        self.plain = plain
        self.source = source


class Inclusion:
    def __init__(self, source, must_attrs, ban_attrs):
        self.source = source
        self.must_attrs = must_attrs
        self.ban_attrs = ban_attrs


class ParsedList:
    def __init__(self, name):
        self.name = name
        self.inclusions = []
        self.entries = []


def parse_entry(line, source):
    parts = line.split()
    raw_type_val = parts[0]
    kv = raw_type_val.split(":", 1)
    if len(kv) == 1:
        rule_type = RULE_TYPE_DOMAIN
        value = raw_type_val.lower()
    elif len(kv) == 2:
        rule_type = kv[0].lower()
        if rule_type == RULE_TYPE_REGEXP:
            value = kv[1]
        elif rule_type == RULE_TYPE_INCLUDE:
            value = kv[1].upper()
        elif rule_type == RULE_TYPE_IPCIDR:
            value = kv[1]
        else:
            value = kv[1].lower()
    else:
        raise ValueError("invalid format: %s" % line)

    if not TYPE_CHECKER.match(rule_type):
        raise ValueError("invalid type: %s" % rule_type)

    if rule_type == RULE_TYPE_REGEXP:
        re.compile(value)
    elif rule_type == RULE_TYPE_INCLUDE:
        if not SITE_CHECKER.match(value):
            raise ValueError("invalid included list name: %s" % value)
    elif rule_type == RULE_TYPE_IPCIDR:
        try:
            value = str(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ValueError("invalid ipcidr: %s" % exc)
    else:
        if not DOMAIN_CHECKER.match(value):
            raise ValueError("invalid domain: %s" % value)

    attrs = []
    affs = []
    for part in parts[1:]:
        if part.startswith("@"):
            attr = part[1:].lower()
            if not ATTR_CHECKER.match(attr):
                raise ValueError("invalid attribute key: %s" % attr)
            attrs.append(attr)
        elif part.startswith("&"):
            aff = part[1:].upper()
            if not SITE_CHECKER.match(aff):
                raise ValueError("invalid affiliation key: %s" % aff)
            affs.append(aff)
        else:
            raise ValueError("invalid attribute/affiliation: %s" % part)
    attrs.sort()

    plain = "%s:%s" % (rule_type, value)
    if attrs:
        plain = plain + ":@" + ",@".join(attrs)
    return Entry(rule_type, value, attrs, affs, plain, source)


def load_data(data_dir):
    ref_map = {}
    for root, _, files in os.walk(data_dir):
        for name in files:
            path = os.path.join(root, name)
            list_name = os.path.basename(path).upper()
            if not SITE_CHECKER.match(list_name):
                raise ValueError("invalid list name: %s" % list_name)
            entries = ref_map.setdefault(list_name, [])
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                for idx, line in enumerate(handle, start=1):
                    comment_idx = line.find("#")
                    if comment_idx != -1:
                        line = line[:comment_idx]
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = parse_entry(line, list_name)
                    except ValueError as exc:
                        raise ValueError("error in %s at line %d: %s" % (path, idx, exc))
                    entries.append(entry)
    return ref_map


def parse_lists(ref_map):
    pl_map = {}
    for ref_name, ref_list in ref_map.items():
        pl = pl_map.get(ref_name)
        if pl is None:
            pl = ParsedList(ref_name)
            pl_map[ref_name] = pl
        for entry in ref_list:
            if entry.type == RULE_TYPE_INCLUDE:
                if entry.affs:
                    raise ValueError("affiliation is not allowed for include:%s" % entry.value)
                must_attrs = []
                ban_attrs = []
                for attr in entry.attrs:
                    if attr.startswith("-"):
                        ban_attrs.append(attr[1:])
                    else:
                        must_attrs.append(attr)
                pl.inclusions.append(Inclusion(entry.value, must_attrs, ban_attrs))
            else:
                for aff in entry.affs:
                    apl = pl_map.get(aff)
                    if apl is None:
                        apl = ParsedList(aff)
                        pl_map[aff] = apl
                    apl.entries.append(entry)
                pl.entries.append(entry)
    return pl_map


def polish_list(rough_map):
    final_list = []
    queue = []
    domains_map = set()

    for entry in rough_map.values():
        if entry.type in (RULE_TYPE_REGEXP, RULE_TYPE_KEYWORD, RULE_TYPE_IPCIDR):
            final_list.append(entry)
            continue
        if entry.type == RULE_TYPE_DOMAIN:
            domains_map.add(entry.value)
        if entry.type in (RULE_TYPE_DOMAIN, RULE_TYPE_FULL) and not entry.attrs:
            queue.append(entry)
        else:
            final_list.append(entry)

    def has_parent_domain(value):
        parent = value
        while True:
            idx = parent.find(".")
            if idx == -1:
                break
            parent = parent[idx + 1 :]
            if "." not in parent:
                break
            if parent in domains_map:
                return True
        return False

    for entry in queue:
        if has_parent_domain(entry.value):
            continue
        final_list.append(entry)

    final_list.sort(key=lambda e: e.plain)
    return final_list


def resolve_lists(pl_map):
    final_map = {}
    in_progress = set()

    def is_match_attr_filters(entry, inc):
        if not inc.must_attrs and not inc.ban_attrs:
            return True
        if not entry.attrs:
            return not inc.must_attrs
        for must in inc.must_attrs:
            if must not in entry.attrs:
                return False
        for banned in inc.ban_attrs:
            if banned in entry.attrs:
                return False
        return True

    def resolve_list(pl):
        if pl.name in final_map:
            return
        if pl.name in in_progress:
            raise ValueError("circular inclusion in: %s" % pl.name)
        in_progress.add(pl.name)
        rough_map = {}
        for entry in pl.entries:
            rough_map[entry.plain] = entry
        for inc in pl.inclusions:
            inc_pl = pl_map.get(inc.source)
            if inc_pl is None:
                raise ValueError("list '%s' includes a non-existent list: '%s'" % (pl.name, inc.source))
            resolve_list(inc_pl)
            for entry in final_map[inc.source]:
                if is_match_attr_filters(entry, inc):
                    rough_map[entry.plain] = entry
        final_map[pl.name] = polish_list(rough_map)
        in_progress.remove(pl.name)

    for pl in pl_map.values():
        resolve_list(pl)
    return final_map


def entry_to_patterns(entry, include_root):
    is_tld_list = entry.source.startswith("TLD-")
    is_tld = entry.type == RULE_TYPE_DOMAIN and "." not in entry.value
    if entry.type == RULE_TYPE_DOMAIN:
        if is_tld_list and is_tld:
            return ["*." + entry.value]
        if include_root:
            return ["*." + entry.value, entry.value]
        return ["*." + entry.value]
    if entry.type == RULE_TYPE_FULL:
        return [entry.value]
    if entry.type == RULE_TYPE_KEYWORD:
        return ["*" + entry.value + "*"]
    if entry.type == RULE_TYPE_REGEXP:
        return ["/" + entry.value + "/"]
    if entry.type == RULE_TYPE_IPCIDR:
        return ipcidr_to_patterns(entry.value)
    return []


def generate_sorl(lists, final_map, output_path, direct_tag, proxy_tag, include_root):
    tld_set = set()
    for list_name in lists:
        upper = list_name.upper()
        for entry in final_map.get(upper, []):
            if entry.source.startswith("TLD-") and entry.type == RULE_TYPE_DOMAIN and "." not in entry.value:
                tld_set.add(entry.value)

    lines = []
    lines.append("[SwitchyOmega Conditions]")
    lines.append("; Require: SwitchyOmega >= 2.3.2")
    lines.append("; Update: %s" % dt.date.today().strftime("%Y/%m/%d"))
    lines.append("; Usage: https://github.com/FelisCatus/SwitchyOmega/wiki/RuleListUsage")

    for list_name in lists:
        upper = list_name.upper()
        entries = final_map.get(upper, [])
        lines.append("")
        lines.append("; %s" % list_name.lower())
        lines.append("")
        for entry in entries:
            if entry.type in (RULE_TYPE_DOMAIN, RULE_TYPE_FULL) and not entry.source.startswith("TLD-"):
                for tld in tld_set:
                    if entry.value == tld or entry.value.endswith("." + tld):
                        entry = None
                        break
                if entry is None:
                    continue
            for pattern in entry_to_patterns(entry, include_root):
                lines.append(pattern)

    if EXTRA_PRIVATE_CIDRS:
        lines.append("")
        lines.append("; private-cidr")
        lines.append("")
        for cidr in EXTRA_PRIVATE_CIDRS:
            lines.extend(ipcidr_to_patterns(cidr))

    lines.append("")

    with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Generate SwitchyOmega .sorl from domain-list-community lists.")
    parser.add_argument(
        "--data-dir",
        default=os.path.join("domain-list-community", "data"),
        help="Path to domain-list-community data directory.",
    )
    parser.add_argument(
        "--lists",
        default="private,cn",
        help="Comma-separated list names to export in order.",
    )
    parser.add_argument(
        "--output",
        default="OmegaRules_auto_switch.sorl",
        help="Output .sorl file path.",
    )
    parser.add_argument("--direct-tag", default="direct", help="Rule target for direct domains.")
    parser.add_argument("--proxy-tag", default="proxy", help="Rule target for default catch-all.")
    parser.add_argument(
        "--include-root",
        action="store_true",
        help="Also emit bare domains for domain rules (in addition to *.).",
    )
    args = parser.parse_args()

    data_dir = args.data_dir
    if not os.path.isdir(data_dir):
        print("Data directory not found: %s" % data_dir, file=sys.stderr)
        return 1

    ref_map = load_data(data_dir)
    pl_map = parse_lists(ref_map)
    final_map = resolve_lists(pl_map)

    lists = [name.strip() for name in args.lists.split(",") if name.strip()]
    if not lists:
        print("No lists requested.", file=sys.stderr)
        return 1

    missing = [name for name in lists if name.upper() not in final_map]
    if missing:
        print("Missing lists: %s" % ", ".join(missing), file=sys.stderr)
        return 1

    generate_sorl(lists, final_map, args.output, args.direct_tag, args.proxy_tag, args.include_root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
