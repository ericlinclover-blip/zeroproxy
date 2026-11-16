"""Compare custom rules in the same first-match order used by subscriptions."""
from __future__ import annotations
import ipaddress

ORDER = ('block', 'landing', 'ai', 'streaming', 'proxy', 'direct')
MAX_RULES = 2048
MAX_DETAILS = 200


def analyze(raw: dict, current: dict, normalize) -> dict:
    if set(raw) - set(ORDER):
        raise ValueError("存在未知的规则分组")
    def canonical(target):
        target = normalize(str(target))
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return target
    rows = []
    cleaned = {key: [] for key in ORDER}
    for group in ORDER:
        values = raw.get(group, [])
        if not isinstance(values, list):
            raise ValueError(f'{group} 应为规则列表')
        for index, source in enumerate(values):
            target = normalize(str(source))
            if not target:
                if str(source).strip():
                    raise ValueError(f'{group} 第 {index + 1} 条目标无效')
                continue
            try:
                network = ipaddress.ip_network(target, strict=False)
                target = str(network)
            except ValueError:
                network = None
            rows.append({'group': group, 'target': target, 'index': index + 1, '_network': network})
            if target not in cleaned[group]:
                cleaned[group].append(target)
            if len(rows) > MAX_RULES:
                raise ValueError(f'单次分析最多 {MAX_RULES} 条规则，请分批整理')
    details, counts = [], {'duplicate': 0, 'shadowed': 0, 'overlap': 0}
    for i, later in enumerate(rows):
        for earlier in rows[:i]:
            left, right = earlier['_network'], later['_network']
            if left is not None and right is not None:
                if left.version != right.version or not left.overlaps(right):
                    continue
                covers = right.subnet_of(left)
            elif left is None and right is None:
                a, b = earlier['target'], later['target']
                covers = b == a or b.endswith('.' + a)
                if not covers and not a.endswith('.' + b):
                    continue
            else:
                continue  # DNS could relate these, but this analyzer cannot prove it.
            relation = 'duplicate' if earlier['target'] == later['target'] else 'shadowed' if covers else 'overlap'
            counts[relation] += 1
            if len(details) < MAX_DETAILS:
                public = lambda item: {key: item[key] for key in ('group', 'target', 'index')}
                details.append({'kind': relation, 'earlier': public(earlier), 'later': public(later),
                                'different_actions': earlier['group'] != later['group'],
                                'fully_shadowed': covers})
    old = {(group, canonical(target)) for group in ORDER for target in current.get(group, [])}
    new = {(row['group'], canonical(row['target'])) for row in rows}
    return {'rules': cleaned, 'order': list(ORDER), 'conflicts': details, 'counts': counts,
            'total_conflicts': sum(counts.values()), 'details_truncated': sum(counts.values()) > len(details),
            'changes': {'added': len(new - old), 'removed': len(old - new)},
            'scope': 'custom-first-match',
            'limits': '不推断 DNS/Geo 命中或客户端手动选组；系统基础防护仍有更高优先级。'}
