"""Portable lightweight front page, reviewed topics, and complete local archive."""
from __future__ import annotations

import html
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from .model import utc_now, stable_hash
from . import __version__
from .themes import QUEUES, policy

STYLE = '''body{margin:0;background:#f3f6fa;color:#192b3d;font:16px/1.65 system-ui,sans-serif}main{max-width:1060px;margin:auto;padding:28px}a{color:#1558ad}h1{font-size:28px}h2{font-size:21px}h3{font-size:18px}article,.panel{background:white;border:1px solid #dbe3ec;border-radius:12px;padding:20px;margin:16px 0}p{margin:8px 0}.muted{color:#5e7083;font-size:14px}.badge{display:inline-block;border-radius:6px;background:#eaf1fa;padding:2px 8px;margin-right:8px}.warning{border-left:4px solid #c77812;padding:12px;background:#fff8ec}details{margin:12px 0}summary{cursor:pointer;font-weight:600}li{margin:6px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}nav{display:flex;gap:18px;flex-wrap:wrap}table{border-collapse:collapse;width:100%}td,th{border:1px solid #dbe3ec;padding:8px;text-align:left}@media(max-width:600px){main{padding:14px}article{padding:14px}}'''


def h(value):
    return html.escape(str(value), quote=True)


def page(title, content):
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + h(title) + '</title><style>' + STYLE + '</style></head><body><main>' + content + '</main></body></html>'


def listed(values):
    return '<ul>' + ''.join('<li>' + h(value) + '</li>' for value in values) + '</ul>'


def time_summary(theme):
    values = []
    for kind in ('first_signal', 'outbreak', 'enforcement', 'release'):
        nodes = [n for n in theme['timeline'] if n['kind'] == kind and n.get('date')]
        if nodes:
            node = min(nodes, key=lambda n: n['date'])
            values.append(policy()['timeline_labels'][kind] + '：' + node['date'] + (' 至 ' + node['end'] if node.get('end') else ''))
        elif kind in ('first_signal', 'outbreak'):
            values.append(policy()['timeline_labels'][kind] + '：未知／尚未证实')
    return ' · '.join(values)


def write_latest_entry(reports, index):
    """Keep a movable bookmark outside the immutable portable bundle."""
    reports, index = Path(reports), Path(index)
    relative = index.relative_to(reports).as_posix()
    target = reports / 'latest-engineer.html'
    target.write_text(page('最新工程师报告', '<h1>最新工程师报告</h1><p><a href="' + h(relative) + '">打开工程师行动摘要</a></p><p>主题详情和全量档案保留在同一个报告目录中。</p>'))
    return str(target)


def write_engineer_bundle(destination, events, triage, start, end, warnings, failures, environment=None):
    from .report import write_run_html, _display_title
    from .triage import build_triage
    destination = Path(destination)
    if destination.exists() or destination.with_suffix('.zip').exists():
        raise ValueError('报告包不可覆盖，请使用新的输出目录')
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix='.engineer-', dir=destination.parent))
    try:
        (temp / 'topics').mkdir(); (temp / 'data').mkdir()
        ordered = sorted(events, key=lambda e: (-e.action_priority, -e.risk_score, e.event_id))
        ids = {e.event_id: i for i, e in enumerate(ordered, 1)}
        by_id = {e.event_id: e for e in events}
        themes = triage.get('themes', [])
        active = [r for r in themes if not r['closed']]
        engineer = [r for r in active if r['queue'] in ('action', 'verify') and not r.get('needs_review')]
        budget = policy()['display_budget']; shown, overflow = engineer[:budget], engineer[budget:]
        covered = {ref['event_id'] for r in active if r['queue'] != 'evidence' and not r.get('needs_review') for ref in r['event_refs']}
        full_triage = build_triage(events, run_at=utc_now())
        high = [r for r in full_triage['items'] if r['high_attention'] and r['event_id'] not in covered]
        gaps = list(dict.fromkeys(list(warnings) + [str(f['source_id']) + '：' + str(f['error']) for f in failures]))
        label = triage.get('runtime', {}).get('run_purpose', '未分类')
        title = '工程师行动摘要 · ' + start + ' 至 ' + end
        body = '<h1>' + h(title) + '</h1><p class="muted">用途：' + h(label) + ' · 完整活动库 ' + str(len(events)) + ' 条事件 · 不是产品已受影响的声明</p>'
        body += '<nav><a href="archive.html">查看全量档案</a><a href="data/events.ndjson" download>下载事件数据</a><a href="data/themes.json" download>下载主题与历史</a><a href="coverage.json">覆盖说明</a></nav>'
        body += '<p>可承接主题 ' + str(len(engineer)) + ' 项 · 持续关注 ' + str(sum(r['queue'] == 'watch' for r in active)) + ' 项 · 高关注待补证据 ' + str(len(high)) + ' 条</p>'
        if gaps:
            body += '<div class="warning">覆盖仍有缺口：' + h(gaps[0]) + '<details><summary>展开全部覆盖说明（' + str(len(gaps)) + '项）</summary>' + listed(gaps) + '</details></div>'
        for queue in ('action', 'verify'):
            selected = [r for r in shown if r['queue'] == queue]
            if not selected: continue
            body += '<h2>' + QUEUES[queue] + '</h2>'
            for r in selected:
                dates = [str(getattr(by_id[ref['event_id']], key, '') or '')[:10] for ref in r['event_refs'] if ref['event_id'] in by_id for key in ('published_at', 'updated_at')]
                activity = '窗口内有发布或修订记录' if any(start <= d <= end for d in dates) else '持续事项／窗口内无可核对更新日期'
                body += '<article><p class="muted">' + h(activity) + '</p><span class="badge">' + h(r['evidence_state']) + '</span><h3><a href="topics/' + r['id'].split(':')[1] + '.html">' + h(r['title']) + '</a></h3><p>' + h(r['risk']) + '</p><p><strong>条件：</strong>' + h('；'.join(r['scope'])) + '</p><p><strong>现在关注：</strong>' + h(r['why_now']) + '</p><p><strong>先做：</strong>' + h(r['first_action']) + '</p><p class="muted">承接：' + h(r['owner']) + ' · ' + h(time_summary(r)) + '</p></article>'
        if not engineer:
            body += '<div class="panel">尚无已完成外部范围评审、可承接的主题。请先处理高关注待补证据，不能据此认为没有风险。</div>'
        if overflow:
            body += '<div class="warning"><strong>另有 ' + str(len(overflow)) + ' 项工程师事项，含 ' + str(sum(r['critical'] for r in overflow)) + ' 项重大事项，必须继续处理。</strong>'
            body += '<ul>' + ''.join('<li><a href="topics/' + r['id'].split(':')[1] + '.html">' + h(r['title']) + '</a></li>' for r in overflow) + '</ul></div>'
        body += '<details><summary>持续关注、待补证据及全部主题（' + str(len(themes)) + '项）</summary><ul>'
        body += ''.join('<li><a href="topics/' + r['id'].split(':')[1] + '.html">' + h(r['title']) + '</a> · ' + ('已关闭' if r['closed'] else QUEUES[r['queue']]) + '</li>' for r in themes) + '</ul></details>'
        body += '<details' + (' open' if high else '') + '><summary>未被就绪主题覆盖的高关注线索（' + str(len(high)) + '条）</summary><ul>'
        body += ''.join('<li><a href="archive.html#event-' + str(ids[r['event_id']]) + '">' + h(_display_title(by_id[r['event_id']])) + '</a> · 情报分析补证据</li>' for r in high if r['event_id'] in ids) + '</ul></details>'
        (temp / 'index.html').write_text(page(title, body))
        for r in themes:
            detail = '<nav><a href="../index.html">返回首页</a><a href="../data/themes.json">主题修订档案</a></nav><h1>' + h(r['title']) + '</h1><p>' + h(r['risk']) + '</p><p>关系：' + ('同一风险' if r['relation'] == 'same-risk' else '同一验证批次，各风险独立') + ' · ' + h(r['evidence_state']) + '</p><p>归并依据：' + h(r['grouping_note']) + '</p>'
            if r.get('needs_review'): detail += '<div class="warning">依据变化，原判断需复审。' + listed(r['review_gaps']) + '</div>'
            detail += '<h2>外部条件</h2>' + listed(r['scope']) + '<p>内部适用性：未知；条件匹配不代表已发生故障。</p><h2>工程动作</h2><p>' + h(r['first_action']) + '</p>' + listed(r['steps']) + '<h3>交付记录</h3>' + listed(r['record']) + '<h3>结果处理</h3>' + listed(d['when'] + ' → ' + d['then'] for d in r['decisions'])
            for sub in r.get('subitems', []):
                detail += '<article><strong>独立子项：</strong>' + h('、'.join(sub['event_ids'])) + '<p>' + h(sub['scope']) + '</p><p>' + h(sub['action']) + '</p><p>独立判定：' + h(sub['expected']) + '</p></article>'
            detail += '<h2>外部时间线</h2><p>' + h(time_summary(r)) + '</p><p class="muted">仅表示已审阅证据所能追溯的时间；发布日期、确认日期和多条帖子均不自动证明大规模爆发。</p>'
            for node in sorted(r['timeline'], key=lambda n: n.get('date') or '9999'):
                detail += '<article><strong>' + h(policy()['timeline_labels'][node['kind']]) + '：' + h(node.get('date') or '未知／尚未证实') + (' 至 ' + h(node['end']) if node.get('end') else '') + '</strong><p>' + h(node['note']) + '</p>'
                detail += ''.join('<p><a href="' + h(b['url']) + '">时间依据</a>：' + h(b['quote']) + '</p>' for b in node.get('basis', [])) + '</article>'
            detail += '<h2>原始事件与证据</h2>'
            for ref in r['event_refs']:
                eid = ref['event_id']; detail += '<p>' + ('<a href="../archive.html#event-' + str(ids[eid]) + '">' + h(eid) + '</a>' if eid in ids else h(eid) + '（当前基线未包含，需复核）') + '</p>'
            detail += ''.join('<p><a href="' + h(b['url']) + '">原文</a>：' + h(b['quote']) + '</p>' for b in r['basis'])
            detail += '<h2>判断与修订</h2><p>' + h(r['review_note']) + '</p><p class="muted">本次评审 ' + h(r['reviewed_at']) + ' · ' + h(r['id']) + '</p><details><summary>查看已保存修订（' + str(len(r.get('history', []))) + '版）</summary><pre>' + h(json.dumps(r.get('history', []), ensure_ascii=False, indent=2)) + '</pre></details>'
            (temp / 'topics' / (r['id'].split(':')[1] + '.html')).write_text(page(r['title'], detail))
        (temp / 'data/events.ndjson').write_text('\n'.join(json.dumps(e.payload(), ensure_ascii=False, sort_keys=True) for e in events) + '\n')
        (temp / 'data/themes.json').write_text(json.dumps(themes, ensure_ascii=False, indent=2))
        manifest = {'schema': 'engineer-report-v1', 'skill_version': __version__, 'facts_sha256': stable_hash(sorted((e.event_id, e.fact_hash()) for e in events)), 'generated_at': utc_now(), 'window': {'start': start, 'end': end}, 'run_purpose': label, 'event_count': len(events), 'theme_count': len(themes), 'shown': len(shown), 'overflow': len(overflow), 'uncovered_high_attention': len(high), 'coverage_gaps': gaps, 'scope': '完整活动库；窗口外持续事项也保留', 'raw_snapshots_included': False, 'uploaded': False, 'product_tests_executed': False}
        (temp / 'coverage.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2))
        archive_triage = full_triage
        for key in ('continuity', 'runtime'):
            if key in triage: archive_triage[key] = triage[key]
        write_run_html(temp / 'archive.html', Path(__file__).resolve().parents[2] / 'assets/report-template.html', '完整档案', 'backfill', start, end, events, {}, gaps + ['完整活动库，可能包含窗口外持续事项；不是本期新增事件列表。'], failures, environment, archive_triage)
        # Reverse links retain exact event-to-reviewed-theme navigation.
        reverse = {}
        for r in themes:
            for ref in r['event_refs']:
                reverse.setdefault(ref['event_id'], []).append(r['id'])
        archive_path = temp / 'archive.html'
        archive_text = archive_path.read_text()
        for eid, linked in reverse.items():
            if eid not in ids: continue
            anchor = 'id="event-' + str(ids[eid]) + '"'
            position = archive_text.find(anchor)
            if position < 0: raise ValueError('完整档案事件锚点缺失：' + eid)
            position = archive_text.find('>', position) + 1
            links = '<nav aria-label="关联风险主题">' + ''.join('<a href="topics/' + tid.split(':')[1] + '.html">关联主题</a>' for tid in linked) + '</nav>'
            archive_text = archive_text[:position] + links + archive_text[position:]
        archive_path.write_text(archive_text)
        (temp / 'data/event-themes.json').write_text(json.dumps(reverse, ensure_ascii=False, indent=2))
        (temp / 'README.txt').write_text('打开 index.html 阅读工程师摘要；topics/ 为主题详情，archive.html 为全量档案。\n解压后保留整个目录，不要只转发首页。data/ 保存全部事件、主题与反向关联；coverage.json 保存覆盖限制。\n这是离线报告，没有执行产品测试。\n')
        temp.rename(destination)
        zip_path = destination.with_suffix('.zip')
        with zipfile.ZipFile(zip_path, 'x', zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(destination.rglob('*')):
                if file.is_file(): archive.write(file, str(Path(destination.name) / file.relative_to(destination)))
        return {'index': str(destination / 'index.html'), 'archive': str(destination / 'archive.html'), 'zip': str(zip_path), 'summary': manifest}
    finally:
        if temp.exists(): shutil.rmtree(temp)
